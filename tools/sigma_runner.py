"""Minimal Sigma evaluator (script-level rule-testing harness) for the parsed EVTX dataset.
Supports: field modifiers contains/startswith/endswith/all/re, lists (OR), selection maps (AND),
conditions with and/or/not/parentheses and '1 of x*', 'all of x*', 'them'. Also Sigma correlation
rules (event_count, value_count, temporal, temporal_ordered), partitioned per source sample file.
Usage: python tools/sigma_runner.py [--no-filters]"""
import yaml, glob, re, sys, json, os
import pandas as pd

CHANNEL = {"sysmon": "Microsoft-Windows-Sysmon/Operational", "security": "Security", "system": "System"}

def chan_mask(df, svc):
    if svc == "powershell": return df.Channel.str.contains("PowerShell", na=False)
    return df.Channel == CHANNEL[svc]

def field_mask(df, key, val):
    f, *mods = key.split("|")
    if f not in df.columns: return pd.Series(False, index=df.index)
    col = df[f]
    vals = val if isinstance(val, list) else [val]
    allmode = "all" in mods
    masks = []
    for v in vals:
        if "re" in mods: m = col.astype(str).str.contains(str(v), case=False, regex=True, na=False)
        elif "contains" in mods: m = col.astype(str).str.lower().str.contains(str(v).lower(), regex=False, na=False)
        elif "startswith" in mods: m = col.astype(str).str.lower().str.startswith(str(v).lower(), na=False)
        elif "endswith" in mods: m = col.astype(str).str.lower().str.endswith(str(v).lower(), na=False)
        else:
            if isinstance(v, int): m = pd.to_numeric(col, errors="coerce") == v
            else: m = col.astype(str).str.lower() == str(v).lower()
        masks.append(m & col.notna())
    out = masks[0]
    for m in masks[1:]: out = (out & m) if allmode else (out | m)
    return out

def sel_mask(df, sel):
    if isinstance(sel, list):
        out = pd.Series(False, index=df.index)
        for s in sel: out |= sel_mask(df, s)
        return out
    out = pd.Series(True, index=df.index)
    for k, v in sel.items(): out &= field_mask(df, k, v)
    return out

def eval_cond(cond, sels):
    import fnmatch
    def grp(pat, mode):
        names = list(sels) if pat == "them" else [n for n in sels if fnmatch.fnmatch(n, pat)]
        ms = [sels[n] for n in names]
        out = ms[0].copy()
        for m in ms[1:]: out = (out | m) if mode == "1" else (out & m)
        return out
    env = {}
    def rep(m):
        k = f"_g{len(env)}"; env[k] = grp(m.group(2), "1" if m.group(1) in ("1", "any") else "all"); return k
    c = re.sub(r"\b(1|all|any) of ([\w\*]+)", rep, cond)
    for i, n in enumerate(sorted(sels, key=len, reverse=True)):
        c = re.sub(rf"\b{re.escape(n)}\b", f"_s{i}", c); env[f"_s{i}"] = sels[n]
    c = c.replace(" and ", " & ").replace(" or ", " | ").replace("not ", "~")
    return eval(c, {"__builtins__": {}}, env)

def load_rules(path="rules/*.yml"):
    return [yaml.safe_load(open(p)) | {"_path": p} for p in sorted(glob.glob(path))]

def run_rule(df, rule, no_filters=False):
    d = dict(rule["detection"]); cond = d.pop("condition")
    if no_filters: cond = re.sub(r"\s+and not \w+", "", cond)
    sels = {k: sel_mask(df, v) for k, v in d.items()}
    m = eval_cond(cond, sels) & chan_mask(df, rule["logsource"]["service"])
    return df[m]

def parse_span(s): return pd.Timedelta({"s": "seconds", "m": "minutes", "h": "hours"}[s[-1]] and f"{s[:-1]} {dict(s='seconds',m='minutes',h='hours')[s[-1]]}")

def run_correlation(df_all, crule, matches_by_name):
    c = crule["correlation"]; typ = c["type"]; span = parse_span(c["timespan"])
    gb = ["_file"] + list(c.get("group-by", []))
    parts = []
    for n in c["rules"]:
        x = matches_by_name[n][gb + ["TimeCreated"]].copy(); x["_rule"] = n; x["_idx"] = matches_by_name[n].index; parts.append(x)
    ev = pd.concat(parts); ev["t"] = pd.to_datetime(ev.TimeCreated, utc=True, errors="coerce"); ev = ev.dropna(subset=["t"]).sort_values("t")
    hits = []
    for key, g in ev.groupby(gb, dropna=False):
        g = g.reset_index(drop=True)
        if typ == "event_count":
            need = c["condition"]["gte"]
            for i in range(len(g)):
                w = g[(g.t >= g.t[i]) & (g.t <= g.t[i] + span)]
                if len(w) >= need: hits.append((key, g.t[i], len(w), list(w._idx))); break
        elif typ == "value_count":
            need = c["condition"]["gte"]; fld = c["condition"]["field"]
            src = df_all.loc[g._idx.unique(), [fld, "TimeCreated"]].copy(); src["t"] = pd.to_datetime(src.TimeCreated, utc=True, errors="coerce"); src = src.sort_values("t").reset_index()
            for i in range(len(src)):
                w = src[(src.t >= src.t[i]) & (src.t <= src.t[i] + span)]
                if w[fld].nunique() >= need: hits.append((key, src.t[i], w[fld].nunique(), list(w["index"])[:50])); break
        else:
            order = c["rules"]
            if set(order) - set(g._rule): continue
            if typ == "temporal":
                first = g[g._rule == order[0]].t
                for t0 in first:
                    w = g[(g.t >= t0) & (g.t <= t0 + span)]
                    if set(order) <= set(w._rule): hits.append((key, t0, len(w), list(w._idx))); break
            else:
                firsts = g[g._rule == order[0]].t
                for t0 in firsts:
                    t_prev, ok, idxs = t0, True, list(g[(g._rule == order[0]) & (g.t == t0)]._idx)
                    for n in order[1:]:
                        nxt = g[(g._rule == n) & (g.t >= t_prev) & (g.t <= t0 + span)]
                        if nxt.empty: ok = False; break
                        t_prev = nxt.t.iloc[0]; idxs += list(nxt._idx.iloc[:1])
                    if ok: hits.append((key, t0, len(idxs), idxs)); break
    return hits

KEYCOLS = ["_file","TimeCreated","Computer","EventID","Image","ParentImage","CommandLine","SourceImage","TargetImage","GrantedAccess","TargetObject","Details","SubjectUserName","TargetUserName","LogonType","LogonProcessName","IpAddress","ShareName","RelativeTargetName","ServiceName","ImagePath","TaskName","AccessMask"]

if __name__ == "__main__":
    nf = "--no-filters" in sys.argv
    df = pd.read_pickle("parsed/events.pkl")
    res = {}; by_name = {}
    os.makedirs("results/evidence", exist_ok=True)
    for r in load_rules():
        m = run_rule(df, r, nf); by_name[r["name"]] = m
        rid = os.path.basename(r["_path"]).split("_")[0]
        res[rid] = {"name": r["name"], "title": r["title"], "level": r["level"], "events": int(len(m)), "files": sorted(m._file.unique().tolist())}
        if not nf:
            cols = [c for c in KEYCOLS if c in m.columns and m[c].notna().any()]
            m[cols].head(25).to_csv(f"results/evidence/{rid}_{r['name']}.csv", index=False)
    corr = {}
    for p in sorted(glob.glob("rules/correlation/*.yml")):
        cr = yaml.safe_load(open(p)); h = run_correlation(df, cr, by_name)
        cid = os.path.basename(p).split("_")[0]
        corr[cid] = {"title": cr["title"], "type": cr["correlation"]["type"], "groups_matched": len(h),
                     "files": sorted({k[0] if isinstance(k, tuple) else k for k, *_ in h}),
                     "examples": [{"key": [str(x) for x in (k if isinstance(k, tuple) else (k,))], "start": str(t), "count": int(n)} for k, t, n, _ in h[:3]]}
        if h and not nf:
            idx = [i for i in h[0][3] if i in df.index]
            df.loc[idx, [c for c in KEYCOLS if c in df.columns]].dropna(axis=1, how="all").to_csv(f"results/evidence/{cid}_{cr['correlation']['rules'][0]}_corr.csv", index=False)
    out = {"single": res, "correlation": corr, "total_events": int(len(df)), "no_filters": nf}
    fn = "results/rule_test_results_nofilter.json" if nf else "results/rule_test_results.json"
    json.dump(out, open(fn, "w"), indent=1)
    for k, v in res.items(): print(f"{k} {v['name']:<34} events={v['events']:<5} files={len(v['files'])}")
    for k, v in corr.items(): print(f"{k} {v['title'][:40]:<42} groups={v['groups_matched']}")
