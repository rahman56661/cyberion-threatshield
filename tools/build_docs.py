"""Generate data-driven docs: data dictionary and rule library catalog."""
import json, yaml, glob, os, pandas as pd
df = pd.read_pickle("parsed/events.pkl")
res = json.load(open("results/rule_test_results.json")); tm = json.load(open("reference/technique_map_subset.json"))
meta = {m["rid"]: m for m in json.load(open("rules/_meta.json"))}

# ---------------- data dictionary ----------------
MEAN = {
 "Sysmon": {1: ("Process Create", {"Image":"Executable path; basis for LOLBin/renamed-binary logic","CommandLine":"Full arguments; primary field for LOLBin abuse detection","ParentImage":"Parent process; reveals unusual spawning (e.g. WmiPrvSE -> cmd)","ParentCommandLine":"Parent args; helps attribute script-driven chains","User":"Account context; separates SYSTEM vs user execution","IntegrityLevel":"Medium vs High shows privilege change (UAC bypass evidence)","Hashes":"File hashes for IOC matching","OriginalFileName":"PE-embedded name; exposes renamed binaries (not present in every sample)"}),
            3: ("Network Connection", {"Image":"Process making the connection","DestinationIp":"Remote IP; public vs private drives egress rules","DestinationPort":"Service/protocol hint","Initiated":"true = outbound from this host","DestinationHostname":"Reverse-DNS name when resolvable"}),
            8: ("CreateRemoteThread", {"SourceImage":"Injecting process","TargetImage":"Victim process","StartFunction":"Thread start; reflective loaders often show unknown"}),
            10: ("Process Access", {"SourceImage":"Accessing process","TargetImage":"Accessed process (lsass.exe = credential theft)","GrantedAccess":"Rights mask; 0x1010/0x1410/0x1fffff = read/dump rights","CallTrace":"Stack; shows unbacked memory callers"}),
            12: ("Registry key create/delete", {"TargetObject":"Registry path","EventType":"CreateKey/DeleteKey"}),
            13: ("Registry value set", {"TargetObject":"Registry path (persistence/UAC/IFEO keys)","Details":"Value written (payload path or DWORD)","Image":"Process that wrote the value"})},
 "Security": {1102: ("Audit log cleared", {"SubjectUserName":"Who cleared the log"}),
              4624: ("Logon success", {"LogonType":"2/3/9/10 distinguish interactive, network, NewCredentials, RDP","LogonProcessName":"seclogo/NtLmSsp/User32 reveal tool path","IpAddress":"Source address; loopback = tunnel","TargetUserName":"Account logged on","AuthenticationPackageName":"NTLM/Negotiate/Kerberos"}),
              4662: ("Directory object operation", {"Properties":"Object/property GUIDs (replication GUIDs = DCSync)","AccessMask":"0x100 = Control Access","SubjectUserName":"Machine ($) vs user account"}),
              4698: ("Scheduled task created", {"TaskName":"Task path; random names suspicious","SubjectUserName":"Creator"}),
              5145: ("Network share object checked", {"ShareName":"IPC$, ADMIN$, C$","RelativeTargetName":"Pipe/file (svcctl, psexec artifacts)","IpAddress":"Source host"})},
 "System": {104: ("Log cleared", {"Provider":"Microsoft-Windows-Eventlog"}), 7045: ("Service installed", {"ServiceName":"Service name","ImagePath":"Binary path; interpreters here are suspicious"})},
 "PowerShell": {4104: ("Script block logging", {"ScriptBlockText":"Decoded script content; keyword hunting target","ScriptBlockId":"Join key across multi-part blocks"})}}
CH = {"Sysmon": df.Channel.str.contains("Sysmon", na=False), "Security": df.Channel == "Security", "System": df.Channel == "System", "PowerShell": df.Channel.str.contains("PowerShell", na=False)}
o = ["# 02 - Data Dictionary (Module 4.1)", "", "Three telemetry source families (four channels) were selected from EVTX-ATTACK-SAMPLES. Counts are from the parsed dataset (`parsed/events.jsonl`, produced by `tools/parse_evtx.py`). *Fill* = share of that event type's records in which the field is populated.", "",
     f"**Dataset size:** {len(df):,} events from {df._file.nunique()} EVTX files, {df.Computer.nunique()} distinct hosts.", ""]
for src, evs in MEAN.items():
    sub = df[CH[src]]; o += [f"## {src} ({len(sub):,} events)", ""]
    for eid, (name, fields) in evs.items():
        e = sub[sub.EventID == eid]; o += [f"### Event ID {eid} - {name} ({len(e):,} events, {e._file.nunique()} samples)", "", "| Field | Fill | Detection meaning |", "|---|---|---|"]
        for f, m in fields.items():
            fill = f"{e[f].notna().mean()*100:.0f}%" if f in e and len(e) else "n/a"
            o.append(f"| `{f}` | {fill} | {m} |")
        o.append("")
o += ["## Data-quality notes", "", "- Sysmon `OriginalFileName` is absent in older samples, so renamed-binary detection relies on command-line content (see DET-004).", "- Security 4688 samples (e.g. `LM_WMI_4624_4688_TargetHost`) lack parent-process and command-line fields, which limits process-lineage rules.", "- Most samples are short captures (seconds to minutes) from a handful of lab hosts, so frequency-based analysis (beaconing) is weak (see Hunt 02).", "- Event timestamps are UTC; `Computer` names are lab hosts (IEWIN7, MSEDGEWIN10, PC01.example.corp, ...), not production systems."]
open("docs/02_data_dictionary.md", "w").write("\n".join(o))

# ---------------- rule library ----------------
o = ["# 03 - Detection Rule Library", "", f"{len(res['single'])} single-event rules and {len(res['correlation'])} correlation rules, all in Sigma format under `rules/`, all validated with `sigma check` (0 errors) and executed against {res['total_events']:,} real events by `tools/sigma_runner.py`.", "",
     "Technique IDs follow **ATT&CK v20** (tactic *Defense Evasion* no longer exists; it was split into *Stealth* and *Defense Impairment*, and T1070.001 became T1685.005).", "",
     "| Rule | Title | Level | Technique(s) | Events | Samples |", "|---|---|---|---|---|---|"]
for rid, v in res["single"].items():
    m = meta[rid]; o.append(f"| {rid} | {v['title']} | {v['level']} | {', '.join(t.upper() for t in m['techs'])} | {v['events']} | {len(v['files'])} |")
for cid, v in res["correlation"].items(): o.append(f"| {cid} | {v['title']} | - | correlation | {v['groups_matched']} groups | {len(v['files'])} |")
o += [""]
for p in sorted(glob.glob("rules/DET-*.yml")):
    r = yaml.safe_load(open(p)); rid = os.path.basename(p).split("_")[0]; v = res["single"][rid]; m = meta[rid]
    o += [f"## {rid} - {r['title']}", "", f"- **Rule file:** `{p}`", f"- **ATT&CK:** " + ", ".join(f"{t.upper()} ({tm[t.upper()]['name']})" for t in m["techs"] if t.upper() in tm),
          f"- **Log source:** {r['logsource']['service']} | **Condition:** `{r['detection']['condition']}`", f"- **Severity:** {r['level']} - {m['why']}",
          f"- **False positives:** " + "; ".join(r["falsepositives"]), f"- **Test result:** {v['events']} events in {len(v['files'])} samples. Samples: " + ", ".join(f"`{f.split('/')[-1]}`" for f in v["files"][:4]) + (" ..." if len(v["files"]) > 4 else ""), ""]
    ev = glob.glob(f"results/evidence/{rid}_*.csv")
    if ev:
        e = pd.read_csv(ev[0]).head(1).iloc[0].dropna().to_dict()
        o += ["  *Evidence (first match):* `" + "; ".join(f"{k}={str(x)[:90]}" for k, x in e.items() if k in ("_file", "TimeCreated", "Computer", "Image", "CommandLine", "TargetObject", "SourceImage", "TargetImage", "GrantedAccess", "SubjectUserName", "IpAddress", "LogonType", "DestinationIp") )+ "`", ""]
o += ["## Correlation rules", ""]
for p in sorted(glob.glob("rules/correlation/COR-*.yml")):
    r = yaml.safe_load(open(p)); cid = os.path.basename(p).split("_")[0]; v = res["correlation"][cid]; c = r["correlation"]
    o += [f"### {cid} - {r['title']}", "", f"- **Type:** {c['type']} | **Rules:** {', '.join(c['rules'])} | **Group-by:** {', '.join(c['group-by'])} | **Timespan:** {c['timespan']} | **Level:** {r['level']}", f"- **Result:** matched in {v['groups_matched']} host/sample group(s): " + ", ".join(f"`{f.split('/')[-1]}`" for f in v["files"]), f"- **Description:** {r['description']}", ""]
o += ["## Validation log (honest record)", "", "Initial expectations were checked against the rules' actual results. Misses led to changes:", "",
      "| Rule | Expectation | Finding | Action |", "|---|---|---|---|",
      "| DET-004 | Renamed regsvr32 sample should fire | Sample used `jabber.exe /u /s /i:http://...` with no scrobj | Added `/i:http` renamed-binary selection |",
      "| DET-006 | `sysmon_1_persist_bitsjob_SetNotifyCmdLine` should fire | Sample is COM-based BITS, no bitsadmin | Removed wrong citation; coverage marked Partial |",
      "| DET-007 | osk accessibility sample should fire | Sample has no IFEO key write (only osk.exe -> whoami) | Added reg.exe IFEO variant; the unvalidated key-create variant was dropped; coverage Partial |",
      "| DET-008 | Hidden Run key sample should fire | Target path was `C:\\Windows\\Tasks\\` | Added `\\Windows\\Tasks\\` to path list |",
      "| DET-012 | WMI 4688 sample should fire | Security 4688 has no parent info | Documented as gap; coverage Partial |",
      "| DET-003 | `services.exe` is a benign LSASS accessor | The only services.exe events were inside the PPLdump attack sample | Reverted the filter (it hid attack evidence) |"]
open("docs/03_rule_library.md", "w").write("\n".join(o)); print("docs written", len(o))
