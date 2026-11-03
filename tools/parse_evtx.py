"""Parse every .evtx in data/ into one flat JSONL file (one event per line).
Reproducible: python tools/parse_evtx.py"""
import json, os, sys, glob
from multiprocessing import Pool
from Evtx.Evtx import Evtx
from lxml import etree

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def parse_file(path):
    rows = []
    rel = os.path.relpath(path, "data").replace("\\", "/")
    tactic = rel.split("/")[0]
    try:
        with Evtx(path) as log:
            for rec in log.records():
                try:
                    root = etree.fromstring(rec.xml().encode("utf-8"))
                except Exception:
                    continue
                s = root.find("e:System", NS)
                if s is None: continue
                g = lambda t: (s.find(f"e:{t}", NS).text if s.find(f"e:{t}", NS) is not None else None)
                tc = s.find("e:TimeCreated", NS)
                d = {
                    "_file": rel, "_tactic": tactic,
                    "EventID": int(g("EventID") or 0),
                    "Channel": g("Channel"), "Computer": g("Computer"),
                    "Provider": s.find("e:Provider", NS).get("Name") if s.find("e:Provider", NS) is not None else None,
                    "TimeCreated": tc.get("SystemTime") if tc is not None else None,
                }
                ed = root.find("e:EventData", NS)
                if ed is not None:
                    for i, x in enumerate(ed):
                        name = x.get("Name") or f"Data{i}"
                        d[name] = x.text
                ud = root.find("e:UserData", NS)
                if ud is not None:
                    for x in ud.iter():
                        if x.text and x.text.strip():
                            d[etree.QName(x).localname] = x.text
                rows.append(d)
    except Exception as ex:
        sys.stderr.write(f"ERR {rel}: {ex}\n")
    return rows

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    files = sorted(glob.glob("data/**/*.evtx", recursive=True))
    print(f"Found {len(files)} files. Parsing takes 5-10 min. Do NOT press Ctrl+C.", flush=True)
    n = 0
    with Pool(max(1, (os.cpu_count() or 2) - 1)) as p, open("parsed/events.jsonl", "w", encoding="utf-8") as out:
        for i, rows in enumerate(p.imap(parse_file, files, chunksize=2), 1):
            for r in rows:
                out.write(json.dumps(r) + "\n"); n += 1
            if i % 20 == 0:
                print(f"{i}/{len(files)} files, {n} events", flush=True)
    print(f"files={len(files)} events={n}")
