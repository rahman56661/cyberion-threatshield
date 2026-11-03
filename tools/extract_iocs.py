"""Extract IOCs (public IPs, URLs/domains, file hashes, suspicious paths) from the parsed telemetry."""
import pandas as pd, re, ipaddress, json
df = pd.read_pickle("parsed/events.pkl"); S = df[df.Channel.str.contains("Sysmon", na=False)]
out = {}
# public IPs (Sysmon 3)
n = S[(S.EventID == 3) & (S.Initiated.astype(str).str.lower() == "true")]
def pub(ip):
    try: return ipaddress.ip_address(str(ip)).is_global
    except ValueError: return False
ips = n[n.DestinationIp.map(pub)].groupby("DestinationIp").agg(events=("EventID", "size"), procs=("Image", lambda x: sorted({i.split("\\")[-1] for i in x})), samples=("_file", lambda x: sorted({i.split("/")[-1] for i in x})[:3]), port=("DestinationPort", lambda x: sorted(set(map(str, x)))[:3])).reset_index()
out["ips"] = ips.to_dict("records")
# URLs in command lines / script blocks
txt = pd.concat([S.CommandLine.dropna(), df[df.EventID == 4104].ScriptBlockText.dropna()])
urls = {}
for t in txt:
    for u in re.findall(r"https?://[^\s\"'\)\]]+", t): urls[u.rstrip(".,;")] = urls.get(u.rstrip(".,;"), 0) + 1
out["urls"] = [{"url": u, "count": c} for u, c in sorted(urls.items(), key=lambda x: -x[1])]
# hashes of known offensive tooling images (Sysmon 1)
h = S[(S.EventID == 1) & S.Hashes.notna() & S.Image.str.contains(r"mimikatz|procdump|PPLdump|Dumpert|AndrewSpecial|MalSeclogon|KeeFarce|com-hijack|jabber|svchost\.exe$", case=False, na=False, regex=True)]
def sha(x):
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", str(x)); return m.group(1).lower() if m else None
h = h.assign(sha256=h.Hashes.map(sha)).dropna(subset=["sha256"])
h = h[~h.Image.str.lower().str.contains(r"system32|syswow64", regex=True)]
out["hashes"] = h.groupby(["sha256"]).agg(image=("Image", lambda x: sorted({i.split("\\")[-1] for i in x})[0]), path=("Image", "first"), sample=("_file", lambda x: x.iloc[0].split("/")[-1])).reset_index().to_dict("records")
json.dump(out, open("results/iocs.json", "w"), indent=1, default=str)
print({k: len(v) for k, v in out.items()})
for r in out["ips"][:10]: print(r["DestinationIp"], r["events"], r["procs"], r["port"])
for r in out["urls"][:12]: print(r["count"], r["url"][:110])
for r in out["hashes"][:10]: print(r["sha256"][:16], r["image"], "|", r["sample"][:40])
