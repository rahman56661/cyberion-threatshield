"""Hunt 02 - C2 beaconing (T1071/T1095). Hypothesis: a compromised host beacons to an external IP at a regular interval.
Method: Sysmon EID 3 outbound connections to non-private IPs, grouped by (sample, host, process, dst ip, port);
inter-arrival coefficient of variation (CV<0.3 and n>=8 = beacon-like).
Run: python hunts/hunt_02_beaconing.py"""
import pandas as pd, ipaddress
df = pd.read_pickle("parsed/events.pkl"); S = df[df.Channel.str.contains("Sysmon", na=False)]
n = S[S.EventID == 3].copy(); n["t"] = pd.to_datetime(n.TimeCreated, utc=True, errors="coerce")
n = n[n.Initiated.astype(str).str.lower() == "true"]
def is_public(ip):
    try: return ipaddress.ip_address(str(ip)).is_global   # handles expanded IPv6 loopback forms too
    except ValueError: return False
ext = n[n.DestinationIp.map(is_public)]
print(f"Sysmon EID3 total={len(S[S.EventID==3])} initiated={len(n)} outbound-public={len(ext)} samples={ext._file.nunique()}")
rows = []
for k, g in ext.groupby(["_file", "Computer", "Image", "DestinationIp", "DestinationPort"]):
    d = g.sort_values("t").t.diff().dt.total_seconds().dropna()
    rows.append(dict(sample=k[0].split("/")[-1], host=k[1], image=k[2].split("\\")[-1], dst=k[3], port=k[4], n=len(g),
                     mean_s=round(d.mean(), 1) if len(d) else None, cv=round(d.std() / d.mean(), 2) if len(d) > 1 and d.mean() > 0 else None))
r = pd.DataFrame(rows).sort_values("n", ascending=False); r.to_csv("results/hunts/hunt02_beacon_candidates.csv", index=False)
print(r.head(8).to_string(index=False))
print("Beacon-like (n>=8, CV<0.3):", len(r[(r.n >= 8) & (r.cv < 0.3)]))
print("Max connections to any single (host,proc,dst,port):", int(r.n.max()))
