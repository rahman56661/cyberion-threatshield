"""Hunt 01 - COM object hijacking (T1546.015). Hypothesis: an attacker persisted by writing a CLSID server key
(InprocServer32/LocalServer32/TreatAs) that points to a non-system, user-writable path.
Run: python hunts/hunt_01_com_hijack.py"""
import pandas as pd
df = pd.read_pickle("parsed/events.pkl"); S = df[df.Channel.str.contains("Sysmon", na=False)]
q = S[S.EventID.isin([12, 13, 14]) & S.TargetObject.str.contains(r"\\CLSID\\\{", case=False, na=False, regex=True)
      & S.TargetObject.str.contains("InprocServer32|LocalServer32|TreatAs", case=False, na=False, regex=True)]
print(f"Step1 CLSID server-key writes: {len(q)} events in {q._file.nunique()} files")
user_paths = r"\\ProgramData\\|\\Users\\|\\Temp\\|\\AppData\\|\\Windows\\Tasks\\|file:///"
q2 = q[q.Details.astype(str).str.contains(user_paths, case=False, regex=True) | q.TargetObject.str.contains("TreatAs", case=False)]
print(f"Step2 pointing to user-writable path or TreatAs redirect: {len(q2)} events in {q2._file.nunique()} files")
cols = ["_file", "TimeCreated", "Computer", "EventID", "Image", "TargetObject", "Details"]
q2[cols].to_csv("results/hunts/hunt01_com_hijack_hits.csv", index=False)
for f, g in q2.groupby("_file"):
    print(" -", f.split("/")[-1], "| writer:", g.Image.iloc[0].split("\\")[-1], "| events:", len(g))
