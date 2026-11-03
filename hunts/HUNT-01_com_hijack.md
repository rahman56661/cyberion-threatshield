# HUNT-01 - COM Object Hijacking Persistence (T1546.015)

| Field | Value |
|---|---|
| Hunt ID | HUNT-01 |
| ATT&CK | T1546.015 Component Object Model Hijacking (ATT&CK v20: Persistence, Privilege Escalation) |
| Prior coverage | **Not covered** (no rule before this hunt) |
| Data | Sysmon EID 12/13/14 from EVTX-ATTACK-SAMPLES (278 files, 37,364 events) |
| Script | `hunts/hunt_01_com_hijack.py` (reproducible; output `results/hunts/hunt01_com_hijack_hits.csv`) |
| Conclusion | **CONFIRMED** (2 COM hijacks) + 1 adjacent finding |

## Hypothesis
An adversary persisted by writing a CLSID server key (`InprocServer32`, `LocalServer32` or a `TreatAs` redirect) that points to a non-system, user-writable location, so a trusted application loads attacker code whenever it instantiates the COM class.

## Method
1. **Scope:** Sysmon registry events (12, 13, 14) whose `TargetObject` contains `\CLSID\{` and `InprocServer32 | LocalServer32 | TreatAs`. Result: **14 events in 3 samples**.
2. **Pivot to risk:** keep events where `Details` points into `ProgramData`, `Users`, `Temp`, `AppData`, `Windows\Tasks` or a `file:///` URL, or the key is a `TreatAs` redirect. Result: **5 events in 3 samples** (9 of 14 were removed: they were `mscoree.dll`, `ThreadingModel`, `RuntimeVersion` values of normal .NET COM registration).
3. **Triage each sample:** writer process, value written, parent context.

## Findings
| Sample | Writer | Value written | Assessment |
|---|---|---|---|
| `persist_firefox_comhijack_sysmon_11_13_7_1` | `com-hijack.exe` (Downloads) | `InprocServer32\(Default)` of CLSID `{BCDE0395-E52F-467C-8E3D-C4579291692E}` = `C:\ProgramData\demo.dll` | **True positive.** A per-user hijack loaded from ProgramData by an unsigned tool run from Downloads. |
| `persist_turla_outlook_backdoor_comhijack` | `reg.exe` | `InProcServer32` of CLSID `{49CBB1C7-97D1-485A-9EC1-A26065633066}` = `C:\Users\User\Documents\mapid.tlb`, plus `TreatAs` redirect from `{84DA0A92-25E0-11D3-B9F7-00C04F4C8F5D}` | **True positive.** A `TreatAs` redirect plus an `InProcServer32` pointing at a payload in a user directory is a classic COM-hijack pattern; the sample name attributes it to a Turla-style Outlook backdoor (attribution comes from the dataset label and was not independently verified). |
| `PanacheSysmon_vs_AtomicRedTeam01` | `regsvcs.exe` | .NET COM registration whose `CodeBase` is `file:///C:/AtomicRedTeam/T1121.DLL` | **Adjacent finding.** This is T1218.009 (Regsvcs/Regasm) abuse via the legitimate registration mechanism, not a hijack of an existing class. Not covered by any rule. |

## Negative results (what was ruled out)
- No `LocalServer32` hijacks, no hijacks of the other 275 samples.
- The 9 removed events were routine .NET COM registration values (default `mscoree.dll`), not hijacks.

## Outcome and hand-off
- New detection **DET-021** (`rules/DET-021_com_hijack_clsid_user_path.yml`) - fires on the Firefox and Outlook samples (2 events, 2 samples), 0 on the other 276.
- Remaining gap: `TreatAs` redirects and T1218.009 are not covered (listed in coverage matrix). Recommended next rule: `TreatAs\(Default)` value written by `reg.exe`.
- Limitation: DET-021 relies on Sysmon 13 being enabled for CLSID keys, which is not default Sysmon config in every deployment.
