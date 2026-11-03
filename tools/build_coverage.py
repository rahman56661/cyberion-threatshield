"""Build ATT&CK coverage matrix (xlsx + Navigator layer) from rule metadata, test results and official ATT&CK v20 STIX data.
A technique may only be 'Covered'/'Partially Covered' if every cited rule actually fired on real telemetry."""
import json, os, glob, yaml
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

res = json.load(open("results/rule_test_results.json"))
fired = {k: v["events"] > 0 for k, v in res["single"].items()} | {k: v["groups_matched"] > 0 for k, v in res["correlation"].items()}
files = set(pd.read_pickle("parsed/events.pkl")._file.unique()) if (pd := __import__("pandas")) else set()

# (technique, status, rules, evidence-sample-substring(s), note)
M = [
 ("T1685.005","Covered",["DET-001","DET-002"],["DE_1102_security_log_cleared","DE_104_system_log_cleared"],"Security 1102 and System 104. Benign lab-prep clears seen in 24 samples (see tuning)."),
 ("T1003.001","Covered",["DET-003","DET-019","COR-003"],["CA_sysmon_hashdump_cmd_meterpreter","Powershell_4104_MiniDumpWriteDump_Lsass"],"Sysmon EID10 access rights, PowerShell 4104, and LSASS+injection correlation."),
 ("T1003.006","Covered",["DET-013"],["CA_DCSync_4662"],"Non-machine account with replication GUIDs and Control Access."),
 ("T1218.010","Covered",["DET-004","COR-004"],["exec_sysmon_lobin_regsvr32_sct","exec_sysmon_1_lolbin_renamed_regsvr32_scrobj"],"Includes renamed regsvr32 via /i:http (added after validation miss)."),
 ("T1218.011","Covered",["DET-005"],["exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler"],"Script/URL handler abuse of rundll32; also catches the mshtml RunHTMLApplication variant."),
 ("T1548.002","Covered",["DET-009","DET-010","DET-020","COR-001"],["Sysmon_13_1_UACBypass_SDCLTBypass","Sysmon_13_1_UAC_Bypass_EventVwrBypass"],"Registry hijack plus elevated child, chained by COR-001."),
 ("T1055","Covered",["DET-011","COR-002"],["de_unmanagedpowershell_psinject_sysmon_7_8_10","Sysmon_meterpreter_ReflectivePEInjection_to_notepad_"],"Remote-thread creation into commonly injected processes; burst correlation."),
 ("T1543.003","Covered",["DET-015"],["LM_Remote_Service02_7045"],"Service with interpreter binary path (7045)."),
 ("T1053.005","Covered",["DET-016"],["LM_ScheduledTask_ATSVC_target_host"],"4698 outside Microsoft task path; updater noise expected."),
 ("T1572","Covered",["DET-018"],["DE_RDP_Tunnel_5156","DE_RDP_Tunneling_4624"],"Loopback-sourced RDP logon (type 10)."),
 ("T1546.012","Covered",["DET-007"],["persistence_SilentProcessExit_ImageHijack_sysmon_13_1"],"IFEO Debugger value write."),
 ("T1546.015","Covered",["DET-021"],["persist_firefox_comhijack_sysmon_11_13_7_1","persist_turla_outlook_backdoor_comhijack"],"Rule created from Hunt 01 findings."),
 ("T1197","Partially Covered",["DET-006","COR-004"],["PanacheSysmon_vs_AtomicRedTeam01"],"bitsadmin CLI only. COM/PowerShell BITS job creation (Bits-Client log) not covered."),
 ("T1546.008","Partially Covered",["DET-007"],["persistence_accessibility_features_osk_sysmon1"],"IFEO debugger path only; the osk.exe-spawns-shell outcome in the sample is not detected."),
 ("T1547.001","Partially Covered",["DET-008"],["evasion_persis_hidden_run_keyvalue_sysmon_13"],"Path heuristic; Run keys pointing at trusted-looking paths are missed."),
 ("T1112","Partially Covered",["DET-010"],["DE_UAC_Disabled_Sysmon_12_13"],"Only the EnableLUA value is covered; other tamper keys are not."),
 ("T1047","Partially Covered",["DET-012"],["LM_wmiexec_impacket_sysmon_whoami"],"Sysmon-based. Security 4688 sample LM_WMI_4624_4688_TargetHost has no parent field so was missed."),
 ("T1021.002","Partially Covered",["DET-014"],["LM_REMCOM_5145_TargetHost"],"svcctl pipe access only; C$/ADMIN$ file copy (5145) not covered."),
 ("T1569.002","Partially Covered",["DET-014"],["LM_Remote_Service01_5145_svcctl"],"Detected at SCM RPC stage, not at service execution."),
 ("T1550.002","Partially Covered",["DET-017"],["tutto_malseclogon"],"seclogo logon type 9 only; NTLM type-3 pass-the-hash not covered."),
 ("T1021.001","Partially Covered",["DET-018"],["DE_RDP_Tunneling_4624"],"Only tunnelled RDP; ordinary lateral RDP not covered."),
 ("T1105","Partially Covered",["DET-022","COR-004"],["panache_sysmon_vs_EDRTestingScript"],"LOLBin network egress only; browser/curl/PowerShell downloads not covered."),
 ("T1218.005","Not Covered",[],["LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1"],"Direct mshta.exe execution has no rule (only the rundll32/mshtml variant is covered)."),
 ("T1564.002","Not Covered",[],["persistence_hidden_local_account_sysmon"],"Hidden ($-suffixed) account registry change."),
 ("T1207","Not Covered",[],["persistence_security_dcshadow_4742"],"DCShadow rogue DC registration (4742)."),
 ("T1134","Not Covered",[],["Invoke_TokenDuplication_UAC_Bypass4624"],"Token duplication / impersonation."),
 ("T1187","Not Covered",[],["CA_PetiPotam_etw_rpc_efsr_5_6"],"PetiPotam forced authentication via EFSRPC."),
 ("T1210","Not Covered",[],["Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805"],"Zerologon exploitation (NetLogon 5805)."),
 ("T1087.002","Not Covered",[],["discovery_bloodhound"],"BloodHound/SharpHound domain account enumeration."),
 ("T1546.003","Not Covered",[],["sysmon_20_21_1_CommandLineEventConsumer"],"WMI event subscription persistence (Sysmon 19/20/21)."),
 ("T1070.006","Not Covered",[],["DE_timestomp_and_dll_sideloading_and_RunPersist"],"Timestomp (Sysmon EID 2) - no rule."),
 ("T1135","Not Covered",[],["discovery_enum_shares_target_sysmon_3_18"],"Network share enumeration."),
]
# technique names/tactics from official STIX (cached subset committed to repo)
ids = [m[0] for m in M]
if os.path.exists("reference/enterprise-attack.json"):
    objs = json.load(open("reference/enterprise-attack.json"))["objects"]; tm = {}
    for o in objs:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            for r in o.get("external_references", []):
                if r.get("source_name") == "mitre-attack" and r["external_id"] in ids:
                    tm[r["external_id"]] = {"name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])]}
    json.dump(tm, open("reference/technique_map_subset.json", "w"), indent=1)
else:
    tm = json.load(open("reference/technique_map_subset.json"))
assert all(i in tm for i in ids), [i for i in ids if i not in tm]
# integrity checks
for tid, st, rules, samples, _ in M:
    if st != "Not Covered":
        assert rules and all(fired.get(r) for r in rules), (tid, "rule did not fire", rules)
    for s in samples:
        assert any(s in f for f in files), (tid, "sample not found", s)

wb = Workbook(); ws = wb.active; ws.title = "Coverage Matrix"
hdr = ["Technique ID","Technique (ATT&CK v20)","Tactics (official)","Status","Supporting rule IDs","Dataset evidence sample(s)","Notes / gaps"]
ws.append(hdr)
F = {"Covered": "C6EFCE", "Partially Covered": "FFEB9C", "Not Covered": "FFC7CE"}
for tid, st, rules, samples, note in M:
    ws.append([tid, tm[tid]["name"], ", ".join(tm[tid]["tactics"]), st, ", ".join(rules) or "-", "; ".join(samples), note])
thin = Side(style="thin", color="BBBBBB"); font = "Arial"
for c in ws[1]: c.font = Font(name=font, bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="1F3864"); c.alignment = Alignment(wrap_text=True, vertical="center")
for r in ws.iter_rows(min_row=2):
    for c in r: c.font = Font(name=font, size=10); c.alignment = Alignment(wrap_text=True, vertical="top"); c.border = Border(top=thin, bottom=thin, left=thin, right=thin)
    r[3].fill = PatternFill("solid", fgColor=F[r[3].value]); r[3].font = Font(name=font, size=10, bold=True)
for i, w in enumerate([14, 34, 34, 18, 28, 52, 70], 1): ws.column_dimensions[get_column_letter(i)].width = w
ws.freeze_panes = "A2"; ws.auto_filter.ref = f"A1:G{len(M)+1}"
last = len(M) + 1

s = wb.create_sheet("Summary")
s["A1"] = "Coverage summary (formula-driven from 'Coverage Matrix')"; s["A1"].font = Font(name=font, bold=True, size=12)
s.append([]); s.append(["Status", "Techniques", "Share of assessed"])
for i, st in enumerate(["Covered", "Partially Covered", "Not Covered"]):
    r = 4 + i
    s[f"A{r}"] = st; s[f"B{r}"] = f"=COUNTIF('Coverage Matrix'!$D$2:$D${last},A{r})"; s[f"C{r}"] = f"=B{r}/B$7"; s[f"C{r}"].number_format = "0%"
s["A7"] = "Total assessed"; s["B7"] = "=SUM(B4:B6)"; s["A7"].font = Font(name=font, bold=True)
s["A9"] = "By primary tactic (technique counted under every tactic it belongs to in ATT&CK v20)"; s["A9"].font = Font(name=font, bold=True)
s.append([]); s.append(["Tactic", "Assessed", "Covered", "Partially Covered", "Not Covered"])
tactics = sorted({t for v in tm.values() for t in v["tactics"]})
for i, t in enumerate(tactics):
    r = 11 + i; s[f"A{r}"] = t
    s[f"B{r}"] = f"=COUNTIF('Coverage Matrix'!$C$2:$C${last},\"*\"&A{r}&\"*\")"
    for col, st in zip("CDE", ["Covered", "Partially Covered", "Not Covered"]):
        s[f"{col}{r}"] = f"=COUNTIFS('Coverage Matrix'!$C$2:$C${last},\"*\"&$A{r}&\"*\",'Coverage Matrix'!$D$2:$D${last},\"{st}\")"
s[f"A{12+len(tactics)}"] = "Note: counts use COUNTIF wildcard on the tactics column; Covered = every supporting rule fired on real telemetry (checked by tools/build_coverage.py)."
for row in s.iter_rows():
    for c in row:
        if c.font.name != font or not c.font.bold: c.font = Font(name=font, size=10, bold=c.font.bold)
for c in s[3] + s[10]: c.font = Font(name=font, bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="1F3864")
s.column_dimensions["A"].width = 30
for col in "BCDE": s.column_dimensions[col].width = 18

rm = wb.create_sheet("Rule-Technique Map")
rm.append(["Rule ID","Title","Level","Techniques (tags)","Events matched","Sample files matched","Tested on real data?"])
meta = {m["rid"]: m for m in json.load(open("rules/_meta.json"))}
for rid, v in res["single"].items():
    rm.append([rid, v["title"], v["level"], ", ".join(meta[rid]["techs"]).upper(), v["events"], len(v["files"]), "Yes" if v["events"] else "No"])
for cid, v in res["correlation"].items():
    rm.append([cid, v["title"], "-", "(correlation)", v["groups_matched"], len(v["files"]), "Yes" if v["groups_matched"] else "No"])
for c in rm[1]: c.font = Font(name=font, bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="1F3864")
for r in rm.iter_rows(min_row=2):
    for c in r: c.font = Font(name=font, size=10)
for i, w in enumerate([10, 70, 10, 30, 14, 18, 18], 1): rm.column_dimensions[get_column_letter(i)].width = w
wb.save("coverage/attack_coverage_matrix.xlsx")

col = {"Covered": "#8ec843", "Partially Covered": "#ffe766", "Not Covered": "#ff6666"}; sc = {"Covered": 3, "Partially Covered": 2, "Not Covered": 1}
layer = {"name": "Cyberion ThreatShield - Detection Coverage", "versions": {"attack": "20", "navigator": "5.1.0", "layer": "4.5"}, "domain": "enterprise-attack",
 "description": "Coverage of 22 Sigma + 4 correlation rules validated on EVTX-ATTACK-SAMPLES. Green=covered, yellow=partial, red=not covered.",
 "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 1, "maxValue": 3}, "legendItems": [{"label": k, "color": v} for k, v in col.items()],
 "techniques": [{"techniqueID": tid, "score": sc[st], "color": col[st], "comment": f"{st}. Rules: {', '.join(r) or 'none'}. {note}", "enabled": True} for tid, st, r, _, note in M]}
json.dump(layer, open("coverage/attack_navigator_layer.json", "w"), indent=1)
json.dump([dict(technique=t, name=tm[t]["name"], tactics=tm[t]["tactics"], status=st, rules=r, samples=sm, note=n) for t, st, r, sm, n in M], open("coverage/coverage_data.json", "w"), indent=1)
from collections import Counter; print(Counter(m[1] for m in M), "tactics:", len(tactics))
