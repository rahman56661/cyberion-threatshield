"""Generates Sigma rule files in rules/ from compact definitions (single source of truth for rule metadata)."""
import yaml, uuid, os, json
NS = uuid.UUID("c0ffee00-0000-4000-8000-000000000001")
DATE = "2026-11-03"
AUTHOR = "Habebur Rahman, Aleena K Mani (Cyberion Defense Labs - Detection Engineering)"
EV = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES"
def mitre(t): return f"https://attack.mitre.org/techniques/{t.upper().replace('.','/')}/"

R = []
def rule(rid, name, title, desc, tactic, techs, svc, det, cond, fps, level, why, samples, extra_refs=()):
    R.append(dict(rid=rid, name=name, title=title, desc=desc, tactic=tactic, techs=techs, svc=svc,
                  det=det, cond=cond, fps=fps, level=level, why=why, samples=samples, refs=list(extra_refs)))

rule("DET-001","security_log_cleared","Windows Security Event Log Cleared",
 "Detects clearing of the Windows Security audit log (Event ID 1102). Adversaries clear logs to remove evidence of intrusion activity.",
 "defense-impairment",["t1685.005"],"security",
 {"selection":{"EventID":1102}},"selection",
 ["Authorised administrators clearing logs during maintenance or log-rotation","Lab/golden-image preparation before telemetry capture (seen in 24 dataset samples)"],
 "high","Log clearing is rarely routine on production hosts and directly destroys audit evidence; any occurrence deserves triage.",
 ["Defense Evasion/DE_1102_security_log_cleared.evtx"])

rule("DET-002","system_log_cleared","Windows System Event Log Cleared",
 "Detects clearing of the Windows System event log (Event ID 104 from the Eventlog provider).",
 "defense-impairment",["t1685.005"],"system",
 {"selection":{"EventID":104,"Provider|contains":"Eventlog"}},"selection",
 ["Administrator maintenance","Lab image preparation"],
 "high","Same intent as Security log clearing but on the System channel; used to hide service installs and driver loads.",
 ["Defense Evasion/DE_104_system_log_cleared.evtx"])

rule("DET-003","lsass_suspicious_access","Suspicious Process Access to LSASS Memory",
 "Detects a process opening a handle to lsass.exe with access rights typically used for credential dumping (Mimikatz, ProcDump, Dumpert, PPLdump, MiniDump).",
 "credential-access",["t1003.001"],"sysmon",
 {"selection":{"EventID":10,"TargetImage|endswith":"\\lsass.exe",
   "GrantedAccess|endswith":["1010","1410","1fffff","1f1fff","143a","1438","101ffb","1f3fff"]},
  "filter_system":{"SourceImage|endswith":["\\wininit.exe","\\csrss.exe","\\MsMpEng.exe","\\lsm.exe"]}},
 "selection and not filter_system",
 ["Endpoint protection / backup agents opening LSASS (add their paths to filter_system)","Crash-dump tooling used by IT"],
 "high","LSASS holds credential material; broad read/dump rights from non-system binaries are a strong indicator of credential theft.",
 ["Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx","Credential Access/babyshark_mimikatz_powershell.evtx"])

rule("DET-004","regsvr32_scriptlet_exec","Regsvr32 Scriptlet Execution (Squiblydoo)",
 "Detects regsvr32.exe loading a COM scriptlet via scrobj.dll or /i: argument, a signed-binary proxy execution technique. Command-line matching (scrobj.dll or a /i:http URL argument) also catches renamed copies of regsvr32.",
 "stealth",["t1218.010"],"sysmon",
 {"selection_cmd":{"EventID":1,"CommandLine|contains":"scrobj.dll"},
  "selection_bin":{"EventID":1,"Image|endswith":"\\regsvr32.exe","CommandLine|contains":[".sct","/i:http","/i:\\\\"]},
  "selection_renamed":{"EventID":1,"CommandLine|contains":"/i:http"}},
 "selection_cmd or selection_bin or selection_renamed",
 ["Legitimate COM registration with /i: switches by installers (rare, normally no .sct/scrobj)"],
 "high","Scriptlet loading through regsvr32 bypasses application allow-listing and has few legitimate uses.",
 ["Execution/exec_sysmon_lobin_regsvr32_sct.evtx","Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx"])

rule("DET-005","rundll32_proxy_exec","Rundll32 Proxy Execution of Script or URL Handlers",
 "Detects rundll32.exe used to run JavaScript, open URLs or invoke abusable exports (FileProtocolHandler, OpenURL, RegisterOCX, RouteTheCall, LaunchApplication, RunHTMLApplication).",
 "stealth",["t1218.011"],"sysmon",
 {"selection_bin":{"EventID":1,"CommandLine|contains":"rundll32"},
  "selection_args":{"CommandLine|contains":["javascript:","FileProtocolHandler","RegisterOCX","RouteTheCall","LaunchApplication","RunHTMLApplication","OpenURL"]}},
 "selection_bin and selection_args",
 ["Software installers calling advpack/setupapi exports","Help/URL handlers invoking url.dll from legacy apps"],
 "medium","Several of these exports are legitimate, but combined with rundll32 they are a common LOLBin execution path; medium keeps analyst load manageable.",
 ["Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx","Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx"])

rule("DET-006","bitsadmin_abuse","BITSAdmin Used for Transfer or Persistence",
 "Detects bitsadmin.exe creating transfer jobs, adding files or setting a notify command line, which can download payloads or persist code execution.",
 "persistence",["t1197"],"sysmon",
 {"selection_bin":{"EventID":1,"CommandLine|contains":"bitsadmin"},
  "selection_args":{"CommandLine|contains":["/transfer","/addfile","/setnotifycmdline","/create"]}},
 "selection_bin and selection_args",
 ["IT scripts using BITS to distribute software","Legacy deployment tools"],
 "medium","BITS is trusted and traffic blends in; /SetNotifyCmdLine specifically gives code execution, so the rule is medium with escalation on notify-cmd.",
 ["Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx"])

rule("DET-007","ifeo_debugger_backdoor","Image File Execution Options Debugger Set (Accessibility Backdoor)",
 "Detects a Debugger value written under Image File Execution Options, via registry events or reg.exe, used to hijack osk.exe/sethc.exe/utilman.exe or any binary for persistence and privilege escalation.",
 "persistence",["t1546.008","t1546.012"],"sysmon",
 {"selection_value":{"EventID":13,"TargetObject|contains":"Image File Execution Options","TargetObject|endswith":"\\Debugger"},
  "selection_cli":{"EventID":1,"CommandLine|contains":"Image File Execution Options","Image|endswith":"\\reg.exe"}},
 "selection_value or selection_cli",
 ["Developers attaching debuggers (WinDbg/Visual Studio) via IFEO on workstations"],
 "high","Debugger hijacks of accessibility binaries give SYSTEM shell at the logon screen; legitimate debugger use is limited to developer machines.",
 ["Persistence/persistence_accessibility_features_osk_sysmon1.evtx"])

rule("DET-008","runkey_user_writable_path","Registry Run Key Pointing to User-Writable Path",
 "Detects creation of a Run key value whose target resides in AppData, Users\\Public, Temp, ProgramData or Windows\\Tasks (a world-writable folder), a common malware persistence pattern.",
 "persistence",["t1547.001"],"sysmon",
 {"selection":{"EventID":13,"TargetObject|contains":"\\CurrentVersion\\Run","Details|contains":["\\AppData\\","\\Users\\Public\\","\\Temp\\","\\ProgramData\\","\\Windows\\Tasks\\"]}},"selection",
 ["Per-user installers (Teams, OneDrive, Zoom) that auto-start from AppData"],
 "medium","User-writable autostart paths are favoured by commodity malware but also used by benign per-user apps, hence medium.",
 ["Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.evtx"])

rule("DET-009","uac_bypass_registry_hijack","UAC Bypass via Registry Shell-Handler Hijack",
 "Detects writes to HKCU class handlers abused by auto-elevating binaries (eventvwr via mscfile, fodhelper/computerdefaults via ms-settings, sdclt via exefile runas isolatedcommand).",
 "privilege-escalation",["t1548.002"],"sysmon",
 {"selection":{"EventID":13,"TargetObject|contains":["\\mscfile\\shell\\open\\command","\\ms-settings\\shell\\open\\command","\\exefile\\shell\\runas\\command"]}},"selection",
 ["Very rare; some file-association tools modify these keys"],
 "high","These keys are not modified in normal operation and the technique grants a high-integrity shell without a prompt.",
 ["Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx","Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx"])

rule("DET-010","uac_disabled_enablelua","UAC Disabled via EnableLUA Registry Value",
 "Detects EnableLUA being set to 0, which turns off User Account Control.",
 "defense-impairment",["t1548.002","t1112"],"sysmon",
 {"selection":{"EventID":[12,13],"TargetObject|endswith":"\\policies\\system\\EnableLUA","Details|contains":"0x00000000"}},"selection",
 ["Troubleshooting by administrators; legacy-app compatibility GPOs"],
 "high","Disabling UAC removes a core privilege-boundary control and is a deliberate action.",
 ["Defense Evasion/DE_UAC_Disabled_Sysmon_12_13.evtx"])

rule("DET-011","remote_thread_injection","Remote Thread Created in Commonly Injected Process",
 "Detects CreateRemoteThread into notepad.exe, explorer.exe, lsass.exe or KeePass.exe, typical of Meterpreter/PowerShell reflective injection and credential theft tooling.",
 "stealth",["t1055"],"sysmon",
 {"selection":{"EventID":8,"TargetImage|endswith":["\\notepad.exe","\\explorer.exe","\\lsass.exe","\\KeePass.exe"]}},"selection",
 ["Accessibility and screen-reader software","Some AV/EDR and game anti-cheat products"],
 "high","Cross-process thread creation into a victim process is rarely legitimate for these targets.",
 ["Execution/Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx","Defense Evasion/de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx"])

rule("DET-012","wmiprvse_suspicious_child","WMI Provider Host Spawning Command Interpreter or LOLBin",
 "Detects WmiPrvSE.exe spawning cmd.exe, powershell.exe or rundll32.exe, characteristic of remote WMI execution (wmic /node, Invoke-WmiMethod).",
 "execution",["t1047"],"sysmon",
 {"selection":{"EventID":1,"ParentImage|endswith":"\\WmiPrvSE.exe","Image|endswith":["\\cmd.exe","\\powershell.exe","\\rundll32.exe","\\mshta.exe"]}},"selection",
 ["Management tools (SCCM, monitoring agents) using WMI to run scripts"],
 "medium","WMI remote execution is a staple of lateral movement but is also used by admin tooling.",
 ["Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"])

rule("DET-013","dcsync_non_machine_account","DCSync Replication Rights Used by Non-Machine Account",
 "Detects directory-replication GUIDs requested with Control Access (0x100) by a non-computer account (Event ID 4662), indicating DCSync via Mimikatz or Impacket.",
 "credential-access",["t1003.006"],"security",
 {"selection":{"EventID":4662,"AccessMask":"0x00000100","Properties|contains":["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ad-9c07-11d1-f79f-00c04fc2dcd2","89e95b76-444d-4c62-991a-0facbeda640c"]},
  "filter_machine":{"SubjectUserName|endswith":"$"}},
 "selection and not filter_machine",
 ["Azure AD Connect / MSOL service accounts that legitimately replicate","Backup or migration tooling with replication rights"],
 "critical","Only domain controllers should replicate; a user account doing so yields all password hashes.",
 ["Credential Access/CA_DCSync_4662.evtx"])

rule("DET-014","remote_svcctl_access","Remote Service Control Manager Access via SMB (svcctl)",
 "Detects SMB access to the svcctl named pipe on IPC$ (Event ID 5145), used by PsExec/RemCom/sc.exe to create remote services.",
 "lateral-movement",["t1021.002","t1569.002"],"security",
 {"selection":{"EventID":5145,"ShareName|endswith":"\\IPC$","RelativeTargetName":"svcctl"},"filter_local":{"IpAddress":["::1","127.0.0.1"]}},
 "selection and not filter_local",
 ["Remote administration by IT using sc.exe or management consoles"],
 "medium","Remote service creation is a core lateral movement primitive; admin tooling causes noise so medium until correlated.",
 ["Lateral Movement/LM_REMCOM_5145_TargetHost.evtx","Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx"])

rule("DET-015","suspicious_service_install","Service Installed with Command Interpreter Binary Path",
 "Detects Service Control Manager Event ID 7045 where ImagePath is cmd.exe, PowerShell, mshta, rundll32 or %COMSPEC%.",
 "persistence",["t1543.003"],"system",
 {"selection":{"EventID":7045,"ImagePath|contains":["cmd.exe","powershell","%COMSPEC%","mshta","rundll32"]}},"selection",
 ["Admin scripts that register services wrapping cmd (rare)"],
 "high","Legitimate services point at purpose-built executables, not interpreters.",
 ["Lateral Movement/LM_Remote_Service02_7045.evtx"])

rule("DET-016","scheduled_task_created_nonms","Scheduled Task Created Outside Microsoft Task Path",
 "Detects Event ID 4698 for tasks created outside \\Microsoft\\ paths, including randomly named tasks created by remote execution tools.",
 "execution",["t1053.005"],"security",
 {"selection":{"EventID":4698},"filter_ms":{"TaskName|startswith":"\\Microsoft\\"}},"selection and not filter_ms",
 ["Software updaters (Chrome, Adobe, Office) creating their own tasks"],
 "medium","Scheduled tasks are used for persistence and remote execution, but third-party updaters make this noisy; medium.",
 ["Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx"])

rule("DET-017","pth_seclogon_logon_type9","Pass-the-Hash Style NewCredentials Logon via seclogo",
 "Detects logon type 9 (NewCredentials) via the seclogo logon process, produced by Mimikatz sekurlsa::pth and secondary-logon abuse.",
 "lateral-movement",["t1550.002"],"security",
 {"selection":{"EventID":4624,"LogonType":9,"LogonProcessName|contains":"seclogo"}},"selection",
 ["runas /netonly used legitimately by administrators"],
 "high","Type 9 with seclogo is the signature of credential injection; runas /netonly is the main benign source.",
 ["Credential Access/tutto_malseclogon.evtx","Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx"])

rule("DET-018","rdp_loopback_tunnel","RDP Logon from Loopback Address (Tunnelled RDP)",
 "Detects interactive RDP logons (type 10) whose source IP is loopback, indicating RDP traffic tunnelled through a local port forward.",
 "command-and-control",["t1572","t1021.001"],"security",
 {"selection":{"EventID":4624,"LogonType":10,"IpAddress":["127.0.0.1","::1"]}},"selection",
 ["Local RDP loopback testing by administrators"],
 "high","Real RDP clients have a routable source address; loopback implies a tunnel such as SSH/plink/chisel.",
 ["Command and Control/DE_RDP_Tunnel_5156.evtx","Command and Control/DE_RDP_Tunneling_4624.evtx"])

rule("DET-019","ps_scriptblock_lsass_dump","PowerShell Script Block Dumping LSASS Memory",
 "Detects Script Block Logging (4104) content referencing lsass together with MiniDump/MiniDumpWriteDump/Out-Minidump.",
 "credential-access",["t1003.001"],"powershell",
 {"selection_id":{"EventID":4104,"ScriptBlockText|contains":"lsass"},"selection_dump":{"ScriptBlockText|contains":["MiniDump","Out-Minidump","comsvcs"]}},
 "selection_id and selection_dump",
 ["Security tooling / red-team scripts in authorised tests"],
 "high","Scripted LSASS dumping has no routine administrative use.",
 ["Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx"])

rule("DET-020","autoelevate_binary_spawns_shell","Auto-Elevating Binary Spawning Interpreter (UAC Bypass Child)",
 "Detects eventvwr.exe, sdclt.exe, fodhelper.exe or computerdefaults.exe spawning cmd, PowerShell or script hosts, i.e. the child process of a UAC bypass.",
 "privilege-escalation",["t1548.002"],"sysmon",
 {"selection":{"EventID":1,"ParentImage|endswith":["\\eventvwr.exe","\\sdclt.exe","\\fodhelper.exe","\\computerdefaults.exe"],
   "Image|endswith":["\\cmd.exe","\\powershell.exe","\\wscript.exe","\\mshta.exe"]}},"selection",
 ["None expected; these binaries do not normally launch interpreters (eventvwr launches mmc.exe, which is excluded)"],
 "high","High-integrity interpreter under an auto-elevating parent is a near-certain UAC bypass.",
 ["Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx"])


rule("DET-021","com_hijack_clsid_user_path","COM Object Hijack: CLSID Server Key Pointing to User-Writable Path",
 "Hunt 01 output. Detects registry writes that set a CLSID InprocServer32/LocalServer32 default value to a user-writable location (ProgramData, Users, Temp, AppData, Windows\\Tasks), the persistence pattern of COM hijacking used by Turla-style Outlook backdoors and Firefox hijacks.",
 "persistence",["t1546.015"],"sysmon",
 {"selection":{"EventID":13,"TargetObject|contains":"\\CLSID\\{","TargetObject|re":"\\\\(InprocServer32|LocalServer32)\\\\[\\(\\{]Default[\\)\\}]$",
   "Details|contains":["\\ProgramData\\","\\Users\\","\\Temp\\","\\AppData\\","\\Windows\\Tasks\\"]}},"selection",
 ["Per-user installed COM components (e.g., some Office add-ins, Teams/OneDrive shell extensions) register under HKCU with AppData paths"],
 "high","A CLSID server redirected to a user-writable DLL gives stealthy, logon-triggered persistence; per-user installers are the main benign source.",
 ["Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx"])

rule("DET-022","lolbin_external_connection","LOLBin Initiating Outbound Connection to a Public IP Address",
 "Hunt 02 pivot output. Detects certutil, mshta, regsvr32, rundll32, bitsadmin or wscript/cscript making outbound network connections to a non-private address, a hallmark of living-off-the-land payload download.",
 "command-and-control",["t1105"],"sysmon",
 {"selection":{"EventID":3,"Initiated":"true","Image|endswith":["\\certutil.exe","\\mshta.exe","\\regsvr32.exe","\\rundll32.exe","\\bitsadmin.exe","\\wscript.exe","\\cscript.exe"]},
  "filter_private":{"DestinationIp|startswith":["10.","192.168.","127.","169.254.","::1","0:0:0:0:0:0:0:1","fe80","172.16.","172.17.","172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.","172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31."]}},
 "selection and not filter_private",
 ["certutil used for legitimate CRL/certificate retrieval by some scripts","Software installers invoking rundll32/regsvr32 with network access"],
 "medium","These binaries rarely need internet access; connection to a public IP is suspicious but certificate/CRL lookups cause some noise.",
 ["AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx"])

def fired_samples(rid):
    try:
        res = json.load(open("results/rule_test_results.json"))["single"][rid]["files"]
        return res[:4]
    except Exception: return None

def write():
    os.makedirs("rules", exist_ok=True)
    meta = []
    for r in R:
        det = dict(r["det"]); det["condition"] = r["cond"]
        tags = [f"attack.{r['tactic']}"] + [f"attack.{t}" for t in r["techs"]]
        d = {"title": r["title"], "id": str(uuid.uuid5(NS, r["rid"])), "name": r["name"], "status": "experimental",
             "description": r["desc"],
             "references": [mitre(t) for t in r["techs"]] + [f"{EV} :: {s}" for s in (fired_samples(r["rid"]) or r["samples"])] + r["refs"],
             "author": AUTHOR, "date": DATE, "tags": tags,
             "logsource": {"product": "windows", "service": r["svc"]}, "detection": det,
             "falsepositives": r["fps"], "level": r["level"]}
        fn = f"rules/{r['rid']}_{r['name']}.yml"
        yaml.dump(d, open(fn, "w"), sort_keys=False, width=1000, allow_unicode=True)
        meta.append({**{k: r[k] for k in ("rid","name","title","tactic","techs","level","why","samples","fps")}, "file": fn, "id": d["id"]})
    json.dump(meta, open("rules/_meta.json", "w"), indent=1)
    print(len(R), "rules written")

if __name__ == "__main__": write()
