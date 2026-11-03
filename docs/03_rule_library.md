# 03 - Detection Rule Library

22 single-event rules and 4 correlation rules, all in Sigma format under `rules/`, all validated with `sigma check` (0 errors) and executed against 37,364 real events by `tools/sigma_runner.py`.

Technique IDs follow **ATT&CK v20** (tactic *Defense Evasion* no longer exists; it was split into *Stealth* and *Defense Impairment*, and T1070.001 became T1685.005).

| Rule | Title | Level | Technique(s) | Events | Samples |
|---|---|---|---|---|---|
| DET-001 | Windows Security Event Log Cleared | high | T1685.005 | 24 | 24 |
| DET-002 | Windows System Event Log Cleared | high | T1685.005 | 2 | 2 |
| DET-003 | Suspicious Process Access to LSASS Memory | high | T1003.001 | 26 | 14 |
| DET-004 | Regsvr32 Scriptlet Execution (Squiblydoo) | high | T1218.010 | 10 | 6 |
| DET-005 | Rundll32 Proxy Execution of Script or URL Handlers | medium | T1218.011 | 19 | 10 |
| DET-006 | BITSAdmin Used for Transfer or Persistence | medium | T1197 | 10 | 2 |
| DET-007 | Image File Execution Options Debugger Set (Accessibility Backdoor) | high | T1546.008, T1546.012 | 8 | 2 |
| DET-008 | Registry Run Key Pointing to User-Writable Path | medium | T1547.001 | 3 | 3 |
| DET-009 | UAC Bypass via Registry Shell-Handler Hijack | high | T1548.002 | 5 | 4 |
| DET-010 | UAC Disabled via EnableLUA Registry Value | high | T1548.002, T1112 | 1 | 1 |
| DET-011 | Remote Thread Created in Commonly Injected Process | high | T1055 | 101 | 9 |
| DET-012 | WMI Provider Host Spawning Command Interpreter or LOLBin | medium | T1047 | 11 | 5 |
| DET-013 | DCSync Replication Rights Used by Non-Machine Account | critical | T1003.006 | 3 | 1 |
| DET-014 | Remote Service Control Manager Access via SMB (svcctl) | medium | T1021.002, T1569.002 | 5 | 3 |
| DET-015 | Service Installed with Command Interpreter Binary Path | high | T1543.003 | 3 | 2 |
| DET-016 | Scheduled Task Created Outside Microsoft Task Path | medium | T1053.005 | 3 | 3 |
| DET-017 | Pass-the-Hash Style NewCredentials Logon via seclogo | high | T1550.002 | 4 | 4 |
| DET-018 | RDP Logon from Loopback Address (Tunnelled RDP) | high | T1572, T1021.001 | 2 | 2 |
| DET-019 | PowerShell Script Block Dumping LSASS Memory | high | T1003.001 | 1 | 1 |
| DET-020 | Auto-Elevating Binary Spawning Interpreter (UAC Bypass Child) | high | T1548.002 | 4 | 4 |
| DET-021 | COM Object Hijack: CLSID Server Key Pointing to User-Writable Path | high | T1546.015 | 2 | 2 |
| DET-022 | LOLBin Initiating Outbound Connection to a Public IP Address | medium | T1105 | 12 | 5 |
| COR-001 | UAC Bypass Chain: Registry Hijack Followed by Elevated Interpreter | - | correlation | 3 groups | 3 |
| COR-002 | Process Injection Burst: Repeated Remote Thread Creation from One Source | - | correlation | 2 groups | 2 |
| COR-003 | Credential Dumping via Injection: LSASS Access Plus Remote Thread | - | correlation | 1 groups | 1 |
| COR-004 | Download via BITSAdmin Followed by Scriptlet Execution | - | correlation | 2 groups | 2 |

## DET-001 - Windows Security Event Log Cleared

- **Rule file:** `rules/DET-001_security_log_cleared.yml`
- **ATT&CK:** T1685.005 (Clear Windows Event Logs)
- **Log source:** security | **Condition:** `selection`
- **Severity:** high - Log clearing is rarely routine on production hosts and directly destroys audit evidence; any occurrence deserves triage.
- **False positives:** Authorised administrators clearing logs during maintenance or log-rotation; Lab/golden-image preparation before telemetry capture (seen in 24 dataset samples)
- **Test result:** 24 events in 24 samples. Samples: `DE_RDP_Tunnel_5156.evtx`, `ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx`, `CA_chrome_firefox_opera_4663.evtx`, `Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx` ...

  *Evidence (first match):* `_file=Command and Control/DE_RDP_Tunnel_5156.evtx; TimeCreated=2019-02-13 18:01:41.593830+00:00; Computer=PC01.example.corp; SubjectUserName=admin01`

## DET-002 - Windows System Event Log Cleared

- **Rule file:** `rules/DET-002_system_log_cleared.yml`
- **ATT&CK:** T1685.005 (Clear Windows Event Logs)
- **Log source:** system | **Condition:** `selection`
- **Severity:** high - Same intent as Security log clearing but on the System channel; used to hide service installs and driver loads.
- **False positives:** Administrator maintenance; Lab image preparation
- **Test result:** 2 events in 2 samples. Samples: `Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx`, `DE_104_system_log_cleared.evtx`

  *Evidence (first match):* `_file=Credential Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.evtx; TimeCreated=2020-09-15 19:28:31.453648+00:00; Computer=01566s-win16-ir.threebeesco.com; SubjectUserName=a-jbrown`

## DET-003 - Suspicious Process Access to LSASS Memory

- **Rule file:** `rules/DET-003_lsass_suspicious_access.yml`
- **ATT&CK:** T1003.001 (LSASS Memory)
- **Log source:** sysmon | **Condition:** `selection and not filter_system`
- **Severity:** high - LSASS holds credential material; broad read/dump rights from non-system binaries are a strong indicator of credential theft.
- **False positives:** Endpoint protection / backup agents opening LSASS (add their paths to filter_system); Crash-dump tooling used by IT
- **Test result:** 26 events in 14 samples. Samples: `PanacheSysmon_vs_AtomicRedTeam01.evtx`, `CA_sysmon_hashdump_cmd_meterpreter.evtx`, `babyshark_mimikatz_powershell.evtx`, `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx` ...

  *Evidence (first match):* `_file=AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx; TimeCreated=2019-07-19 15:11:16.487989+00:00; Computer=MSEDGEWIN10; SourceImage=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; TargetImage=C:\Windows\system32\lsass.exe; GrantedAccess=0x00001010`

## DET-004 - Regsvr32 Scriptlet Execution (Squiblydoo)

- **Rule file:** `rules/DET-004_regsvr32_scriptlet_exec.yml`
- **ATT&CK:** T1218.010 (Regsvr32)
- **Log source:** sysmon | **Condition:** `selection_cmd or selection_bin or selection_renamed`
- **Severity:** high - Scriptlet loading through regsvr32 bypasses application allow-listing and has few legitimate uses.
- **False positives:** Legitimate COM registration with /i: switches by installers (rare, normally no .sct/scrobj)
- **Test result:** 10 events in 6 samples. Samples: `PanacheSysmon_vs_AtomicRedTeam01.evtx`, `panache_sysmon_vs_EDRTestingScript.evtx`, `exec_sysmon_1_7_jscript9_defense_evasion.evtx`, `exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx` ...

  *Evidence (first match):* `_file=AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx; TimeCreated=2019-07-19 14:53:42.815966+00:00; Computer=MSEDGEWIN10; Image=C:\Windows\System32\cmd.exe; CommandLine="C:\Windows\system32\cmd.exe" /c "regsvr32.exe /s /u /i:C:\AtomicRedTeam\atomics\T1117\Reg`

## DET-005 - Rundll32 Proxy Execution of Script or URL Handlers

- **Rule file:** `rules/DET-005_rundll32_proxy_exec.yml`
- **ATT&CK:** T1218.011 (Rundll32)
- **Log source:** sysmon | **Condition:** `selection_bin and selection_args`
- **Severity:** medium - Several of these exports are legitimate, but combined with rundll32 they are a common LOLBin execution path; medium keeps analyst load manageable.
- **False positives:** Software installers calling advpack/setupapi exports; Help/URL handlers invoking url.dll from legacy apps
- **Test result:** 19 events in 10 samples. Samples: `panache_sysmon_vs_EDRTestingScript.evtx`, `Sysmon_Exec_CompiledHTML.evtx`, `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx`, `exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx` ...

  *Evidence (first match):* `_file=AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx; TimeCreated=2019-07-29 21:34:10.373482+00:00; Computer=MSEDGEWIN10; Image=C:\Windows\System32\cmd.exe; CommandLine=cmd  /c rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObjec`

## DET-006 - BITSAdmin Used for Transfer or Persistence

- **Rule file:** `rules/DET-006_bitsadmin_abuse.yml`
- **ATT&CK:** T1197 (BITS Jobs)
- **Log source:** sysmon | **Condition:** `selection_bin and selection_args`
- **Severity:** medium - BITS is trusted and traffic blends in; /SetNotifyCmdLine specifically gives code execution, so the rule is medium with escalation on notify-cmd.
- **False positives:** IT scripts using BITS to distribute software; Legacy deployment tools
- **Test result:** 10 events in 2 samples. Samples: `PanacheSysmon_vs_AtomicRedTeam01.evtx`, `panache_sysmon_vs_EDRTestingScript.evtx`

  *Evidence (first match):* `_file=AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx; TimeCreated=2019-07-19 14:48:04.103365+00:00; Computer=MSEDGEWIN10; Image=C:\Windows\System32\cmd.exe; CommandLine="C:\Windows\system32\cmd.exe" /c "bitsadmin.exe  /transfer /Download /priority Foreground `

## DET-007 - Image File Execution Options Debugger Set (Accessibility Backdoor)

- **Rule file:** `rules/DET-007_ifeo_debugger_backdoor.yml`
- **ATT&CK:** T1546.008 (Accessibility Features), T1546.012 (Image File Execution Options Injection)
- **Log source:** sysmon | **Condition:** `selection_value or selection_cli`
- **Severity:** high - Debugger hijacks of accessibility binaries give SYSTEM shell at the logon screen; legitimate debugger use is limited to developer machines.
- **False positives:** Developers attaching debuggers (WinDbg/Visual Studio) via IFEO on workstations
- **Test result:** 8 events in 2 samples. Samples: `PanacheSysmon_vs_AtomicRedTeam01.evtx`, `persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx`

  *Evidence (first match):* `_file=AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx; TimeCreated=2019-07-19 14:50:02.220425+00:00; Computer=MSEDGEWIN10; Image=C:\Windows\system32\reg.exe; TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Deb`

## DET-008 - Registry Run Key Pointing to User-Writable Path

- **Rule file:** `rules/DET-008_runkey_user_writable_path.yml`
- **ATT&CK:** T1547.001 (Registry Run Keys / Startup Folder)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** medium - User-writable autostart paths are favoured by commodity malware but also used by benign per-user apps, hence medium.
- **False positives:** Per-user installers (Teams, OneDrive, Zoom) that auto-start from AppData
- **Test result:** 3 events in 3 samples. Samples: `DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`, `sideloading_injection_persistence_run_key.evtx`, `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx`

  *Evidence (first match):* `_file=AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx; TimeCreated=2019-04-27 15:57:53.884487+00:00; Computer=IEWIN7; Image=C:\Users\IEUser\AppData\Roaming\NvSmart.exe; TargetObject=HKU\S-1-5-21-3583694148-1414552638-2922671848-1000\Software\Microsoft\Windows\CurrentVersi`

## DET-009 - UAC Bypass via Registry Shell-Handler Hijack

- **Rule file:** `rules/DET-009_uac_bypass_registry_hijack.yml`
- **ATT&CK:** T1548.002 (Bypass User Account Control)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** high - These keys are not modified in normal operation and the technique grants a high-integrity shell without a prompt.
- **False positives:** Very rare; some file-association tools modify these keys
- **Test result:** 5 events in 4 samples. Samples: `Sysmon_13_1_UACBypass_SDCLTBypass.evtx`, `Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx`, `Sysmon_UACME_33.evtx`, `sysmon_13_1_compmgmtlauncherUACBypass.evtx`

  *Evidence (first match):* `_file=Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx; TimeCreated=2019-05-09 02:07:51.116072+00:00; Computer=IEWIN7; Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; TargetObject=HKU\S-1-5-21-3583694148-1414552638-2922671848-1000_CLASSES\exefile\shell\runas\command\Iso`

## DET-010 - UAC Disabled via EnableLUA Registry Value

- **Rule file:** `rules/DET-010_uac_disabled_enablelua.yml`
- **ATT&CK:** T1548.002 (Bypass User Account Control), T1112 (Modify Registry)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** high - Disabling UAC removes a core privilege-boundary control and is a deliberate action.
- **False positives:** Troubleshooting by administrators; legacy-app compatibility GPOs
- **Test result:** 1 events in 1 samples. Samples: `DE_UAC_Disabled_Sysmon_12_13.evtx`

  *Evidence (first match):* `_file=Defense Evasion/DE_UAC_Disabled_Sysmon_12_13.evtx; TimeCreated=2019-05-16 14:17:15.763712+00:00; Computer=DC1.insecurebank.local; Image=C:\Windows\system32\reg.exe; TargetObject=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\EnableLUA`

## DET-011 - Remote Thread Created in Commonly Injected Process

- **Rule file:** `rules/DET-011_remote_thread_injection.yml`
- **ATT&CK:** T1055 (Process Injection)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** high - Cross-process thread creation into a victim process is rarely legitimate for these targets.
- **False positives:** Accessibility and screen-reader software; Some AV/EDR and game anti-cheat products
- **Test result:** 101 events in 9 samples. Samples: `sideloading_uacbypass_rundll32_injection_c2.evtx`, `CA_keefarce_keepass_credump.evtx`, `CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx`, `CA_sysmon_hashdump_cmd_meterpreter.evtx` ...

  *Evidence (first match):* `_file=AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx; TimeCreated=2020-10-17 11:43:40.903538+00:00; Computer=MSEDGEWIN10; SourceImage=C:\Users\IEUser\AppData\Roaming\WINWORD.exe; TargetImage=C:\Windows\SysWOW64\explorer.exe`

## DET-012 - WMI Provider Host Spawning Command Interpreter or LOLBin

- **Rule file:** `rules/DET-012_wmiprvse_suspicious_child.yml`
- **ATT&CK:** T1047 (Windows Management Instrumentation)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** medium - WMI remote execution is a staple of lateral movement but is also used by admin tooling.
- **False positives:** Management tools (SCCM, monitoring agents) using WMI to run scripts
- **Test result:** 11 events in 5 samples. Samples: `sysmon_10_1_memdump_comsvcs_minidump.evtx`, `LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx`, `LM_wmiexec_impacket_sysmon_whoami.evtx`, `smbmap_upload_exec_sysmon.evtx` ...

  *Evidence (first match):* `_file=Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx; TimeCreated=2019-08-30 12:54:08.354050+00:00; Computer=MSEDGEWIN10; Image=C:\Windows\System32\rundll32.exe; CommandLine=rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin fu`

## DET-013 - DCSync Replication Rights Used by Non-Machine Account

- **Rule file:** `rules/DET-013_dcsync_non_machine_account.yml`
- **ATT&CK:** T1003.006 (DCSync)
- **Log source:** security | **Condition:** `selection and not filter_machine`
- **Severity:** critical - Only domain controllers should replicate; a user account doing so yields all password hashes.
- **False positives:** Azure AD Connect / MSOL service accounts that legitimately replicate; Backup or migration tooling with replication rights
- **Test result:** 3 events in 1 samples. Samples: `CA_DCSync_4662.evtx`

  *Evidence (first match):* `_file=Credential Access/CA_DCSync_4662.evtx; TimeCreated=2019-05-08 02:10:43.487217+00:00; Computer=DC1.insecurebank.local; SubjectUserName=Administrator`

## DET-014 - Remote Service Control Manager Access via SMB (svcctl)

- **Rule file:** `rules/DET-014_remote_svcctl_access.yml`
- **ATT&CK:** T1021.002 (SMB/Windows Admin Shares), T1569.002 (Service Execution)
- **Log source:** security | **Condition:** `selection and not filter_local`
- **Severity:** medium - Remote service creation is a core lateral movement primitive; admin tooling causes noise so medium until correlated.
- **False positives:** Remote administration by IT using sc.exe or management consoles
- **Test result:** 5 events in 3 samples. Samples: `LM_REMCOM_5145_TargetHost.evtx`, `LM_Remote_Service01_5145_svcctl.evtx`, `LM_renamed_psexecsvc_5145.evtx`

  *Evidence (first match):* `_file=Lateral Movement/LM_REMCOM_5145_TargetHost.evtx; TimeCreated=2019-02-16 17:54:41.256813+00:00; Computer=PC01.example.corp; SubjectUserName=IEUser; IpAddress=10.0.2.16`

## DET-015 - Service Installed with Command Interpreter Binary Path

- **Rule file:** `rules/DET-015_suspicious_service_install.yml`
- **ATT&CK:** T1543.003 (Windows Service)
- **Log source:** system | **Condition:** `selection`
- **Severity:** high - Legitimate services point at purpose-built executables, not interpreters.
- **False positives:** Admin scripts that register services wrapping cmd (rare)
- **Test result:** 3 events in 2 samples. Samples: `LM_Remote_Service02_7045.evtx`, `System_7045_namedpipe_privesc.evtx`

  *Evidence (first match):* `_file=Lateral Movement/LM_Remote_Service02_7045.evtx; TimeCreated=2019-03-03 09:20:28.621489+00:00; Computer=WIN-77LTAPHIQ1R.example.corp`

## DET-016 - Scheduled Task Created Outside Microsoft Task Path

- **Rule file:** `rules/DET-016_scheduled_task_created_nonms.yml`
- **ATT&CK:** T1053.005 (Scheduled Task)
- **Log source:** security | **Condition:** `selection and not filter_ms`
- **Severity:** medium - Scheduled tasks are used for persistence and remote execution, but third-party updaters make this noisy; medium.
- **False positives:** Software updaters (Chrome, Adobe, Office) creating their own tasks
- **Test result:** 3 events in 3 samples. Samples: `temp_scheduled_task_4698_4699.evtx`, `LM_ScheduledTask_ATSVC_target_host.evtx`, `PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx`

  *Evidence (first match):* `_file=Execution/temp_scheduled_task_4698_4699.evtx; TimeCreated=2019-03-19 00:02:04.319944+00:00; Computer=WIN-77LTAPHIQ1R.example.corp; SubjectUserName=Administrator`

## DET-017 - Pass-the-Hash Style NewCredentials Logon via seclogo

- **Rule file:** `rules/DET-017_pth_seclogon_logon_type9.yml`
- **ATT&CK:** T1550.002 (Pass the Hash)
- **Log source:** security | **Condition:** `selection`
- **Severity:** high - Type 9 with seclogo is the signature of credential injection; runas /netonly is the main benign source.
- **False positives:** runas /netonly used legitimately by administrators
- **Test result:** 4 events in 4 samples. Samples: `tutto_malseclogon.evtx`, `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`, `Invoke_TokenDuplication_UAC_Bypass4624.evtx`, `security_4624_4673_token_manip.evtx`

  *Evidence (first match):* `_file=Credential Access/tutto_malseclogon.evtx; TimeCreated=2021-12-07 17:33:01.616154+00:00; Computer=MSEDGEWIN10; SubjectUserName=IEUser; LogonType=9; IpAddress=::1`

## DET-018 - RDP Logon from Loopback Address (Tunnelled RDP)

- **Rule file:** `rules/DET-018_rdp_loopback_tunnel.yml`
- **ATT&CK:** T1572 (Protocol Tunneling), T1021.001 (Remote Desktop Protocol)
- **Log source:** security | **Condition:** `selection`
- **Severity:** high - Real RDP clients have a routable source address; loopback implies a tunnel such as SSH/plink/chisel.
- **False positives:** Local RDP loopback testing by administrators
- **Test result:** 2 events in 2 samples. Samples: `DE_RDP_Tunnel_5156.evtx`, `DE_RDP_Tunneling_4624.evtx`

  *Evidence (first match):* `_file=Command and Control/DE_RDP_Tunnel_5156.evtx; TimeCreated=2019-02-13 18:04:58.363695+00:00; Computer=PC01.example.corp; SubjectUserName=PC01$; LogonType=10; IpAddress=127.0.0.1`

## DET-019 - PowerShell Script Block Dumping LSASS Memory

- **Rule file:** `rules/DET-019_ps_scriptblock_lsass_dump.yml`
- **ATT&CK:** T1003.001 (LSASS Memory)
- **Log source:** powershell | **Condition:** `selection_id and selection_dump`
- **Severity:** high - Scripted LSASS dumping has no routine administrative use.
- **False positives:** Security tooling / red-team scripts in authorised tests
- **Test result:** 1 events in 1 samples. Samples: `Powershell_4104_MiniDumpWriteDump_Lsass.evtx`

  *Evidence (first match):* `_file=Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx; TimeCreated=2020-06-30 14:24:08.254604+00:00; Computer=MSEDGEWIN10`

## DET-020 - Auto-Elevating Binary Spawning Interpreter (UAC Bypass Child)

- **Rule file:** `rules/DET-020_autoelevate_binary_spawns_shell.yml`
- **ATT&CK:** T1548.002 (Bypass User Account Control)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** high - High-integrity interpreter under an auto-elevating parent is a near-certain UAC bypass.
- **False positives:** None expected; these binaries do not normally launch interpreters (eventvwr launches mmc.exe, which is excluded)
- **Test result:** 4 events in 4 samples. Samples: `Sysmon_13_1_UACBypass_SDCLTBypass.evtx`, `Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx`, `Sysmon_UACME_33.evtx`, `sysmon_1_13_UACBypass_AppPath_Control.evtx`

  *Evidence (first match):* `_file=Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx; TimeCreated=2019-05-09 02:08:00.446150+00:00; Computer=IEWIN7; Image=C:\Windows\System32\cmd.exe; CommandLine="C:\Windows\System32\cmd.exe" /c notepad.exe`

## DET-021 - COM Object Hijack: CLSID Server Key Pointing to User-Writable Path

- **Rule file:** `rules/DET-021_com_hijack_clsid_user_path.yml`
- **ATT&CK:** T1546.015 (Component Object Model Hijacking)
- **Log source:** sysmon | **Condition:** `selection`
- **Severity:** high - A CLSID server redirected to a user-writable DLL gives stealthy, logon-triggered persistence; per-user installers are the main benign source.
- **False positives:** Per-user installed COM components (e.g., some Office add-ins, Teams/OneDrive shell extensions) register under HKCU with AppData paths
- **Test result:** 2 events in 2 samples. Samples: `persist_firefox_comhijack_sysmon_11_13_7_1.evtx`, `persist_turla_outlook_backdoor_comhijack.evtx`

  *Evidence (first match):* `_file=Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.evtx; TimeCreated=2019-05-21 00:35:07.474159+00:00; Computer=IEWIN7; Image=C:\Users\IEUser\Downloads\com-hijack.exe; TargetObject=HKU\S-1-5-21-3583694148-1414552638-2922671848-1000_CLASSES\CLSID\{BCDE0395-E52F-467C-8E3D-`

## DET-022 - LOLBin Initiating Outbound Connection to a Public IP Address

- **Rule file:** `rules/DET-022_lolbin_external_connection.yml`
- **ATT&CK:** T1105 (Ingress Tool Transfer)
- **Log source:** sysmon | **Condition:** `selection and not filter_private`
- **Severity:** medium - These binaries rarely need internet access; connection to a public IP is suspicious but certificate/CRL lookups cause some noise.
- **False positives:** certutil used for legitimate CRL/certificate retrieval by some scripts; Software installers invoking rundll32/regsvr32 with network access
- **Test result:** 12 events in 5 samples. Samples: `PanacheSysmon_vs_AtomicRedTeam01.evtx`, `panache_sysmon_vs_EDRTestingScript.evtx`, `exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx`, `exec_sysmon_lobin_regsvr32_sct.evtx` ...

  *Evidence (first match):* `_file=AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx; TimeCreated=2019-07-19 14:53:46.589405+00:00; Computer=MSEDGEWIN10; Image=C:\Windows\System32\regsvr32.exe`

## Correlation rules

### COR-001 - UAC Bypass Chain: Registry Hijack Followed by Elevated Interpreter

- **Type:** temporal_ordered | **Rules:** uac_bypass_registry_hijack, autoelevate_binary_spawns_shell | **Group-by:** Computer | **Timespan:** 5m | **Level:** critical
- **Result:** matched in 3 host/sample group(s): `Sysmon_13_1_UACBypass_SDCLTBypass.evtx`, `Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx`, `Sysmon_UACME_33.evtx`
- **Description:** Correlates a UAC-bypass registry handler hijack with an auto-elevating binary spawning an interpreter on the same host within 5 minutes. Combining both stages gives near-certain confidence compared with either rule alone.

### COR-002 - Process Injection Burst: Repeated Remote Thread Creation from One Source

- **Type:** event_count | **Rules:** remote_thread_injection | **Group-by:** Computer, SourceImage | **Timespan:** 1m | **Level:** high
- **Result:** matched in 2 host/sample group(s): `de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx`, `Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx`
- **Description:** Detects five or more suspicious CreateRemoteThread events from the same source image within one minute, characteristic of reflective injection frameworks looping through targets or migrating payloads.

### COR-003 - Credential Dumping via Injection: LSASS Access Plus Remote Thread

- **Type:** temporal | **Rules:** lsass_suspicious_access, remote_thread_injection | **Group-by:** Computer | **Timespan:** 1m | **Level:** critical
- **Result:** matched in 1 host/sample group(s): `CA_sysmon_hashdump_cmd_meterpreter.evtx`
- **Description:** Correlates suspicious LSASS memory access with a remote thread into a commonly injected process on the same host within one minute, as seen when Meterpreter hashdump migrates and then reads LSASS.

### COR-004 - Download via BITSAdmin Followed by Scriptlet Execution

- **Type:** temporal_ordered | **Rules:** bitsadmin_abuse, regsvr32_scriptlet_exec | **Group-by:** Computer | **Timespan:** 10m | **Level:** high
- **Result:** matched in 2 host/sample group(s): `PanacheSysmon_vs_AtomicRedTeam01.evtx`, `panache_sysmon_vs_EDRTestingScript.evtx`
- **Description:** Correlates BITSAdmin transfer activity with regsvr32 scriptlet execution on the same host within 10 minutes, a typical ingress-tool-transfer then proxy-execution chain.

## Validation log (honest record)

Initial expectations were checked against the rules' actual results. Misses led to changes:

| Rule | Expectation | Finding | Action |
|---|---|---|---|
| DET-004 | Renamed regsvr32 sample should fire | Sample used `jabber.exe /u /s /i:http://...` with no scrobj | Added `/i:http` renamed-binary selection |
| DET-006 | `sysmon_1_persist_bitsjob_SetNotifyCmdLine` should fire | Sample is COM-based BITS, no bitsadmin | Removed wrong citation; coverage marked Partial |
| DET-007 | osk accessibility sample should fire | Sample has no IFEO key write (only osk.exe -> whoami) | Added reg.exe IFEO variant; the unvalidated key-create variant was dropped; coverage Partial |
| DET-008 | Hidden Run key sample should fire | Target path was `C:\Windows\Tasks\` | Added `\Windows\Tasks\` to path list |
| DET-012 | WMI 4688 sample should fire | Security 4688 has no parent info | Documented as gap; coverage Partial |
| DET-003 | `services.exe` is a benign LSASS accessor | The only services.exe events were inside the PPLdump attack sample | Reverted the filter (it hid attack evidence) |