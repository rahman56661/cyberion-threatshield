# 02 - Data Dictionary (Module 4.1)

Three telemetry source families (four channels) were selected from EVTX-ATTACK-SAMPLES. Counts are from the parsed dataset (`parsed/events.jsonl`, produced by `tools/parse_evtx.py`). *Fill* = share of that event type's records in which the field is populated.

**Dataset size:** 37,364 events from 278 EVTX files, 22 distinct hosts.

## Sysmon (3,241 events)

### Event ID 1 - Process Create (1,491 events, 146 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `Image` | 100% | Executable path; basis for LOLBin/renamed-binary logic |
| `CommandLine` | 100% | Full arguments; primary field for LOLBin abuse detection |
| `ParentImage` | 100% | Parent process; reveals unusual spawning (e.g. WmiPrvSE -> cmd) |
| `ParentCommandLine` | 100% | Parent args; helps attribute script-driven chains |
| `User` | 100% | Account context; separates SYSTEM vs user execution |
| `IntegrityLevel` | 100% | Medium vs High shows privilege change (UAC bypass evidence) |
| `Hashes` | 100% | File hashes for IOC matching |
| `OriginalFileName` | 19% | PE-embedded name; exposes renamed binaries (not present in every sample) |

### Event ID 3 - Network Connection (164 events, 42 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `Image` | 100% | Process making the connection |
| `DestinationIp` | 100% | Remote IP; public vs private drives egress rules |
| `DestinationPort` | 100% | Service/protocol hint |
| `Initiated` | 100% | true = outbound from this host |
| `DestinationHostname` | 75% | Reverse-DNS name when resolvable |

### Event ID 8 - CreateRemoteThread (104 events, 10 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `SourceImage` | 100% | Injecting process |
| `TargetImage` | 100% | Victim process |
| `StartFunction` | 2% | Thread start; reflective loaders often show unknown |

### Event ID 10 - Process Access (157 events, 49 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `SourceImage` | 96% | Accessing process |
| `TargetImage` | 100% | Accessed process (lsass.exe = credential theft) |
| `GrantedAccess` | 100% | Rights mask; 0x1010/0x1410/0x1fffff = read/dump rights |
| `CallTrace` | 100% | Stack; shows unbacked memory callers |

### Event ID 12 - Registry key create/delete (95 events, 29 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `TargetObject` | 100% | Registry path |
| `EventType` | 100% | CreateKey/DeleteKey |

### Event ID 13 - Registry value set (223 events, 60 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `TargetObject` | 100% | Registry path (persistence/UAC/IFEO keys) |
| `Details` | 100% | Value written (payload path or DWORD) |
| `Image` | 100% | Process that wrote the value |

## Security (1,577 events)

### Event ID 1102 - Audit log cleared (24 events, 24 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `SubjectUserName` | 100% | Who cleared the log |

### Event ID 4624 - Logon success (87 events, 22 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `LogonType` | 100% | 2/3/9/10 distinguish interactive, network, NewCredentials, RDP |
| `LogonProcessName` | 100% | seclogo/NtLmSsp/User32 reveal tool path |
| `IpAddress` | 100% | Source address; loopback = tunnel |
| `TargetUserName` | 100% | Account logged on |
| `AuthenticationPackageName` | 100% | NTLM/Negotiate/Kerberos |

### Event ID 4662 - Directory object operation (33 events, 5 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `Properties` | 100% | Object/property GUIDs (replication GUIDs = DCSync) |
| `AccessMask` | 100% | 0x100 = Control Access |
| `SubjectUserName` | 100% | Machine ($) vs user account |

### Event ID 4698 - Scheduled task created (3 events, 3 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `TaskName` | 100% | Task path; random names suspicious |
| `SubjectUserName` | 100% | Creator |

### Event ID 5145 - Network share object checked (958 events, 15 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `ShareName` | 100% | IPC$, ADMIN$, C$ |
| `RelativeTargetName` | 100% | Pipe/file (svcctl, psexec artifacts) |
| `IpAddress` | 100% | Source host |

## System (17 events)

### Event ID 104 - Log cleared (2 events, 2 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `Provider` | 100% | Microsoft-Windows-Eventlog |

### Event ID 7045 - Service installed (4 events, 2 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `ServiceName` | 100% | Service name |
| `ImagePath` | 100% | Binary path; interpreters here are suspicious |

## PowerShell (11 events)

### Event ID 4104 - Script block logging (4 events, 3 samples)

| Field | Fill | Detection meaning |
|---|---|---|
| `ScriptBlockText` | 100% | Decoded script content; keyword hunting target |
| `ScriptBlockId` | 100% | Join key across multi-part blocks |

## Data-quality notes

- Sysmon `OriginalFileName` is absent in older samples, so renamed-binary detection relies on command-line content (see DET-004).
- Security 4688 samples (e.g. `LM_WMI_4624_4688_TargetHost`) lack parent-process and command-line fields, which limits process-lineage rules.
- Most samples are short captures (seconds to minutes) from a handful of lab hosts, so frequency-based analysis (beaconing) is weak (see Hunt 02).
- Event timestamps are UTC; `Computer` names are lab hosts (IEWIN7, MSEDGEWIN10, PC01.example.corp, ...), not production systems.