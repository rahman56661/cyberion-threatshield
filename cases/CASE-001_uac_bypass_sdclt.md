# CASE-001 - UAC Bypass via sdclt.exe (Privilege Escalation)

| Field | Value |
|---|---|
| Case ID | CASE-001 |
| Detection source | DET-009 (registry hijack), DET-020 (auto-elevate child), **COR-001** (chain) |
| Sample | `Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.evtx` |
| Host / user | `IEWIN7` / `IEWIN7\IEUser` |
| Severity | High (critical when chained) |
| **Closure** | **True positive** (adversary-emulation sample) |

## Summary
A user-level PowerShell session wrote a per-user shell handler for `exefile\shell\runas\command\IsolatedCommand`, then launched `sdclt.exe /kickoffelev`. The auto-elevating binary consumed the hijacked key and started `cmd.exe` at **High** integrity, i.e. a UAC bypass with no consent prompt.

## Timeline (UTC, 2019-05-09, reconstructed from raw Sysmon events)
| Time | EID | Evidence | ATT&CK |
|---|---|---|---|
| 02:07:51.116 | 13 | `powershell.exe` sets `HKU\S-1-5-21-...-1000_CLASSES\exefile\shell\runas\command\IsolatedCommand` = `C:\Windows\System32\cmd.exe /c notepad.exe` | T1548.002 |
| 02:07:51.131 | 1 | `sdclt.exe /kickoffelev`, parent `powershell.exe`, user IEWIN7\IEUser, integrity **Medium** | T1548.002 |
| 02:07:51.131 | 10 | `powershell.exe` opens `sdclt.exe` with `0x1fffff` | (control of child) |
| 02:07:56.149 | 10 | Second access to `sdclt.exe`, `0x1f1fff` | - |
| 02:08:00.446 | 1 | `cmd.exe /c notepad.exe`, parent `sdclt.exe`, integrity **High** | T1548.002 |

Elapsed from registry write to elevated child: **9.3 seconds**.

## Corroboration
Three distinct event types (registry set EID 13, process create EID 1, process access EID 10) agree. A second telemetry *source* (e.g. Security 4688/4672) is not present in the sample, which limits independent confirmation; the integrity-level change from Medium to High within one chain is nonetheless unambiguous.

## Root cause
Auto-elevating Microsoft binaries (`sdclt.exe`) honour per-user class registrations. Any process running as the user can write HKCU\Software\Classes, so a standard user can redirect an elevated launch to attacker-chosen commands. Contributing factor: UAC at default level without "always notify".

## Impact
Standard user to High-integrity execution. Payload in the sample is `notepad.exe` (test), so no data access occurred; in a real intrusion, High integrity enables credential dumping, service installation and security-tool tampering.

## Detection assessment
- Rules fired: DET-009 on the registry write, DET-020 on `cmd.exe` under `sdclt.exe`, COR-001 chained both in one group (host IEWIN7, 5-minute window) -> critical.
- Gap: initial execution of the PowerShell session (how the actor got in) is not in the sample.

## Response
Follow PB-001 (privilege/credential escalation branch): isolate host, review persistence and credential access after 02:08, remove the HKCU key, restrict UAC to "Always notify", alert on the registry paths.
