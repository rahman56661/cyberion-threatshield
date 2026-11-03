# CASE-002 - Credential Theft: Meterpreter-style LSASS Access and Injection

| Field | Value |
|---|---|
| Case ID | CASE-002 |
| Detection source | DET-003 (LSASS access), DET-011 (remote thread), **COR-003** |
| Sample | `Credential Access/CA_sysmon_hashdump_cmd_meterpreter.evtx` |
| Host | `IEWIN7` |
| Severity | Critical |
| **Closure** | **True positive** (adversary-emulation sample) |

## Summary
A binary named `voice_mail.msg.exe`, executed from a VirtualBox shared folder (`\\VBOXSVR\HTools\`), opened full-access handles to core Windows processes and created remote threads inside `lsass.exe`, consistent with Meterpreter's `hashdump` flow (migrate into a SYSTEM process, read credential stores).

## Evidence (9 Sysmon events, all stamped 2019-04-30 12:43:43.784 UTC)
All events share one timestamp in this sample, so ordering is by record, not by time; the set of actions is therefore reported as a set.

| EID | Source | Target | Detail | ATT&CK |
|---|---|---|---|---|
| 10 | `\\VBOXSVR\HTools\voice_mail.msg.exe` | `smss.exe`, `csrss.exe` (x2), `wininit.exe`, `winlogon.exe`, `services.exe` | `GrantedAccess 0x1f1fff` on each | T1055 (process discovery / migration prep) |
| 10 | same | `lsass.exe` | `0x1f1fff` | T1003.001 |
| 8 | same | `lsass.exe` | CreateRemoteThread (x2) | T1055 |

## Corroboration
Single source (Sysmon). The same actor touching smss/csrss/wininit/winlogon/services/lsass in one burst, followed by thread creation in lsass, is not explainable by normal software; the file name masquerades as a voicemail attachment while living on a network share (T1036 masquerading, delivery inferred).

## Root cause
Not determinable from the sample: the process-creation event (Sysmon 1) and parent chain for the payload are absent, so the initial execution vector is unknown. Likely user-run payload from a shared location.

## Impact
Assume **all credential material in LSASS and the local SAM** is compromised for IEWIN7 (logged-on user secrets, NTLM hashes). The logs prove access and injection, not exfiltration; scope must be assumed worst-case until network logs prove otherwise. No network (EID 3) events are in the sample.

## Detection assessment
- DET-003 fires on the `0x1f1fff` access to lsass; DET-011 fires on both remote threads; COR-003 chains them (1 group, 1 minute window) -> critical.
- Improvement candidate: Sysmon 1 `Image` starting with `\\` (execution from UNC path) is a cheap, high-value rule not yet written.

## Response
Follow PB-001: isolate IEWIN7, reset all credentials that touched the host (domain first), hunt other hosts for the same hash/filename, review lateral movement (PB-002).
