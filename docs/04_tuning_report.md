# 04 - Rule Quality and False-Positive Tuning (Module 4.8)

Method: every rule with a `filter_*` block was run **with and without** its filter (`python tools/sigma_runner.py --no-filters`) and the removed events were inspected. Limitation to keep in mind: the dataset is attack-focused, so benign baseline is thin; "false positive" below means an event that a defender could reasonably consider benign *and* that I could examine in context.

## Tuning pass 1 - DET-003 LSASS access: proposed `services.exe` filter REJECTED
- **Observed scenario:** `services.exe` opens `lsass.exe` with `0x1410` and `0x1fffff` (2 events).
- **Initial change:** exclude `services.exe` (a frequent benign accessor in public rule sets).
- **Evidence check:** both events sit in `ppl_bypass_ppldump_knowdll_hijack_sysmon_security.evtx`, a PPLdump attack in which code runs *inside* `services.exe` to dump LSASS. Filtering it would have hidden attacker activity.
- **Decision:** filter removed; the remaining filter (`wininit.exe`, `csrss.exe`, `MsMpEng.exe`, `lsm.exe`) is based on documented benign behaviour but is **not exercised by this dataset** (0 events removed), so it is untested here.
- **Trade-off:** more analyst triage of `services.exe` in production; accepted because the only observed evidence is malicious. Result: 26 events in 14 samples.

## Tuning pass 2 - DET-013 DCSync: machine-account filter
- **Observed scenario:** `DC1$` requests replication GUIDs with Control Access in `ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx` (3 events), normal domain-controller replication.
- **Change:** `filter_machine` (`SubjectUserName` ends with `$`): 6 events -> 3 events (the 3 remaining are `Administrator` in `CA_DCSync_4662`).
- **Trade-off:** an attacker using a compromised *machine* account (or a rogue DC) is hidden. Production mitigation: replace the `$` wildcard with an explicit allow-list of real DC computer accounts so unknown machine accounts still alert.

## Tuning pass 3 - DET-011 remote thread: alert-volume reduction through correlation
- **Observed scenario:** 101 events, 91 of them from two samples (82 from one PowerShell injection session, 9 from another). One injection run would create dozens of identical alerts.
- **Change:** keep DET-011 as-is for single events and add **COR-002** (event_count >= 5 from one source image within 1 minute). The two bursts become 2 aggregated alerts instead of 91 events.
- **Trade-off:** aggregate alert is up to one minute later, and slow single-thread injections still rely on DET-011 (high) rather than the correlation.

## Tuning pass 4 - DET-022 LOLBin egress: private-range exclusion hides lab C2
- **Observed scenario:** with no filter the rule produced 15 events; excluding private/loopback ranges removed 3, all connections from `rundll32.exe`, `mshta.exe` and `wscript.exe` to `10.0.2.18` on ports `8181` and `4443` - the attacker's listener in the lab.
- **Decision:** keep the exclusion (internal proxies and CRL servers would otherwise flood a production SOC) but record the blind spot.
- **Trade-off / follow-up:** internal pivot or staging hosts are missed; recommended companion rule: LOLBin to RFC1918 address on non-standard ports.

## Tuning pass 5 - DET-001 log cleared: benign-positive accepted, no suppression
- **Observed scenario:** 24 hits in 24 samples. These samples were prepared by clearing logs before recording (users `a-jbrown`, `IEUser`, `bob`, `Administrator`, ...), i.e. benign positives in lab context.
- **Decision:** no suppression. In production, log clearing should always be triaged; optional suppression only for named admin accounts *with* a change ticket. Level stays high.

## Recall tuning driven by validation misses
| Rule | Change | Evidence |
|---|---|---|
| DET-004 | Added `/i:http` renamed-binary selection | `jabber.exe /u /s /i:http://pastebin...` missed originally |
| DET-007 | Added `reg.exe` IFEO variant; dropped an untested key-create variant | Fired in `PanacheSysmon_vs_AtomicRedTeam01` |
| DET-008 | Added `\Windows\Tasks\` path | `c:\windows\tasks\taskhost.exe` Run key missed originally |

Net effect on precision cannot be quantified without a benign corpus; this is stated as a limitation in the methodology document.
