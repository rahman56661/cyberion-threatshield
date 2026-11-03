# PB-001 - Credential Compromise (LSASS dumping, DCSync, pass-the-hash)

**Goal:** contain stolen credentials within the first hour. Written for a 1-2 person on-shift team.

## Trigger conditions
Any of: DET-003, DET-013 (critical), DET-017, DET-019, COR-003 (critical). Also: unexpected 4662 replication by a user account.

## First 15 minutes - triage (decide: real or lab/test)
1. Pull the alert's host, user, process path and timestamp. Is the source process signed and expected (EDR agent, backup)? If not -> treat as true positive.
2. Check same host +/- 10 minutes: Sysmon 1 (what started it), Sysmon 3 (outbound), 4624 type 9/10 (logons).
3. Is the host a **domain controller or admin workstation**? If yes, escalate to critical immediately.

## Containment (do not wait for full analysis)
- Isolate the host from the network (EDR isolate or switch-port); keep it powered on to preserve memory.
- Disable (do not delete) the account(s) used; for DCSync, disable the requesting account and its sessions.
- Block the offending hash/path on EDR; add the source IP to firewall deny.
- Do **not** reboot, wipe or log in interactively with admin credentials on the compromised host.

## Investigation
- Which credentials were present on the host (logged-on users, services, scheduled-task accounts)? All are compromised.
- DCSync: dump 4662 for the last 24 h; which accounts have replication rights (`Get-ADUser` ACL check)?
- Search all hosts for the same file name/hash (IOC list) and for 4624 type 9/3 logons from the host.
- Preserve: memory image, Sysmon/Security logs (export the .evtx), EDR timeline.

## Eradication and recovery
- Reset passwords for every exposed account; for domain-wide exposure rotate **krbtgt twice** (spaced by replication interval) and service-account secrets.
- Reimage the host (or rebuild) after evidence capture; re-enable account only after reset and MFA check.
- Remove malicious persistence found (Run keys, tasks, services) before bringing hosts back.
- Verify closure: no new 4662/LSASS alerts for 72 h; no logons from unknown hosts.

## Communications
| Who | When | What |
|---|---|---|
| SOC lead | Immediately | Alert, host role, containment status |
| IT/AD admins | Within 15 min | Account disables, krbtgt plan |
| Client contact / management | Within 1 h if DC or privileged accounts | Plain-language impact and next steps |
| Legal / privacy | If data access is suspected | Only after scoping |

## Exit criteria
Host isolated, all exposed credentials reset, scope documented, detection gap noted in the coverage matrix.
