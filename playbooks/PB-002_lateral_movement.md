# PB-002 - Lateral Movement via Remote Services (SMB/svcctl, WMI, scheduled tasks, remote services)

## Trigger conditions
DET-012, DET-014, DET-015, DET-016, DET-017, DET-018, COR-001/002 when seen on more than one host. Typical signature: 5145 `svcctl`, then 7045 service with an interpreter path, or 4698 with random task name.

## First 15 minutes - triage
1. Identify **source and destination**: IpAddress in 5145/4624, Computer field of the destination alert.
2. Was the source host already alerted (credential theft, PB-001)? If yes, treat as an active intrusion.
3. Admin tooling check: is there an approved change or admin using PsExec/sc.exe right now? Confirm with the on-call admin by phone, not email.

## Containment
- Block SMB (445) and WMI/RPC between the source and destination at the host firewall/VLAN.
- Isolate the **destination** if it executed attacker code; isolate the **source** if it is unmanaged or compromised.
- Disable the account used for the remote logon.
- Stop and disable the created service / delete the scheduled task **after** copying its definition (ImagePath, task XML).

## Investigation
- Timeline on destination: 4624 type 3, 5145 (IPC$/ADMIN$/C$ file names), 7045/4698, Sysmon 1 children of `services.exe`, `WmiPrvSE.exe` or `taskeng/svchost`.
- Pivot: other destinations contacted by the same source and account in the last 24 h.
- Capture the dropped binary (hash, path) and look for it elsewhere.

## Eradication and recovery
- Remove service/task/binaries; rebuild hosts that executed attacker code.
- Reset the used account and any account cached on the touched hosts.
- Tighten: restrict local admin reuse (LAPS), limit SMB admin shares via firewall, require tiered admin accounts.

## Communications
SOC lead and IT ops immediately (network blocks); asset owners of touched servers within 1 h; management summary if >1 host or any server tier-0/1.

## Exit criteria
No further 5145 svcctl / 7045 / 4698 from the source for 72 h; all touched hosts clean or rebuilt; root cause of the first foothold identified or escalated to IR.
