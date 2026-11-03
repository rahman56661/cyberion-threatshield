# PB-003 - Command-and-Control and Tunnelling (LOLBin egress, RDP tunnel, beaconing)

## Trigger conditions
DET-018 (loopback RDP logon), DET-022 (LOLBin to public IP), COR-004 (BITS then scriptlet), DET-004/005 (script handlers) followed by outbound traffic; Hunt 02 beacon candidates.

## First 15 minutes - triage
1. Which process connected where? (Sysmon 3: `Image`, `DestinationIp`, `DestinationPort`.) Resolve IP/hostname and check reputation and age.
2. Is the destination a known software or CDN endpoint used by the process legitimately (e.g. certutil CRL fetch)? If unknown or rare -> suspicious.
3. DET-018: confirm a tunnelling tool (plink/ssh/chisel/ngrok) exists on the host: Sysmon 1 for those names and listening ports (Sysmon 3 Initiated=false).

## Containment
- Block the destination IP/domain at proxy/firewall and DNS sinkhole it.
- Isolate the host if payload execution is confirmed (a download alone may be contained by block only).
- Kill the tunnelling or LOLBin process tree; preserve memory first if possible.
- Disable the account that logged on via the tunnelled RDP session.

## Investigation
- Retrieve the downloaded payload (URL in the command line, BITS job, proxy logs) and detonate in sandbox; extract IOCs.
- Check frequency/interval of the connections (CV < 0.3 suggests beaconing) in proxy/Zeek logs over 24 h or more.
- Search for the same destination and payload hash across the estate.

## Eradication and recovery
- Remove persistence (Run keys, tasks, COM hijack keys, BITS jobs: `bitsadmin /list /allusers`).
- Rebuild hosts that executed second-stage code; rotate credentials used on them.
- Add IOCs to blocklists; add missing detections (see coverage gaps).

## Communications
SOC lead (immediately); network team (blocks) within 15 min; security/IR manager if execution is confirmed; client notification per contract SLA if data egress is possible.

## Exit criteria
No traffic to the C2/payload endpoint for 72 h, persistence removed, IOCs distributed, detection coverage updated.
