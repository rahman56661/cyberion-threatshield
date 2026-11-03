# HUNT-02 - C2 Beaconing to External IP

| Field | Value |
|---|---|
| Hunt ID | HUNT-02 |
| ATT&CK | T1071 / T1095 (C2) - hypothesis; pivot finding T1105 Ingress Tool Transfer |
| Data | Sysmon EID 3 (network connection) |
| Script | `hunts/hunt_02_beaconing.py` (outputs `results/hunts/hunt02_beacon_candidates.csv`) |
| Conclusion | **INCONCLUSIVE** for beaconing (no evidence, but dataset cannot test it). **Confirmed** pivot finding: LOLBins downloading from the internet. |

## Hypothesis
A compromised host beacons to an external IP at a regular interval (low inter-arrival variance), e.g. coefficient of variation (CV) < 0.3 over at least 8 connections.

## Method
1. Take Sysmon EID 3 with `Initiated=true` (outbound): 164 EID 3 events across 42 samples, 77 initiated.
2. Keep public destinations using Python's `ipaddress.is_global` (this also correctly handles IPv6 loopback written in expanded form; a first regex-based attempt wrongly treated `0:0:0:0:0:0:0:1` as external, an example of why validating the filter matters). Result: **22 connections in 9 samples**.
3. Group by (sample, host, process, destination IP, port) and compute inter-arrival CV.

## Findings
- **Beacon-like groups (n>=8, CV<0.3): 0.** The largest group has only **2** connections, so periodicity cannot be measured. The captures are seconds to minutes long.
- The only periodic group in the first, looser pass (3 connections, ~60 s, CV 0.01) was the ADWS service talking to LDAP over IPv6 loopback in `DE_remote_eventlog_svc_crash_byt3bl33d3r` - automated service polling and internal, i.e. a benign positive.
- **Pivot (confirmed):** `certutil.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe` and `powershell.exe` connect to the same public address `151.101.0.133:443` (10 connections). The destination hostname is not logged, but the command lines of the same processes fetch `raw.githubusercontent.com` payloads, so this is consistent with GitHub-hosted payload download (inference, not logged fact). That is ingress tool transfer by living-off-the-land binaries.

## Conclusion
Beaconing hypothesis: **inconclusive**. We cannot claim it is ruled out in production, because the telemetry is too short to observe a beacon interval; we can only say no beacon-like pattern exists in this dataset. A proper test needs >= 24 h of network logs (Zeek conn.log or Sysmon 3 over a day).

## Hand-off
- New detection **DET-022** (LOLBin connecting to a public IP): 12 events, 5 samples.
- Tuning lesson recorded in `docs/04_tuning_report.md`: excluding private ranges also hides lab C2 callbacks to `10.0.2.18:4443/8181`.
