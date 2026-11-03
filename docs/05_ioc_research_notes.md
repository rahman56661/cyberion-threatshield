# 05 - IOC Research Notes (Module 4.5)

IOCs were extracted programmatically from the telemetry (`tools/extract_iocs.py` -> `results/iocs.json`). **Context caveat:** the samples are public red-team/lab recordings. Many indicators belong to *test infrastructure* (Atomic Red Team and EDR-Testing-Script GitHub repositories) rather than live criminal campaigns, and are labelled as such. Nothing here should be blocklisted in production without that context.

## Public IP addresses (outbound, Sysmon EID 3)

| IP | Conn. | Processes | Port | Context | Operational use |
|---|---|---|---|---|---|
| `104.20.208.21` | 1 | regsvr32.exe | 80 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |
| `105.73.6.105` | 2 | WMIC.exe, mshta.exe | 80 | rDNS `aka105.inwitelecom.net`; contacted by mshta (`exec_persist_rundll32_mshta_scheduledtask`) and WMIC (`exec_wmic_xsl_internet`) over port 80 | Watchlist for DET-022 / proxy review |
| `105.73.6.112` | 1 | mshta.exe | 80 | rDNS `aka112.inwitelecom.net`; mshta over port 80 | Watchlist |
| `108.179.232.58` | 1 | mshta.exe | 443 | rDNS `gator4243.hostgator.com`; mshta over 443 - shared hosting | Watchlist (hosting provider; block only with URL evidence) |
| `151.101.0.133` | 10 | WMIC.exe, certutil.exe, mshta.exe, powershell.exe, regsvr32.exe, rundll32.exe | 443 | Same processes fetch raw.githubusercontent.com URLs (inferred; hostname not logged). Shared CDN address. | Do **not** block; use as DET-022 hunting pivot only |
| `151.101.128.133` | 1 | regsvr32.exe | 443 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |
| `151.101.36.133` | 1 | powershell.exe | 443 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |
| `172.217.17.132` | 1 | powershell.exe | 80 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |
| `185.199.111.153` | 1 | mmc.exe | 443 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |
| `45.76.12.27` | 1 | WMIC.exe | 443 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |
| `93.184.220.29` | 1 | mshta.exe | 80 | Single connection from a LOLBin/PowerShell in an Atomic/test sample | Context only |

## URLs / domains (from command lines and script blocks)

| URL | Seen | Assessment | Operational use |
|---|---|---|---|
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/CradleTest.txt` | 8 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md` | 4 | Atomic Red Team public test payload (benign test infra) | Allow-list for lab; detect process pattern (DET-004/005), not the URL |
| `https://hotelesms.com/talsk.txt` | 3 | Unattributed domain used in a rundll32 -> mshta chain; no public attribution found in my search | Proxy/DNS watchlist; DET-005 + DET-022 detect the behaviour |
| `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1216/payloads/T1216.sc` | 2 | Atomic Red Team public test payload (benign test infra) | Allow-list for lab; detect process pattern (DET-004/005), not the URL |
| `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xs` | 2 | Atomic Red Team public test payload (benign test infra) | Allow-list for lab; detect process pattern (DET-004/005), not the URL |
| `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1117/RegSvr32.sct` | 2 | Atomic Red Team public test payload (benign test infra) | Allow-list for lab; detect process pattern (DET-004/005), not the URL |
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Mshta_calc.sct` | 2 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp_calc.sct` | 2 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Wmic_calc.xsl` | 2 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test` | 2 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/Cmstp.inf` | 2 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/op7ic/EDR-Testing-Script/master/Payloads/test.sct` | 2 | op7ic EDR-Testing-Script public test payload (benign test infra) | Same |
| `https://raw.githubusercontent.com/3gstudent/SCTPersistence/master/calc.sct` | 2 | Unclassified | Review |
| `http://pastebin.com/raw/H4A4iDTA` | 2 | Unclassified | Review |

## File hashes of offensive tooling (Sysmon EID 1, SHA256)

| SHA256 | File | Sample | Operational use |
|---|---|---|---|
| `0bf5ee2bb8beb0814f17f1d76249565937ea6263242193848fac6c6eb69f6049` | MalSeclogon.exe | tutto_malseclogon.evtx | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `2969e70b74a12e3b0441d0bda498322464a8614421b00321e889756d60ab4200` | AndrewSpecial.exe | sysmon_10_11_outlfank_dumpert_and_andrewspecial_ | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `38879fe4aa25044db241b093e6a1cf904ba9f4e999041c0cc039e2d5f7aba044` | Outflank-Dumpert.exe | sysmon_10_11_outlfank_dumpert_and_andrewspecial_ | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `68612b1c72b8aa498530aceb929ed44f1837b8bc52d1269e30a834931434fc41` | PPLdump.exe | ppl_bypass_ppldump_knowdll_hijack_sysmon_securit | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `70908f9bbc59198febe0d1ca0e34a9e79c68f5053a39a0ba0c6f6cec9ed1a875` | ppldump.exe | DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.evtx | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `890c1734ed1ef6b2422a9b21d6205cf91e014add8a7f41aa5a294fcf60631a7b` | jabber.exe | exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evt | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `e624863387832c7bbe47d17a346aab6a76638a2c9b5368fd7308a28775f1478a` | com-hijack.exe | persist_firefox_comhijack_sysmon_11_13_7_1.evtx | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |
| `f0d5c8e6df82a7b026f4f0412f8ede11a053185675d965215b1ffbbc52326516` | KeeFarce.exe | CA_keefarce_keepass_credump.evtx | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |

## OSINT context used

- Technique `rundll32 javascript:"\..\mshtml,RunHTMLApplication"` is publicly documented as a signed-binary proxy execution method: Elastic prebuilt rule *Script Execution via Microsoft HTML Application* (maps to T1218.011 and T1218.005) - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-3-script-execution-via-microsoft-html-application.html
- Quick Heal analysis of spam campaigns using the same rundll32/mshtml pattern, similar to Poweliks-style fileless malware - https://blogs.quickheal.com/?p=84916
- Trend Micro threat entry RANSOM_CRYPCUTE.C, which uses the same command pattern for persistence - https://trendmicro.com/vinfo/dk/threat-encyclopedia/malware/ransom_crypcute.c
- Red Canary research on MSHTA via mshta.exe and rundll32.exe - https://redcanary.com/blog/threat-research-questions
- Source datasets: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES; test payload repos named above.

**Not found:** I did not find public reporting tying `hotelesms.com/talsk.txt` or the `105.73.6.x` addresses to a named campaign, so they are recorded as unattributed rather than guessed.

## How each IOC type is operationalised

| IOC type | Feeds | Mechanism |
|---|---|---|
| Behaviour (command-line patterns) | DET-004, DET-005, DET-006, DET-022 | Sigma rules - preferred over static IOCs |
| Public IPs / domains | Proxy and DNS watchlist, DET-022 triage | Review-only; block when payload URL confirmed |
| File hashes | EDR custom blocklist and hunting | Retro-search 30 days of process-creation events |
| Tool names (Dumpert, PPLdump, KeeFarce) | DET-003, DET-011 | Behaviour rules fired on these samples; names are context only |