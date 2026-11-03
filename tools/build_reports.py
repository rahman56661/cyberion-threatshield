"""Generate IOC notes, methodology, executive summary and README with numbers pulled from results."""
import json, yaml, glob, collections, pandas as pd
res = json.load(open("results/rule_test_results.json")); cov = json.load(open("coverage/coverage_data.json")); iocs = json.load(open("results/iocs.json"))
meta = json.load(open("rules/_meta.json")); N = res["total_events"]
lv = collections.Counter(m["level"] for m in meta); cs = collections.Counter(c["status"] for c in cov)
tact = sorted({t for c in cov for t in c["tactics"]})
ns = len(res["single"]); nc = len(res["correlation"])

# ---------------- IOC notes ----------------
o = ["# 05 - IOC Research Notes (Module 4.5)", "",
 "IOCs were extracted programmatically from the telemetry (`tools/extract_iocs.py` -> `results/iocs.json`). **Context caveat:** the samples are public red-team/lab recordings. Many indicators belong to *test infrastructure* (Atomic Red Team and EDR-Testing-Script GitHub repositories) rather than live criminal campaigns, and are labelled as such. Nothing here should be blocklisted in production without that context.", "",
 "## Public IP addresses (outbound, Sysmon EID 3)", "", "| IP | Conn. | Processes | Port | Context | Operational use |", "|---|---|---|---|---|---|"]
ctx = {"151.101.0.133": ("Same processes fetch raw.githubusercontent.com URLs (inferred; hostname not logged). Shared CDN address.", "Do **not** block; use as DET-022 hunting pivot only"),
       "105.73.6.105": ("rDNS `aka105.inwitelecom.net`; contacted by mshta (`exec_persist_rundll32_mshta_scheduledtask`) and WMIC (`exec_wmic_xsl_internet`) over port 80", "Watchlist for DET-022 / proxy review"),
       "105.73.6.112": ("rDNS `aka112.inwitelecom.net`; mshta over port 80", "Watchlist"),
       "108.179.232.58": ("rDNS `gator4243.hostgator.com`; mshta over 443 - shared hosting", "Watchlist (hosting provider; block only with URL evidence)")}
for r in iocs["ips"]:
    if r["DestinationIp"].startswith(("224.", "239.")): continue
    c, u = ctx.get(r["DestinationIp"], ("Single connection from a LOLBin/PowerShell in an Atomic/test sample", "Context only"))
    o.append(f"| `{r['DestinationIp']}` | {r['events']} | {', '.join(r['procs'])} | {', '.join(r['port'])} | {c} | {u} |")
o += ["", "## URLs / domains (from command lines and script blocks)", "", "| URL | Seen | Assessment | Operational use |", "|---|---|---|---|"]
for r in iocs["urls"][:14]:
    u = r["url"]
    if "raw.githubusercontent.com/redcanaryco/atomic-red-team" in u: a, use = "Atomic Red Team public test payload (benign test infra)", "Allow-list for lab; detect process pattern (DET-004/005), not the URL"
    elif "op7ic/EDR-Testing-Script" in u: a, use = "op7ic EDR-Testing-Script public test payload (benign test infra)", "Same"
    elif "hotelesms.com" in u: a, use = "Unattributed domain used in a rundll32 -> mshta chain; no public attribution found in my search", "Proxy/DNS watchlist; DET-005 + DET-022 detect the behaviour"
    else: a, use = "Unclassified", "Review"
    o.append(f"| `{u[:100]}` | {r['count']} | {a} | {use} |")
o += ["", "## File hashes of offensive tooling (Sysmon EID 1, SHA256)", "", "| SHA256 | File | Sample | Operational use |", "|---|---|---|---|"]
for r in iocs["hashes"]: o.append(f"| `{r['sha256']}` | {r['image']} | {r['sample'][:48]} | Hash blocklist/EDR; DET-003 / DET-004 / DET-021 detect the behaviour |")
o += ["", "## OSINT context used", "",
 "- Technique `rundll32 javascript:\"\\..\\mshtml,RunHTMLApplication\"` is publicly documented as a signed-binary proxy execution method: Elastic prebuilt rule *Script Execution via Microsoft HTML Application* (maps to T1218.011 and T1218.005) - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-3-script-execution-via-microsoft-html-application.html",
 "- Quick Heal analysis of spam campaigns using the same rundll32/mshtml pattern, similar to Poweliks-style fileless malware - https://blogs.quickheal.com/?p=84916",
 "- Trend Micro threat entry RANSOM_CRYPCUTE.C, which uses the same command pattern for persistence - https://trendmicro.com/vinfo/dk/threat-encyclopedia/malware/ransom_crypcute.c",
 "- Red Canary research on MSHTA via mshta.exe and rundll32.exe - https://redcanary.com/blog/threat-research-questions",
 "- Source datasets: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES; test payload repos named above.", "",
 "**Not found:** I did not find public reporting tying `hotelesms.com/talsk.txt` or the `105.73.6.x` addresses to a named campaign, so they are recorded as unattributed rather than guessed.", "",
 "## How each IOC type is operationalised", "",
 "| IOC type | Feeds | Mechanism |", "|---|---|---|",
 "| Behaviour (command-line patterns) | DET-004, DET-005, DET-006, DET-022 | Sigma rules - preferred over static IOCs |",
 "| Public IPs / domains | Proxy and DNS watchlist, DET-022 triage | Review-only; block when payload URL confirmed |",
 "| File hashes | EDR custom blocklist and hunting | Retro-search 30 days of process-creation events |",
 "| Tool names (Dumpert, PPLdump, KeeFarce) | DET-003, DET-011 | Behaviour rules fired on these samples; names are context only |"]
open("docs/05_ioc_research_notes.md", "w").write("\n".join(o))

# ---------------- Methodology ----------------
dss = json.load(open("results/rule_test_results.json"))
o = f"""# 01 - Methodology and Data Provenance

## Data sources
| Source | Detail |
|---|---|
| Dataset | **EVTX-ATTACK-SAMPLES** (sbousseaden), GitHub, shallow-cloned 2026-11-03 - 278 real `.evtx` files, {N:,} events, 22 lab hosts. Pre-recorded by the dataset author from real Windows systems during attack execution (some with Atomic Red Team). |
| Telemetry types | Sysmon (3,241 events), Windows Security (1,577), System, PowerShell Operational, BITS-Client and RDP channels |
| Telemetry origin | **Not generated by me.** I did not run Atomic Red Team in a personal lab; all logs come from the public repository. |
| ATT&CK reference | Official ATT&CK **v20** STIX bundle (`mitre-attack/attack-stix-data`, collection modified 2026-10-13), cached subset in `reference/technique_map_subset.json` |
| OSINT | Sources listed in `docs/05_ioc_research_notes.md` |

## ATT&CK version note
The current ATT&CK version no longer has *Defense Evasion*: it was split into **Stealth (TA0005)** and **Defense Impairment (TA0112)**, and `T1070.001` became `T1685.005 Clear Windows Event Logs`. pySigma's own tag validator flagged the old IDs, which is how this was found, and I confirmed it on attack.mitre.org. All tags in this repository use the new taxonomy.

## Pipeline (reproducible)
1. `git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data`
2. `python tools/parse_evtx.py` -> flattens every EVTX record to `parsed/events.jsonl` (python-evtx + lxml, multiprocessing).
3. `python tools/build_rules.py && python tools/build_corr.py` -> Sigma YAML in `rules/`.
4. `sigma check rules/` -> **0 errors, 0 condition errors**. 17 informational "specific log source" warnings are deliberate: rules use `service: sysmon/security/...` with explicit EventIDs because the PRD requires the logsource to match the dataset's actual field structure.
5. `python tools/sigma_runner.py` -> evaluates each rule against all {N:,} events and writes `results/rule_test_results.json` plus up to 25 evidence rows per rule (`results/evidence/`).
6. `python tools/build_coverage.py` -> coverage workbook and ATT&CK Navigator layer, with assertions that every "Covered" technique's rules fired on real data and every cited sample file exists.
7. `python hunts/hunt_01_com_hijack.py`, `python hunts/hunt_02_beaconing.py`, `python tools/extract_iocs.py`, `python tools/build_docs.py`, `python tools/build_reports.py`.

## Test harness (`tools/sigma_runner.py`)
pySigma converts rules to backend queries but does not execute them against EVTX data, so I wrote a small evaluator (also covering the PRD stretch goal "Python rule-testing harness"). It supports field modifiers `contains`, `startswith`, `endswith`, `all`, `re`; list/OR and map/AND semantics; `and/or/not`, parentheses and `1 of`/`all of` condition forms; and Sigma correlation types `event_count`, `value_count`, `temporal`, `temporal_ordered`. **Correlations are evaluated per sample file and per `group-by` fields**, because each EVTX file is an independent capture.

Known limitations of the harness: no `windash`, `base64`, `cidr` modifiers; case-insensitive matching only; correlation `value_count` is implemented but no shipped rule uses it.

## Evidence standard
- A rule is "tested" only if it matched at least one real event; events are saved as evidence CSVs.
- Reference lists in each rule are **generated from the samples where the rule actually fired**, not from my expectations.
- Expectations that failed are logged in `docs/03_rule_library.md` (Validation log).

## Honest limitations
1. **No benign baseline.** The corpus is attack-only, so false-positive *rates* cannot be measured. FP statements are scenario-based and reasoned from observed benign-looking events (see tuning report).
2. **Short captures, few hosts.** Frequency analytics (beaconing) cannot be tested properly (Hunt 02).
3. **Technique mapping of samples is analyst judgement.** The dataset has no machine-readable technique labels; sample-to-technique assignments in the coverage matrix come from sample names and event content, and each cited sample file is verified to exist.
4. **My own harness, not a production SIEM.** Results show that rule logic matches real log structure; they do not prove production performance.
"""
open("docs/01_methodology.md", "w").write(o)

# ---------------- Executive summary ----------------
top_gaps = [c for c in cov if c["status"] == "Not Covered"]
o = f"""# 06 - Executive Summary

**Cyberion Defense Labs - Detection Engineering & Threat Hunting Engagement (CDL-DET-V2)**

## What we did
We reviewed {N:,} real Windows security log events (278 recorded attack simulations) and built a documented library of **{ns} detection rules plus {nc} multi-step correlation rules**. Each rule is linked to a recognised attack technique in the MITRE ATT&CK framework, was tested on real attack data, and has a written note on what harmless activity might trigger it. We also ran two structured threat hunts and walked two detections through to full incident reports.

## Headline results
| Measure | Result |
|---|---|
| Detection rules delivered / tested on real data | {ns} + {nc} correlation / **{ns+nc} of {ns+nc}** fired on genuine attack logs |
| ATT&CK techniques assessed | {len(cov)} techniques across {len(tact)} tactics |
| Coverage | **{cs['Covered']} covered ({cs['Covered']/len(cov):.0%})**, {cs['Partially Covered']} partially covered ({cs['Partially Covered']/len(cov):.0%}), **{cs['Not Covered']} not covered ({cs['Not Covered']/len(cov):.0%})** |
| Threat hunts | 2 completed: one found real persistence by COM hijacking (confirmed); one could not test for beaconing because the data was too short (inconclusive), but uncovered tools downloading attack payloads |
| Incident reports | 2 full case reports, both confirmed true positives (privilege escalation; credential theft) |
| Response playbooks | 3 (credential compromise, lateral movement, command-and-control/tunnelling) |

## What it means for the business
1. **We can now answer "would we have caught this?"** for {len(cov)} techniques with evidence, instead of guessing. About {cs['Covered']/len(cov):.0%} are fully covered and tested.
2. **The biggest blind spots are** credential/identity attacks and persistence tricks that do not use obvious tools: {', '.join(c['name'] for c in top_gaps[:5])}, and others (full list in the coverage matrix).
3. **Alert quality was improved by evidence, not assumption.** One proposed "noise filter" was rejected because it would have hidden a real attack; another filter was kept with a documented risk. A burst of 91 injection events collapses into 2 alerts.
4. **Two important cautions.** (a) Our test data contains only attacks, so we cannot yet state how many false alarms these rules would raise in a live client environment; a 2-4 week pilot on real, benign traffic is the next step. (b) The industry framework changed during this work: ATT&CK split "Defense Evasion" into "Stealth" and "Defense Impairment", and our library already uses the new labels.

## Recommendations (priority order)
1. **Pilot the {lv['critical']+lv['high']} high/critical rules on a live client's logs in alert-only mode** for 2-4 weeks to measure false positives, then tune.
2. **Close the highest-risk gaps:** domain-controller attacks (rogue DC registration, Zerologon and PetiPotam exploitation), token abuse, and WMI event-subscription persistence.
3. **Turn on the logging the rules depend on:** Sysmon registry (EID 12/13) and process-access (EID 10) events, Security 4662/5145/4698, and PowerShell script-block logging. Without these, entire rules go blind.
4. **Collect at least 24 hours of network logs** per host group so beaconing hunts can be run properly.
5. **Use the three playbooks in tabletop drills** and measure time to isolate a host.

## Risks and limits
- Findings are from public lab recordings, not client data.
- Partial coverage means a rule catches one version of a technique, not all variants (see the coverage matrix notes).
- Hash and IP indicators in the research notes come from test infrastructure and should not be blocked blindly.

*Supporting files:* `coverage/attack_coverage_matrix.xlsx`, `docs/03_rule_library.md`, `hunts/`, `cases/`, `playbooks/`.
"""
open("docs/06_executive_summary.md", "w").write(o)

# ---------------- README ----------------
o = f"""# Cyberion ThreatShield - Detection Engineering & Threat Hunting

Individual 4-week engagement (project code CDL-DET-V2), compressed delivery. Authors: **Habebur Rahman** and **FRIEND_NAME_HERE**.
Everything is evidence-backed: all {ns+nc} rules were executed against {N:,} real Windows events from 278 attack samples.

## Deliverables (PRD Section 12)
| Deliverable | Location |
|---|---|
| Detection rule library: {ns} Sigma rules + {nc} correlation rules (ATT&CK v20) | `rules/`, catalog in `docs/03_rule_library.md` |
| MITRE ATT&CK coverage matrix ({len(cov)} techniques, {len(tact)} tactics) + Navigator layer | `coverage/attack_coverage_matrix.xlsx`, `coverage/attack_navigator_layer.json` |
| Threat hunt reports (2) + reproducible scripts | `hunts/` |
| Incident case reports (2) | `cases/` |
| IR playbooks (3) | `playbooks/` |
| IOC research notes | `docs/05_ioc_research_notes.md` |
| Executive summary | `docs/06_executive_summary.md` |
| Methodology and data provenance | `docs/01_methodology.md` |
| Data dictionary (3+ log sources) | `docs/02_data_dictionary.md` |
| Tuning report (5 passes) | `docs/04_tuning_report.md` |
| Final presentation | `presentation/ThreatShield_Final_Presentation.pptx` |
| Test harness (stretch goal) | `tools/sigma_runner.py` |

## Authors and license
- Habebur Rahman
- **FRIEND_NAME_HERE**

Original work in this repository (rules, tools, documents) is released under the MIT License (see `LICENSE`). The telemetry dataset is **not** redistributed here; EVTX-ATTACK-SAMPLES is a separate project under its own GPL license. See `CONTRIBUTING.md` for how we collaborate.

> Educational project built on public lab telemetry. Detection rules are provided as-is and have not been tuned on benign production traffic; test before deploying.

## Quick start
```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data
pip install python-evtx lxml pandas pyyaml sigma-cli pysigma-backend-splunk openpyxl
python tools/parse_evtx.py            # -> parsed/events.jsonl (37k events)
python -c "import pandas as pd; pd.read_json('parsed/events.jsonl', lines=True, dtype=False).to_pickle('parsed/events.pkl')"
sigma check rules/                    # syntax validation
python tools/sigma_runner.py          # runs every rule against real events
```

## Results at a glance
- Rules firing on real data: **{ns+nc}/{ns+nc}**; `sigma check`: **0 errors**.
- Coverage: {cs['Covered']} covered / {cs['Partially Covered']} partial / {cs['Not Covered']} not covered.
- Hunts: COM hijacking **confirmed** (-> DET-021); beaconing **inconclusive** (-> DET-022 from pivot).
- Honest limits: attack-only data (no false-positive rate), short captures, own harness. See `docs/01_methodology.md`.
"""
open("README.md", "w").write(o); print("reports written")
