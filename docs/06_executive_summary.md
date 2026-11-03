# 06 - Executive Summary

**Cyberion Defense Labs - Detection Engineering & Threat Hunting Engagement (CDL-DET-V2)**

## What we did
We reviewed 37,364 real Windows security log events (278 recorded attack simulations) and built a documented library of **22 detection rules plus 4 multi-step correlation rules**. Each rule is linked to a recognised attack technique in the MITRE ATT&CK framework, was tested on real attack data, and has a written note on what harmless activity might trigger it. We also ran two structured threat hunts and walked two detections through to full incident reports.

## Headline results
| Measure | Result |
|---|---|
| Detection rules delivered / tested on real data | 22 + 4 correlation / **26 of 26** fired on genuine attack logs |
| ATT&CK techniques assessed | 32 techniques across 9 tactics |
| Coverage | **12 covered (38%)**, 10 partially covered (31%), **10 not covered (31%)** |
| Threat hunts | 2 completed: one found real persistence by COM hijacking (confirmed); one could not test for beaconing because the data was too short (inconclusive), but uncovered tools downloading attack payloads |
| Incident reports | 2 full case reports, both confirmed true positives (privilege escalation; credential theft) |
| Response playbooks | 3 (credential compromise, lateral movement, command-and-control/tunnelling) |

## What it means for the business
1. **We can now answer "would we have caught this?"** for 32 techniques with evidence, instead of guessing. About 38% are fully covered and tested.
2. **The biggest blind spots are** credential/identity attacks and persistence tricks that do not use obvious tools: Mshta, Hidden Users, Rogue Domain Controller, Access Token Manipulation, Forced Authentication, and others (full list in the coverage matrix).
3. **Alert quality was improved by evidence, not assumption.** One proposed "noise filter" was rejected because it would have hidden a real attack; another filter was kept with a documented risk. A burst of 91 injection events collapses into 2 alerts.
4. **Two important cautions.** (a) Our test data contains only attacks, so we cannot yet state how many false alarms these rules would raise in a live client environment; a 2-4 week pilot on real, benign traffic is the next step. (b) The industry framework changed during this work: ATT&CK split "Defense Evasion" into "Stealth" and "Defense Impairment", and our library already uses the new labels.

## Recommendations (priority order)
1. **Pilot the 15 high/critical rules on a live client's logs in alert-only mode** for 2-4 weeks to measure false positives, then tune.
2. **Close the highest-risk gaps:** domain-controller attacks (rogue DC registration, Zerologon and PetiPotam exploitation), token abuse, and WMI event-subscription persistence.
3. **Turn on the logging the rules depend on:** Sysmon registry (EID 12/13) and process-access (EID 10) events, Security 4662/5145/4698, and PowerShell script-block logging. Without these, entire rules go blind.
4. **Collect at least 24 hours of network logs** per host group so beaconing hunts can be run properly.
5. **Use the three playbooks in tabletop drills** and measure time to isolate a host.

## Risks and limits
- Findings are from public lab recordings, not client data.
- Partial coverage means a rule catches one version of a technique, not all variants (see the coverage matrix notes).
- Hash and IP indicators in the research notes come from test infrastructure and should not be blocked blindly.

*Supporting files:* `coverage/attack_coverage_matrix.xlsx`, `docs/03_rule_library.md`, `hunts/`, `cases/`, `playbooks/`.
