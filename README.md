# Cyberion ThreatShield - Detection Engineering & Threat Hunting

Individual 4-week engagement (project code CDL-DET-V2), compressed delivery. Analyst: **Madhan**.
Everything is evidence-backed: all 26 rules were executed against 37,364 real Windows events from 278 attack samples.

## Deliverables (PRD Section 12)
| Deliverable | Location |
|---|---|
| Detection rule library: 22 Sigma rules + 4 correlation rules (ATT&CK v20) | `rules/`, catalog in `docs/03_rule_library.md` |
| MITRE ATT&CK coverage matrix (32 techniques, 9 tactics) + Navigator layer | `coverage/attack_coverage_matrix.xlsx`, `coverage/attack_navigator_layer.json` |
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
- Rules firing on real data: **26/26**; `sigma check`: **0 errors**.
- Coverage: 12 covered / 10 partial / 10 not covered.
- Hunts: COM hijacking **confirmed** (-> DET-021); beaconing **inconclusive** (-> DET-022 from pivot).
- Honest limits: attack-only data (no false-positive rate), short captures, own harness. See `docs/01_methodology.md`.
