# Cyberion ThreatShield - Detection Engineering & Threat Hunting

Individual 4-week engagement (project code CDL-DET-V2), compressed delivery. Authors: **Habebur Rahman** and **Aleena K Mani**.
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

## Authors and license
- Habebur Rahman
- **Aleena K Mani**

Original work in this repository (rules, tools, documents) is released under the MIT License (see `LICENSE`). The telemetry dataset is **not** redistributed here; EVTX-ATTACK-SAMPLES is a separate project under its own GPL license. See `CONTRIBUTING.md` for how we collaborate.

> Educational project built on public lab telemetry. Detection rules are provided as-is and have not been tuned on benign production traffic; test before deploying.

## How to run and verify (about 15 minutes)

**Prerequisites:** Python 3.10+ and Git. Works on Windows, Linux and macOS.

### 1. Clone this repository
```bash
git clone https://github.com/rahman56661/cyberion-threatshield.git
cd cyberion-threatshield
```

### 2. Download the public dataset (not included in this repo)
```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Parse the 278 EVTX files (takes 5-10 minutes)
```bash
python tools/parse_evtx.py
```
It prints progress every 20 files. Please do not press Ctrl+C. Expected last line: `files=278 events=37364`.

### 5. Convert to a fast format
```bash
python -c "import pandas as pd; pd.read_json('parsed/events.jsonl', lines=True, dtype=False).to_pickle('parsed/events.pkl')"
```

### 6. Validate the Sigma rules
```bash
sigma check rules/
```
Expected: `Found 0 errors, 0 condition errors and 17 issues`. The 17 "specific log source" notes are deliberate (rules match the dataset's raw Sysmon/Security structure).

### 7. Run every rule against the real events
```bash
python tools/sigma_runner.py
```
Expected: 22 rule lines (`DET-001` to `DET-022`) and 4 correlation lines (`COR-001` to `COR-004`), each with `events=` or `groups=` greater than 0. Example: `DET-003 ... events=26 files=14`, `DET-011 ... events=101`. A warning about regex groups is harmless.

### 8. Optional: reproduce the hunts
```bash
python hunts/hunt_01_com_hijack.py
python hunts/hunt_02_beaconing.py
```

## Review without running anything
| What | Where |
|---|---|
| All rules (Sigma YAML) | `rules/` |
| Test results (real events matched) | `results/rule_test_results.json`, `results/evidence/` |
| ATT&CK coverage matrix | `coverage/attack_coverage_matrix.xlsx` |
| Rule catalog with false-positive notes | `docs/03_rule_library.md` |
| Executive summary | `docs/06_executive_summary.md` |
| Hunts, cases, playbooks | `hunts/`, `cases/`, `playbooks/` |
| Presentation | `presentation/ThreatShield_Final_Presentation.pptx` |

## Troubleshooting
- **Antivirus warning on download:** the repo has no executables. It contains text describing attack techniques (for detection research); evidence strings are defanged (`hxxp://`). Cloning with git avoids zip scanning.
- **`FileNotFoundError: parsed/events.pkl`:** steps 4 and 5 were not completed.
- **Python 3.14 or older versions:** developed and tested on Python 3.14 (Windows) and 3.12 (Linux).
