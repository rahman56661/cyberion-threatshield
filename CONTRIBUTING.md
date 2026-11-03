# Collaboration workflow

1. Never commit directly to `main`. Create a branch: `git checkout -b feature/<short-name>`.
2. Rules live in `tools/build_rules.py` / `tools/build_corr.py` (single source of truth). Edit there, then run:
   `python tools/build_rules.py && python tools/build_corr.py && sigma check rules/ && python tools/sigma_runner.py`
3. A rule is only accepted if it fires on real data in `tools/sigma_runner.py` and has a false-positive note.
4. Regenerate docs: `python tools/build_coverage.py && python tools/build_docs.py && python tools/build_reports.py`.
5. Open a Pull Request; the other person reviews and merges.
6. Do not commit the dataset (`data/`), `parsed/` or other large files (see `.gitignore`).
