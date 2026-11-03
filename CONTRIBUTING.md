# Collaboration workflow

1. Always update first: `git checkout main && git pull`.
2. Never commit directly to `main`. Create a branch: `git checkout -b feature/<short-name>`.
3. Rules live in `tools/build_rules.py` / `tools/build_corr.py` (single source of truth). Edit there, not in the generated `rules/*.yml`, then run:
   `python tools/build_rules.py && python tools/build_corr.py && sigma check rules/ && python tools/sigma_runner.py`
   (Needs the dataset and `parsed/events.pkl`; see README "How to run".)
4. A rule is only accepted if it fires on real data in `tools/sigma_runner.py` and has a false-positive note.
5. Regenerate the matrix and rule catalog: `python tools/build_coverage.py && python tools/build_docs.py`.
   Do NOT run `tools/build_reports.py` (it overwrites README.md); edit README and docs by hand.
6. Commit and push your branch: `git add -A && git commit -m "..." && git push -u origin feature/<short-name>`, then open a Pull Request on GitHub.
7. The other person reviews and merges. Delete the branch after merge.
8. Binary files (`.pptx`, `.xlsx`) cannot be merged. Tell each other before editing them; only one person edits at a time.
9. Do not commit the dataset (`data/`), `parsed/` or other large files (see `.gitignore`).
