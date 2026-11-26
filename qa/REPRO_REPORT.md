# QA reproducibility report: secret-ward on toolkit dev/ data

> **Historical record, not a live bug report.** Gaps 1 (bare `python`/`pip`) and 2 (no Python version stated) were fixed on main by the hotfix merge `732abee`, which has been on main since `1e5e012`. `raksha.toml` now uses `python3`, and the README says "Requires Python 3.9 or newer". Re-verified on `1e5e012`: `check_submission.py --run` prints READY TO SUBMIT under stock macOS Python 3.9.6. Logs referenced below live in the git-ignored `qa/logs/` and are not in the repo.

Date: 2026-11-26 · Engine `Manav-N4/secret-ward@ff98503` · Toolkit `Reinforce-SST/Secret-Wards-ToolKit@6c0a85a`
Machine: macOS (Darwin 27.2), Homebrew Python 3.14.6, fresh clones, no prior setup.
All raw output is in `qa/logs/`. No existing file in either repo was modified (`git status` shows only `?? qa/`).

## Verdict
**The README's numbers reproduce exactly.** `validate_output.py` printed `CONTRACT OK`.

| Metric (check_dev.py) | README claims | Measured |
|---|---|---|
| PII pieces leaked | 0 / 3230 | **0 / 3230** (every category 0%; latin/deva/hinglish 0%; all hiding places 0%) |
| Canaries found | 0 / 4 | **0 / 4** |
| Medical values kept | 4855 / 4855 | **4855 / 4855** (100%) |
| Linking precision / recall | 1.00 / 0.82 | **1.00 / 0.82** (F0.5 0.96, 0 wrong merges) |
| Raw copies of bad files | – | **0** |
| Runtime | ~2 s | **~2.0 s** wall time (200 files: 193 sanitized, 7 quarantined, 822 records) |

Determinism (`04_determinism.log`): two runs with the same secret produced identical output (ignoring the timing in `report.json`). With a different secret, 226 files differed.

## README commands (verbatim)
```bash
pip install -r requirements.txt
RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
```

## Gaps a judge would hit on a clean machine
1. **`pip` / `python` don't exist on a stock macOS or Homebrew install. Only `pip3` and `python3` do.** Running the README literally failed with `command not found` (exit 127, `00_literal_readme.log`). It worked inside a venv. `raksha.toml` uses the same bare `python main.py ...`, and the toolkit's `check_submission.py --run` executes that string with `shell=True`, so the official pre-submit check may also fail on a machine without a `python` alias. Fix: document `python3` or a venv step. Whether to change `raksha.toml` depends on what the organisers' runner provides.
2. **No Python version stated.** The toolkit says 3.10+. Verified here on 3.14.6 only.
3. **No example secret.** `<secret>` is a placeholder. The toolkit uses `RAKSHA_SECRET=practice`, and the README doesn't explain that any string works. It also doesn't mention the Windows syntax (`set` / `$env:`).
4. **No mention of where the data comes from or how to verify.** The README never points to the toolkit's `dev/input`, `validate_output.py` or `check_dev.py`, even though its "Measured" table comes from them. A reader can't reproduce the table from the README alone.
5. **The setup step contradicts the text.** The README says "Standard library only", yet tells you to `pip install -r requirements.txt`, and that file contains only a comment. The step is harmless but may confuse readers.
6. **"&lt;empty output dir&gt;" isn't enforced.** `main.py` uses `mkdir(exist_ok=True)` and doesn't clear the directory, so reusing a folder could leave stale files from an earlier run in the output. I didn't test this. It's a doc/robustness note, not a confirmed bug.
7. **Tests and helper scripts are undocumented.** `tests/test_traps.py` (run with `python -m pytest tests -q` or `python tests/test_traps.py`) and `scripts/link_misses.py`, `scripts/lost_probes.py` aren't mentioned in the README. I didn't run them.

## Exact commands used
```bash
cd secret-ward
python3 -m venv qa/.venv && source qa/.venv/bin/activate
pip install -r requirements.txt
RAKSHA_SECRET=practice python main.py --input ../Secret-Wards-ToolKit/dev/input --output qa/out/run1
python ../Secret-Wards-ToolKit/validate_output.py --input ../Secret-Wards-ToolKit/dev/input --output qa/out/run1
python ../Secret-Wards-ToolKit/check_dev.py --output qa/out/run1 --show 10
```
