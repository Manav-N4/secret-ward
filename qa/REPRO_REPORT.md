# QA reproducibility report

## Current status (re-run on main, 2026-11-27)
| check | result |
|---|---|
| practice set (check_dev) | 0 / 3230 leaked, 0 / 4 canaries, medical 4826 / 4855 (99.4%), linking P 1.00 R 1.00 |
| `mutate.py`, 8 seeds (1, 7, 42, 99, 123, 555, 1337, 2026) | **0 / 3230 leaked on every seed**, medical 99.4%, linking 1.00 / 1.00 |
| `attack_sim.py`, raw → sanitized | A3 risk 0.648 → 0.028; re-identified 97.9% → 8.3%; A5 100% → 47.6% |

Bug found by this harness and fixed: seeds 1 and 42 renamed `aadhaar` to `uid_sankhya` in a JSON
file where the Aadhaar is stored as a **number** (`902115225016`); numbers under unknown keys were passed
through. Integers with 10 or more digits now go through the same ID rules as text (trap test added).

Reproduce:
```bash
python3 qa/mutate.py --dev ../Secret-Wards-ToolKit/dev --out qa/mutated/s42 --seed 42
RAKSHA_SECRET=practice python3 main.py --input qa/mutated/s42/input --output qa/out/s42
python3 ../Secret-Wards-ToolKit/check_dev.py --output qa/out/s42 --truth qa/mutated/s42/truth/truth.json
python3 qa/attack_sim.py --kit ../Secret-Wards-ToolKit --output out     # add --raw for the baseline
```

## Original report (2026-11-26, historical)

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
