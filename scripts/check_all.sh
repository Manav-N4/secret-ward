#!/usr/bin/env bash
# One command for the whole verification routine.
# Usage (from the repo root):  bash scripts/check_all.sh [path/to/Secret-Wards-ToolKit] [--full]
#   --full also runs the held-out stress tests (about 10 s more)
set -u
KIT="${1:-../Secret-Wards-ToolKit}"
FULL="${2:-}"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
OUT=out
fail=0
rm -rf "$OUT"

echo "== 1. pipeline"
RAKSHA_SECRET=practice "$PY" main.py --input "$KIT/dev/input" --output "$OUT" || fail=1

echo "== 2. output contract"
"$PY" "$KIT/validate_output.py" --input "$KIT/dev/input" --output "$OUT" | tail -1 | tee /tmp/_sw_contract
grep -q "CONTRACT OK" /tmp/_sw_contract || fail=1

echo "== 3. practice self-check"
"$PY" "$KIT/check_dev.py" --output "$OUT" | grep -E "PERSONAL DATA|by language|by hiding|CANARIES|MEDICAL|LINKING|RAW COPIES"

echo "== 4. trap tests"
"$PY" tests/test_traps.py | tail -1 | tee /tmp/_sw_traps
grep -q " 0 failures" /tmp/_sw_traps || fail=1

echo "== 5. our attacker (approximation of the official arena)"
"$PY" scripts/attack.py --kit "$KIT" --output "$OUT"

if [ "$FULL" = "--full" ]; then
  echo "== 6. held-out stress tests"
  "$PY" scripts/heldout.py --kit "$KIT"
fi

echo "== 7. official submission check (3 runs)"
"$PY" "$KIT/check_submission.py" --repo . --run 2>&1 | grep -E "❌|READY|FIX" | tee /tmp/_sw_sub
grep -q "READY TO SUBMIT" /tmp/_sw_sub || fail=1

echo
if [ $fail -eq 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL (see above)"; fi
exit $fail
