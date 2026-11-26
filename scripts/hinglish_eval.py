#!/usr/bin/env python3
"""Hinglish nursing-note test (dev only): 40 synthetic notes written by a teammate, with no
registration table behind them, so every name must be found from the text alone.

Runs the notes two ways: each line as its own note, and all 40 lines as one multi-line note
(the way real ward notes arrive). Reports name parts removed and clinical words kept.
Usage: python scripts/hinglish_eval.py [--show]
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("RAKSHA_SECRET", "eval")

from secretward.detect import Ctx, sanitize         # noqa: E402
from secretward.gazetteer import Gazetteer          # noqa: E402

DATA = ROOT / "tests/hinglish"
CLINICAL = ["fever", "khansi", "nausea", "breathlessness", "100.4", "vomiting", "loose motions",
            "dizziness", "sore throat", "headache", "diabetes", "swelling", "pulse", "fatigue",
            "weakness", "allergy", "chest discomfort", "abdominal pain", "pain score 3 out of 10"]


def score(lines, outs, gold):
    tot = caught = clean = 0
    misses = []
    for g, o in zip(gold, outs):
        left = [w for w in g if re.search(r"(?<![A-Za-z])" + w + r"(?![A-Za-z])", o)]
        tot += len(g)
        caught += len(g) - len(left)
        clean += not left
        if left:
            misses.append(o)
    text = "\n".join(outs)
    kept = sum(1 for c in CLINICAL if c in text)
    return caught, tot, clean, kept, misses


def main() -> int:
    lines = (DATA / "hinglish_notes_40.txt").read_text(encoding="utf-8").splitlines()
    gold = json.loads((DATA / "hinglish_notes_40.names.json").read_text(encoding="utf-8"))
    gaz = Gazetteer()
    gaz.compile()
    one_by_one = [sanitize(l, Ctx(gaz=gaz, shift=7)) for l in lines]
    together = sanitize("\n".join(lines), Ctx(gaz=gaz, shift=7)).split("\n")
    for label, outs in (("each note alone", one_by_one), ("one 40-line note", together)):
        c, t, clean, kept, misses = score(lines, outs, gold)
        print(f"{label:17}: name parts removed {c}/{t} ({100 * c / t:.1f}%), notes fully clean "
              f"{clean}/{len(lines)}, clinical words kept {kept}/{len(CLINICAL)}")
        if "--show" in sys.argv:
            for m in misses:
                print("   MISS", m)
    return 0


if __name__ == "__main__":
    sys.exit(main())
