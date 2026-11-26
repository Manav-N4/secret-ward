#!/usr/bin/env python3
"""No-cue stress test (dev only): names with no label/relation/honorific/trigger and not in any
table, plus capitalised medical decoys. Reports name recall and decoy damage.

Usage: python scripts/nocue_eval.py [--n 400] [--show 8]
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("RAKSHA_SECRET", "eval")

from nocue_data import generate                    # noqa: E402
from secretward.detect import Ctx, sanitize         # noqa: E402
from secretward.gazetteer import Gazetteer          # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=400)
    ap.add_argument("--show", type=int, default=0)
    ap.add_argument("--split", default="test")
    a = ap.parse_args()
    gaz = Gazetteer()          # empty: these people are in no registration table
    gaz.compile()
    items = generate(a.split, a.n)
    names_total = names_caught = decoys_total = decoys_kept = 0
    other_total = other_kept = 0
    misses, damage = [], []
    for sent, names, decoys in items:
        out = sanitize(sent, Ctx(gaz=gaz, shift=7))
        for nm in names:
            toks = nm.split()
            names_total += 1
            if not any(t in out for t in toks):
                names_caught += 1
            else:
                misses.append((sent, out))
        name_toks = {t for nm in names for t in nm.split()}
        for w in re.findall(r"[A-Za-z]+", sent):
            if w not in name_toks:
                other_total += 1
        out_words = Counter(re.findall(r"[A-Za-z]+", out))
        in_words = Counter(w for w in re.findall(r"[A-Za-z]+", sent) if w not in name_toks)
        other_kept += sum(min(c, out_words[w]) for w, c in in_words.items())
        for d in decoys:
            decoys_total += 1
            if d in out:
                decoys_kept += 1
            else:
                damage.append((sent, out))
    print(f"no-cue names removed : {names_caught}/{names_total} ({100 * names_caught / max(1, names_total):.1f}%)")
    print(f"medical decoys kept  : {decoys_kept}/{decoys_total} ({100 * decoys_kept / max(1, decoys_total):.1f}%)")
    print(f"all non-name words kept: {other_kept}/{other_total} ({100 * other_kept / max(1, other_total):.2f}%)")
    for s, o in misses[:a.show]:
        print("  MISS  ", s, "->", o)
    for s, o in damage[:a.show]:
        print("  DAMAGE", s, "->", o)
    return 0


if __name__ == "__main__":
    sys.exit(main())
