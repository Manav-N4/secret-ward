#!/usr/bin/env python3
"""Re-identification risk estimate (dev only), the number the Project Brief asks for.

For every patient we release, count the people in the attacker's voter-list register who fit
what the release says about them (gender, age band, district: our only quasi-identifiers;
village, house, PIN beyond 3 digits, DOB and names are removed, and dates are shifted per
patient, so a known admission date or week does not point to the record). A patient who fits
exactly ONE register person is unique, i.e. re-identifiable from quasi-identifiers alone.

Baselines on the same register: what the raw records expose (gender + exact age + village)
and the "5-year band + district" setting the kit's reference solution uses.

Usage: python scripts/reid_risk.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("RAKSHA_SECRET", "practice")

from secretward.pipeline import Pipeline  # noqa: E402


def norm(s: str) -> str:
    return re.sub(r"[^a-z]", "", str(s).lower())


def summary(label: str, sizes: list[int]) -> None:
    n = len(sizes)
    uniq = sum(1 for s in sizes if s == 1)
    small = sum(1 for s in sizes if s < 3)
    print(f"{label:44}: unique {uniq:2}/{n} ({100 * uniq / n:4.1f}%), fewer than 3 matches "
          f"{small:2}/{n} ({100 * small / n:4.1f}%), median matches {statistics.median(sizes):g}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    a = ap.parse_args()
    kit = Path(a.kit)
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    reg = list(csv.DictReader((kit / "dev/attacker/registry.csv").open(encoding="utf-8")))
    by_rid = {r["rid"]: r for r in reg}

    p = Pipeline(kit / "dev/input", Path("/tmp/_reid_unused"))
    p.load()
    p.build_units()

    # cluster -> true register person (majority of its records, from the answer key)
    votes: dict[str, Counter] = {}
    info: dict[str, tuple[set, set]] = {}
    for d in p.docs:
        units_truth = truth["files"].get(d.rel, {}).get("units", {})
        for u in d.units:
            if not u.cluster:
                continue
            g, dist = info.setdefault(u.cluster, (set(), set()))
            g |= u.ev.genders
            dist |= {norm(x) for x in u.ev.districts}
            pt = units_truth.get(u.loc, {}).get("patient")
            rid = truth["patients"].get(pt, {}).get("rid") if pt else None
            if rid:
                votes.setdefault(u.cluster, Counter())[rid] += 1

    ours, raw_exact, ref5, ten = [], [], [], []
    missed = 0
    for c, (genders, dists) in sorted(info.items()):
        if c not in votes:
            continue
        rid = votes[c].most_common(1)[0][0]
        me = by_rid.get(rid)
        if not me:
            continue
        band = p.cluster_bands.get(c)
        hidden = c in p.hidden_loc

        def fits(r, lo=None, hi=None, need_dist=True):
            if genders and len(genders) == 1 and r["gender"] not in genders:
                return False
            if lo is not None and not (lo <= int(r["age"]) <= hi):
                return False
            if need_dist and dists and norm(r["district"]) not in dists:
                return False
            return True

        lo, hi = band if band else (None, None)
        cands = [r for r in reg if fits(r, lo, hi, need_dist=not hidden)]
        if me not in cands:
            missed += 1             # our band/district would exclude the true person: an honest release never does
        ours.append(max(1, len(cands)))
        raw_exact.append(sum(1 for r in reg if r["gender"] == me["gender"] and r["age"] == me["age"]
                             and norm(r["village"]) == norm(me["village"])))
        age = int(me["age"])
        b5 = (age // 5) * 5
        ref5.append(sum(1 for r in reg if r["gender"] == me["gender"] and b5 <= int(r["age"]) <= b5 + 4
                        and norm(r["district"]) == norm(me["district"])))
        b10 = (age // 10) * 10
        ten.append(sum(1 for r in reg if r["gender"] == me["gender"] and b10 <= int(r["age"]) <= b10 + 9
                       and norm(r["district"]) == norm(me["district"])))

    print(f"patients released: {len(ours)} | register people: {len(reg)} | "
          f"true person outside our released band/district: {missed}")
    summary("raw: gender + exact age + village", raw_exact)
    summary("reference-style: gender + 5-yr band + district", ref5)
    summary("plain 10-yr band + district (no local k-anon)", ten)
    summary("ours: one band per patient + local k-anon", ours)
    return 0


if __name__ == "__main__":
    sys.exit(main())
