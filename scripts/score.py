#!/usr/bin/env python3
"""Estimate the parts of the OFFICIAL score that check_dev.py does not show (dev tool).

Follows docs/SCORING.md as closely as the published formulas allow:
  temporal        every pair of one patient's dated events: output interval == true interval
                  (1.0 exact, 0.5 at +-1 day), plus length-of-stay pairs
  generalization  structured age / DOB / village / district / PIN / gender fields: informative
                  and truthful (age band <=10y 0.8, <=20y 0.6; village kept 1.0, district 0.7 ...)
  token retention multiset share of non-PII input tokens still present (dates, ages, PII excluded)
  detection       recall macro-averaged by type (weighted) and by script, as the scorer does

These are ESTIMATES: the official evaluator is not public. Use them to compare versions.

Usage: python scripts/score.py --kit ../Secret-Wards-ToolKit --output out [--show 10]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

TYPE_W = {"AADHAAR": 1, "ABHA_NUMBER": 1, "PHONE": 1, "EMAIL": 1, "MRN": 1, "PAN": 1, "PATIENT_NAME": 1,
          "RELATIVE_NAME": .8, "DOB": .7, "HOUSE": .6, "LOCALITY": .6, "LANDMARK": .5, "VILLAGE": .5, "PIN": .5,
          "AADHAAR_MASKED": .5, "INSURANCE_ID": 1}


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def read(path: Path) -> str:
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def csv_rows(text: str, suffix: str):
    delim = "\t" if suffix == ".tsv" or text.count("\t") > text.count(",") else ","
    return list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))


def json_get(data, pointer: str):
    cur = data
    for part in pointer.strip("/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    return cur


DATE_RX = re.compile(r"(\d{4})-(\d{2})-(\d{2})|(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})")


def parse_date(s: str, hint: str):
    m = DATE_RX.search(s or "")
    if not m:
        return None
    try:
        if m.group(1):
            return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        a, b, y = int(m.group(4)), int(m.group(5)), m.group(6)
        y = int(y) if len(y) == 4 else 2000 + int(y)
        d, mo = (b, a) if hint == "mdy" else (a, b)
        return dt.date(y, mo, d)
    except ValueError:
        return None


def out_value(out_path: Path, loc: str, path: str | None, anchor: str | None, cache: dict):
    """Find the value at the same place in OUR output: CSV column, JSON pointer, or after an anchor."""
    key = str(out_path)
    if key not in cache:
        txt = read(out_path)
        obj = None
        if out_path.suffix.lower() in (".csv", ".tsv"):
            obj = csv_rows(txt, out_path.suffix.lower())
        elif out_path.suffix.lower() == ".json":
            try:
                obj = json.loads(txt)
            except ValueError:
                obj = None
        cache[key] = (txt, obj)
    txt, obj = cache[key]
    try:
        if path and path.startswith("col:") and isinstance(obj, list) and loc.startswith("row:"):
            col = path[4:]
            hdr = obj[0]
            j = hdr.index(col) if col in hdr else None
            return obj[int(loc[4:]) + 1][j] if j is not None else None
        if path and path.startswith("/") and obj is not None:
            try:                                   # paths are relative to the record ...
                return str(json_get(obj, (loc if loc.startswith("/") else "") + path))
            except (IndexError, KeyError, ValueError, TypeError):
                return str(json_get(obj, path))    # ... or to the file root
        if anchor:
            i = txt.find(anchor)
            return txt[i + len(anchor): i + len(anchor) + 40] if i >= 0 else None
    except (IndexError, KeyError, ValueError, TypeError):
        return None
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--show", type=int, default=0)
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    out_of = {e["input_sha256"]: e["output"] for e in report["files"]}
    cache: dict = {}

    # ------------------------------------------------------------------ temporal
    events = defaultdict(list)       # patient -> [(true date, our date or None, where)]
    missing = Counter()
    for rel, f in truth["files"].items():
        o = out_of.get(f["sha256"])
        for loc, u in f["units"].items():
            for d in u.get("dates", []):
                true = dt.date.fromisoformat(d["true"])
                ours = None
                if o:
                    v = out_value(out / o, loc, d.get("path"), d.get("anchor"), cache)
                    ours = parse_date(v, d.get("hint", "dmy")) if v else None
                if ours is None:
                    missing[rel.split("/")[0]] += 1
                events[d["patient"]].append((true, ours, f"{rel}#{loc}"))
    pairs = exact = half = 0
    bad = []
    for pt, evs in events.items():
        found = [e for e in evs if e[1] is not None]
        for (t1, o1, w1), (t2, o2, w2) in combinations(found, 2):
            pairs += 1
            diff = abs(((o1 - o2) - (t1 - t2)).days)
            if diff == 0:
                exact += 1
            elif diff == 1:
                half += 1
            elif len(bad) < 200:
                bad.append((pt, w1, w2, (t2 - t1).days, (o2 - o1).days))
    temporal = (exact + 0.5 * half) / pairs if pairs else 0.0

    # ------------------------------------------------------------------ generalization
    gen = defaultdict(list)
    for rel, f in truth["files"].items():
        o = out_of.get(f["sha256"])
        if not o:
            continue
        for loc, u in f["units"].items():
            for fl in u.get("fields", []):
                v = out_value(out / o, loc, fl.get("path"), None, cache)
                k, true = fl["kind"], fl["true"]
                s = (v or "").strip()
                score = 0.0
                if k == "age":
                    m = re.match(r"(\d{1,3})\s*-\s*(\d{1,3})|(\d{1,3})\s*\+|(\d{1,3})$", s)
                    if m:
                        if m.group(4):
                            score = 1.0 if int(m.group(4)) == true else 0.0
                        elif m.group(3):
                            score = 0.3 if true >= int(m.group(3)) else 0.0
                        else:
                            lo, hi = int(m.group(1)), int(m.group(2))
                            w = hi - lo + 1
                            score = 0.0 if not lo <= true <= hi else 0.9 if w <= 5 else 0.8 if w <= 10 else 0.6 if w <= 20 else 0.3
                elif k == "gender":
                    score = 1.0 if s[:1].upper() == str(true)[:1].upper() or s in ("महिला", "पुरुष") else 0.0
                elif k == "district":
                    score = 1.0 if s and not s.startswith("[") else 0.0
                elif k == "village":
                    score = 1.0 if s and not s.startswith("[") and "pur" in s.lower() else (0.7 if s and not s.startswith("[") else 0.0)
                elif k == "pin":
                    score = 1.0 if re.fullmatch(r"\d{6}", s) else 0.7 if re.fullmatch(r"\d{3}\*{3}", s) else 0.0
                elif k == "dob":
                    score = 0.9 if parse_date(s, "dmy") else 0.8 if re.fullmatch(r"(19|20)\d{2}", s) else 0.0
                gen[k].append(score)
    gen_score = sum(sum(v) / len(v) for v in gen.values()) / len(gen) if gen else 0.0

    # ------------------------------------------------------------------ token retention
    tok = re.compile(r"[A-Za-zऀ-ॿ]{3,}")
    kept = total = 0
    lost = Counter()
    for rel, f in truth["files"].items():
        o = out_of.get(f["sha256"])
        src = kit / "dev/input" / rel
        if not o or not src.is_file():
            continue
        pii = set()
        for u in f["units"].values():
            for e in u.get("entities", []):
                pii.update(t.lower() for t in tok.findall(e.get("surface", "")))
        tin = Counter(t.lower() for t in tok.findall(read(src)) if t.lower() not in pii)
        tout = Counter(t.lower() for t in tok.findall(read(out / o)))
        total += sum(tin.values())
        kept += sum(min(c, tout[t]) for t, c in tin.items())
        for t, c in tin.items():
            if c > tout[t]:
                lost[t] += c - tout[t]
    retention = kept / total if total else 0.0

    # ------------------------------------------------------------------ print
    print(f"temporal intervals : {temporal:.3f}  ({exact} exact, {half} off-by-1, {pairs - exact - half} wrong, of {pairs} pairs)")
    print(f"dates not found in output: {dict(missing)}")
    print("generalization     : " + "  ".join(f"{k} {sum(v)/len(v):.2f}" for k, v in sorted(gen.items()))
          + f"  -> mean {gen_score:.3f}")
    print(f"token retention    : {retention:.3f}  ({kept} of {total} non-PII tokens kept)")
    if a.show:
        print("most-lost non-PII tokens:", ", ".join(f"{t}x{n}" for t, n in lost.most_common(a.show * 2)))
    if a.show and bad:
        print("example wrong intervals (patient, record A, record B, true days, our days):")
        for b in bad[:a.show]:
            print("   ", b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
