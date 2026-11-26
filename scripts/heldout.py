#!/usr/bin/env python3
"""Held-out stress tests (dev tool, practice data only).

The practice self-check runs on the same data we tuned on, so it flatters us. These
variants remove the sources our runtime gazetteer learns names from, which is what
"new patients we have never seen" looks like:

  full            the whole practice set (baseline)
  no_registration registration/ removed: no clean patient tables to learn names from
  free_text_only  only notes/, prescriptions/, discharge/ and lab/*.txt: names must be
                  found from context alone
  new_formats     phones, Aadhaar, IDs, DOBs, labels and relation markers rewritten into
                  formats our rules have never seen (truth surfaces updated to match)
  renamed_headers every CSV/TSV header renamed to wording our rules have never seen
                  (Gram/Shehar, Sampark Sutra, Pehchan Sankhya ...): detection must use content

For each variant we build a matching subset of truth.json, run main.py, then the kit's
check_dev.py, and print one comparable line.

Usage: python scripts/heldout.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

VARIANTS = {
    "full": lambda rel: True,
    "no_registration": lambda rel: not rel.startswith("registration/"),
    "free_text_only": lambda rel: rel.split("/")[0] in ("notes", "prescriptions", "discharge")
    or (rel.startswith("lab/") and rel.endswith(".txt")),
}


# Unseen header wording for the "renamed_headers" variant. These live ONLY here, never in
# config/rules: the point is to test content-based detection, not to learn these names.
UNSEEN_HEADERS = {
    "patient name": "Rogi ka Vivran", "patient_name": "Rogi", "naam": "Poora Vivran", "firstname": "Pehla",
    "lastname": "Kul", "city": "Gram/Shehar", "village/mohalla": "Basti", "gaon": "Thikana Gaon",
    "mobile": "Sampark Sutra", "mobile no": "Doorbhash", "phone": "Sampark", "address": "Rihayish",
    "pata": "Rihayish Vivran", "street": "Gali", "relative name": "Parijan", "guardian": "Sanrakshak",
    "pita/pati ka naam": "Abhibhavak", "aadhaar no": "Pehchan Sankhya", "aadhar": "Pehchan",
    "abha no": "Swasthya Khata", "dob": "Paidaish", "janm tithi": "Paidaish Din", "tehsil": "Pargana",
    "pin": "Dak Sankhya", "zip": "Dak Sankhya", "pin code": "Dak Code", "email": "E-Daak",
    "uhid": "Aspatal Kram", "patientid": "Kram Sankhya", "reg no": "Panjikaran",
}


def rename_headers(raw: bytes, suffix: str) -> bytes:
    import csv
    import io
    text = None
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeError:
            continue
    if text is None:
        return raw
    delim = "\t" if suffix == ".tsv" or text.count("\t") > text.count(",") else ","
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
    if not rows:
        return raw
    rows[0] = [UNSEEN_HEADERS.get(h.strip().lower(), h) for h in rows[0]]
    buf = io.StringIO()
    csv.writer(buf, delimiter=delim, lineterminator="\n").writerows(rows)
    return buf.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------- new formats
# Rewrites identifiers, dates and labels into formats our rules have never seen, and updates
# the truth surfaces to match, so leak counting stays exact. Only this test knows the formats.
import random as _random

_MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _phone(d: str, k: int) -> str:
    d = d[-10:]
    return [f"0{d[:5]} {d[5:]}", f"+91 ({d[:5]}) {d[5:]}", f"{d[:4]}-{d[4:7]}-{d[7:]}", f"91{d}"][k % 4]


def _date(s: str, k: int):
    m = re.fullmatch(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})", s.strip())
    iso = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s.strip())
    if m:
        d, mo, y = m.groups()
    elif iso:
        y, mo, d = iso.groups()
    else:
        return None
    if int(mo) > 12:
        return None
    return [f"{int(d)} {_MON[int(mo) - 1]} {y}", f"{d}.{mo}.{y}"][k % 2]


LABEL_SWAPS = [(r"(?i)\bpatient name\s*:", "Pt:"), (r"(?i)(?<![a-z])name\s*:", "Naam -"),
               (r"नाम:", "रोगी:"), (r"\bS/o\b", "son of"), (r"\bW/o\b", "wife of"), (r"\bD/o\b", "daughter of")]


def new_formats_file(rel: str, raw: bytes, f: dict):
    """Return (new bytes, new truth entry) for one file."""
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeError:
            continue
    else:
        return raw, f
    rnd = _random.Random(rel)
    f = json.loads(json.dumps(f))
    subs = {}
    for u in f["units"].values():
        for e in u["entities"]:
            if e.get("channel") not in ("content",):
                continue
            s0 = e["surface"]
            new = None
            digits = re.sub(r"\D", "", s0)
            if e["type"] == "PHONE" and len(digits) >= 10:
                new = _phone(digits, rnd.randrange(4))
            elif e["type"] == "AADHAAR" and len(digits) == 12:
                new = f"{digits[:4]}-{digits[4:8]}-{digits[8:]}"
            elif e["type"] == "MRN" and re.fullmatch(r"[A-Z]+-\d{5,}", s0):
                pfx, num = s0.split("-", 1)
                new = [f"{pfx}#{num}", f"{pfx} {num}"][rnd.randrange(2)]
            elif e["type"] == "DOB":
                new = _date(s0, rnd.randrange(2))
            if new and s0 in text:
                subs[s0] = new
                e["surface"] = new
    is_json = rel.endswith(".json")
    for s0, new in sorted(subs.items(), key=lambda x: -len(x[0])):
        text = text.replace(s0, new)
    if not rel.endswith((".csv", ".tsv", ".json")):
        for rx, rep in LABEL_SWAPS:
            text = re.sub(rx, rep, text)
    out = text.encode("utf-8")
    if is_json:
        try:
            json.loads(text)
        except ValueError:
            return raw, None                      # never produce a broken test file
    f["sha256"] = hashlib.sha256(out).hexdigest()
    return out, f


def run_variant(kit: Path, name: str, keep, work: Path, transform=None, file_transform=None) -> str:
    src = kit / "dev"
    truth = json.loads((src / "truth/truth.json").read_text(encoding="utf-8"))
    base = work / name
    (base / "input").mkdir(parents=True)
    (base / "truth").mkdir()
    files = {}
    for rel, f in truth["files"].items():
        if keep(rel):
            dest = base / "input" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            raw = (src / "input" / rel).read_bytes()
            f = dict(f)
            if transform and dest.suffix.lower() in (".csv", ".tsv") and raw.strip():
                raw = transform(raw, dest.suffix.lower())
                f["sha256"] = hashlib.sha256(raw).hexdigest()
            if file_transform and raw.strip() and f.get("expect") == "sanitize":
                raw2, f2 = file_transform(rel, raw, f)
                if f2 is not None:
                    raw, f = raw2, f2
            dest.write_bytes(raw)
            files[rel] = f
    sub = dict(truth)
    sub["files"] = files
    (base / "truth/truth.json").write_text(json.dumps(sub, ensure_ascii=False), encoding="utf-8")
    out = base / "out"
    env = dict(os.environ, RAKSHA_SECRET="practice")
    subprocess.run([sys.executable, str(REPO / "main.py"), "--input", str(base / "input"), "--output", str(out)],
                   check=True, env=env, capture_output=True)
    res = subprocess.run([sys.executable, str(kit / "check_dev.py"), "--output", str(out),
                          "--truth", str(base / "truth/truth.json")], capture_output=True, text=True, env=env)
    txt = res.stdout

    def grab(rx, default="?"):
        m = re.search(rx, txt)
        return m.group(1) if m else default
    leaked = grab(r"PERSONAL DATA:\s+(\d+ of \d+)")
    pct = grab(r"\(\s*([\d.]+)% leaked")
    names = grab(r"PATIENT_NAME\s+leaked\s+(\d+ /\s*\d+)")
    rel = grab(r"RELATIVE_NAME\s+leaked\s+(\d+ /\s*\d+)")
    scripts = grab(r"by language: ([^\n]+)")
    canary = grab(r"CANARIES: (\d+ of \d+)")
    med = grab(r"MEDICAL DATA KEPT: [^(]*\(\s*([\d.]+)%")
    link = grab(r"precision ([\d.]+, recall [\d.]+)")
    return (f"{name:16s} files {len(files):3d} | leaked {leaked:>12s} ({pct}%) | names {names:>9s} | "
            f"relatives {rel:>9s} | canaries {canary} | medical {med}% | link P,R {link}\n"
            f"{'':16s} by script: {scripts}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    a = ap.parse_args()
    kit = Path(a.kit).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        for name, keep in VARIANTS.items():
            print(run_variant(kit, name, keep, Path(tmp)))
        print(run_variant(kit, "renamed_headers", lambda rel: True, Path(tmp), rename_headers))
        print(run_variant(kit, "new_formats", lambda rel: True, Path(tmp), file_transform=new_formats_file))
    return 0


if __name__ == "__main__":
    sys.exit(main())
