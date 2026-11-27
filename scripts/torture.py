#!/usr/bin/env python3
"""Torture test (dev only): the real-world inputs an organiser can use to break a firewall.

Builds a fresh input tree full of hostile cases, runs main.py on it in a subprocess, then
checks: exit code, the official contract, every input file accounted for, and that none of
the planted identifiers appears ANYWHERE in the output (files, names, logs, report, stdout,
stderr). Reports time and peak memory.

Usage: python scripts/torture.py --kit ../Secret-Wards-ToolKit [--big-mb 60] [--keep DIR]
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import random
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NAMES = ["Ramesh Yadav", "Sunita Devi", "Mohammad Shahid", "Kavita Kushwaha", "Rajendra Prasad Tiwari"]
PHONE = "9876543210"
AADHAAR = "4123 5678 9012"
PLANTED = NAMES + [PHONE, AADHAAR.replace(" ", ""), "Zorawar Qadri"]


def note(i: int) -> str:
    n = NAMES[i % len(NAMES)]
    return (f"Patient Name: {n}\nMobile: {PHONE}\nAadhaar: {AADHAAR}\n"
            f"Pt c/o fever x 3 days. Tab Paracetamol 650 mg 1-0-1 x 5 days. BP 130/80.\n")


def build(inp: Path, big_mb: int) -> dict:
    """Returns {relative path: expectation} for the hostile cases."""
    cases = {}

    def w(rel, data, why):
        p = inp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        cases[rel] = why

    # --- empty and degenerate files
    w("empty/zero.csv", b"", "zero-byte CSV")
    w("empty/zero.json", b"", "zero-byte JSON")
    w("empty/zero.txt", b"", "zero-byte text")
    w("empty/space.txt", "   \n\n\t \n", "whitespace only")
    w("empty/header_only.csv", "Patient Name,Mobile,Diagnosis\n", "header, no rows")
    w("empty/null.json", "null", "JSON null")
    w("empty/obj.json", "{}", "empty JSON object")
    w("empty/arr.json", "[]", "empty JSON array")
    w("empty/scalar.json", "42", "JSON scalar")
    w("empty/bom_only.txt", b"\xef\xbb\xbf", "BOM only")

    # --- encodings and disguises
    w("enc/utf16_nobom.txt", note(0).encode("utf-16-le"), "UTF-16 without BOM")
    w("enc/utf16_bom.csv", ("Patient Name,Mobile\n" + f"{NAMES[1]},{PHONE}\n").encode("utf-16"), "UTF-16 CSV with BOM")
    w("enc/nul_bytes.txt", note(1).replace("Name: ", "Name: \x00"), "NUL byte inside a name label")
    w("enc/mixed.txt", note(2).encode("utf-8") + "Kavita Kushwaha ne bataya\n".encode("cp1252") + b"\xff\xfe\x00",
      "valid UTF-8 then stray bytes")
    w("enc/json_in_csv.csv", json.dumps({"patient_name": NAMES[3], "mobile": PHONE}), "JSON behind .csv")
    w("enc/binary.csv", bytes(random.Random(1).getrandbits(8) for _ in range(4096)), "random binary as .csv")
    w("enc/truncated.json", '{"patient": {"name": "' + NAMES[4] + '", "phone": "' + PHONE, "truncated JSON")

    # --- names and paths
    w(f"Ramesh Yadav {PHONE}/discharge.txt", note(0), "PII in a FOLDER name")
    w(f"notes/{NAMES[1].replace(' ', '_')}_{PHONE}.txt", note(1), "PII in file name")
    w("notes/UPPER.TXT", note(2), "upper-case extension")
    w("notes/no_extension", note(3), "no extension")
    w("notes/.hidden_note.txt", note(4), "hidden file")
    w("notes/नोट_रोगी.txt", "नाम: रमेश यादव\nमोबाइल: 9876543210\nबुखार 3 दिन से\n", "Devanagari file name")
    w("notes/record.jsonl", "\n".join(json.dumps({"patient_name": n, "phone": PHONE, "dx": "Typhoid"}) for n in NAMES),
      "JSON Lines")
    w("notes/page.html", f"<html><body><p>Patient: {NAMES[0]}, Mob {PHONE}</p></body></html>", "HTML")
    w("notes/b64.txt", "Attachment: " + base64.b64encode(f"Consent witnessed by Zorawar Qadri, {PHONE}".encode()).decode(),
      "base64 attachment")
    w("dup/a/copy.txt", note(0), "duplicate file 1")
    w("dup/b/copy.txt", note(0), "duplicate file 2")

    # --- CSV shapes
    hdr = ["Patient Name", "Mobile", "Aadhaar", "Diagnosis"] + [f"col{i}" for i in range(3000)]
    w("csv/wide.csv", ",".join(hdr) + "\n" + ",".join([NAMES[0], PHONE, AADHAAR, "TB"] + ["x"] * 3000) + "\n",
      "3,004 columns")
    w("csv/ragged.csv", f"Patient Name,Mobile,Diagnosis\n{NAMES[0]},{PHONE}\n{NAMES[1]},{PHONE},TB,extra,more\n",
      "ragged rows")
    w("csv/quoted_newline.csv", f'Patient Name,Notes\n"{NAMES[2]}","line one\nCalled {NAMES[3]} on {PHONE}"\n',
      "quoted newline in a cell")
    w("csv/semicolon.csv", f"Patient Name;Mobile;Diagnosis\n{NAMES[0]};{PHONE};Malaria\n", "semicolon delimiter")
    w("csv/pipe.csv", f"Patient Name|Mobile|Diagnosis\n{NAMES[1]}|{PHONE}|Dengue\n", "pipe delimiter")

    # --- size
    line = "Spoke with Ramesh Yadav about the plan, mob 9876543210, BP 120/80. "
    w("big/one_line.txt", line * (2_000_000 // len(line)), "2 MB on ONE line")
    rnd = random.Random(7)
    first = ["Ramesh", "Sunita", "Arjun", "Pooja", "Imran", "Neha", "Vikram", "Farida", "Gopal", "Rekha"]
    last = ["Yadav", "Sharma", "Khan", "Verma", "Gupta", "Rao", "Mishra", "Ansari", "Patel", "Joshi"]
    rows = ["UHID,Patient Name,Father Name,Mobile,Age,Gender,Village,District,Diagnosis,Admission Date"]
    size = len(rows[0])
    i = 0
    while size < big_mb * 1_000_000:
        r = (f"BULK-{i:07d},{rnd.choice(first)} {rnd.choice(last)},{rnd.choice(first)} {rnd.choice(last)},"
             f"9{rnd.randrange(10**8, 10**9)},{rnd.randrange(1, 95)},{rnd.choice('MF')},Rampur,Lucknow,"
             f"{rnd.choice(['TB', 'Typhoid', 'Diabetes', 'Malaria'])},{rnd.randrange(1, 28):02d}/0{rnd.randrange(1, 9)}/2025")
        rows.append(r)
        size += len(r) + 1
        i += 1
    rows.append(f"BULK-{i:07d},{NAMES[4]},Shyam Tiwari,{PHONE},44,M,Rampur,Lucknow,TB,01/02/2025")
    w("big/bulk_export.csv", "\n".join(rows) + "\n", f"bulk export, {big_mb} MB, {i + 1:,} rows")
    return cases


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--big-mb", type=int, default=60)
    ap.add_argument("--keep")
    a = ap.parse_args()
    work = Path(a.keep) if a.keep else Path(tempfile.mkdtemp(prefix="sw_torture_"))
    if work.exists():
        shutil.rmtree(work)
    inp, out = work / "input", work / "output"
    inp.mkdir(parents=True)
    cases = build(inp, a.big_mb)
    try:
        os.symlink("/etc/passwd", inp / "notes" / "link_outside.txt")
        cases["notes/link_outside.txt"] = "symlink pointing outside the input"
    except OSError:
        pass
    n_files = sum(1 for p in inp.rglob("*") if p.is_file())

    env = dict(os.environ, RAKSHA_SECRET="torture")
    t0 = time.time()
    proc = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                          capture_output=True, text=True, env=env)
    secs = time.time() - t0
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024
    print(f"exit {proc.returncode} | {secs:.1f} s | peak {peak:.0f} MB | input files {n_files}")
    print("stdout:", proc.stdout.strip()[:300])
    if proc.stderr.strip():
        print("stderr:", proc.stderr.strip()[-600:])
    ok = proc.returncode == 0

    v = subprocess.run([sys.executable, str(Path(a.kit) / "validate_output.py"), "--input", str(inp),
                        "--output", str(out)], capture_output=True, text=True)
    print("contract:", (v.stdout.strip().splitlines() or ["(none)"])[-1])
    ok &= "CONTRACT OK" in v.stdout

    rep = json.loads((out / "report.json").read_text()) if (out / "report.json").exists() else {"files": []}
    print(f"report lists {len(rep['files'])} of {n_files} files; "
          f"quarantined {sum(f['status'] == 'quarantined' for f in rep['files'])}")
    reasons = {}
    for f in rep["files"]:
        if f["status"] == "quarantined":
            reasons[f["reason"]] = reasons.get(f["reason"], 0) + 1
    print("quarantine reasons:", reasons)

    # planted identifiers anywhere: file contents (normalised like the scorer), paths, stdout, stderr
    def norm(s: str) -> str:
        return re.sub(r"[\s\x00​-‍]+", " ", s).lower()
    hits = []
    for p in out.rglob("*"):
        rel = str(p.relative_to(out))
        if rel.startswith("quarantine"):
            continue
        texts = [rel]
        if p.is_file():
            texts.append(p.read_bytes().decode("utf-8", "replace"))
        for t in texts:
            tn = norm(t)
            dn = re.sub(r"\D", "", t)
            for s in PLANTED:
                if (s.isdigit() and s in dn) or (not s.isdigit() and norm(s) in tn):
                    hits.append((rel, s))
    for t, where in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
        for s in PLANTED:
            if norm(s) in norm(t):
                hits.append((where, s))
    seen = set()
    for h in hits:
        if h not in seen:
            seen.add(h)
            print("  LEAK", h)
    print(f"planted identifiers found in output: {len(seen)}")
    ok &= not seen
    print("RESULT:", "PASS" if ok else "FAIL")
    if not a.keep:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
