#!/usr/bin/env python3
"""Side-channel leak scan: search everything a run produced for the secret, canaries and real PII.

Hard pass/fail (exit 1 on any hit). The scoring rules charge a canary or identifier leak found
*anywhere*: sanitized files, file names, report.json, records.jsonl, logs, stdout/stderr, temp files.

Searches every given file (or every file under a given folder) three ways:
  raw text        decoded as UTF-8 (binary files are scanned too, e.g. .pyc caches)
  normalised      NFKC + casefold + collapsed whitespace, same as the toolkit's check_dev.py
  base64          every run of 24+ base64 characters is decoded and searched (check_dev does this
                  for canaries; one practice canary is hidden that way in the input)
Text needles match on word boundaries ("Mary" does not hit "Summary"); phones and Aadhaar are
matched digits-only inside a digit run of about the same length, so "+91 72864 90658",
"7286490658" and "72864-90658" all hit. File NAMES are checked too.

Needles: the secret (--secret, default $RAKSHA_SECRET), all CANARY entities from truth.json, and
patient/relative names, phones and Aadhaar numbers from the truth (registration CSV/TSV files by
default, or every file with --pii-scope all).

Run it on the raw input first as a positive control: it must report the canaries.

Usage:
  RAKSHA_SECRET=practice TMPDIR=/tmp/scan_tmp/ python3 main.py --input IN --output OUT > run.out 2> run.err
  python3 qa/leak_scan.py --truth ../Secret-Wards-ToolKit/dev/truth/truth.json --secret practice \\
      OUT run.out run.err /tmp/scan_tmp
Stdlib only.
"""
import argparse
import base64
import binascii
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
PII_TYPES = ("PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR")


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def word_rx(needle_norm: str):
    return re.compile(r"(?<![^\W_])" + re.escape(needle_norm) + r"(?![^\W_])")


def build_needles(truth, secret, scope):
    needles = []
    if secret:
        needles.append(("SECRET", secret, "text"))
    seen, pii = set(), set()
    for rel, f in truth["files"].items():
        in_scope = scope == "all" or (rel.startswith("registration/") and rel.endswith((".csv", ".tsv")))
        for u in f["units"].values():
            for e in u["entities"]:
                if e["type"] == "CANARY" and e["surface"] not in seen:
                    seen.add(e["surface"])
                    needles.append(("CANARY", e["surface"], "text"))
                elif in_scope and e["type"] in PII_TYPES:
                    pii.add((e["type"], e["surface"]))
    for t, s in sorted(pii):
        if t in ("PHONE", "AADHAAR"):
            d = re.sub(r"\D", "", s)
            needles.append((t, d[-10:] if t == "PHONE" else d, "digits"))
        else:
            needles.append((t, s, "text"))
    return needles


def variants(raw: bytes):
    txt = raw.decode("utf-8", errors="replace")
    yield "raw", txt
    for m in B64.finditer(txt):
        tok = m.group(0)
        try:
            yield "base64", base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            pass


def scan(paths, needles):
    compiled = [(c, n, m, word_rx(norm(n)) if m == "text" and norm(n) else None) for c, n, m in needles]
    files = [p for r in paths for p in ([r] if r.is_file() else sorted(r.rglob("*"))) if p.is_file()]
    hits, nbytes = [], 0
    for p in files:
        raw = p.read_bytes()
        nbytes += len(raw)
        for kind, text in variants(raw):
            lines = text.splitlines() or [""]
            nlines = [norm(l) for l in lines]
            for cat, needle, mode, rx in compiled:
                if mode == "text":
                    if rx is None:
                        continue
                    for i, l in enumerate(nlines):
                        if rx.search(l):
                            hits.append((cat, needle, str(p), i + 1, kind, lines[i].strip()[:160]))
                else:
                    for i, l in enumerate(lines):
                        for run in re.findall(r"\d[\d\s+-]*\d", l):
                            digits = re.sub(r"\D", "", run)
                            if digits.endswith(needle) and len(digits) <= len(needle) + 2:
                                hits.append((cat, needle, str(p), i + 1, kind, l.strip()[:160]))
        fname = norm(p.name).replace("_", " ")
        for cat, needle, mode, rx in compiled:
            if mode == "text" and rx is not None and rx.search(fname):
                hits.append((cat, needle, str(p), 0, "filename", p.name))
    return files, nbytes, hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--truth", required=True, help="toolkit dev/truth/truth.json (canaries + PII needles)")
    ap.add_argument("--secret", default=os.environ.get("RAKSHA_SECRET"), help="secret to look for "
                    "(default: $RAKSHA_SECRET)")
    ap.add_argument("--pii-scope", choices=("registration", "all"), default="registration")
    ap.add_argument("paths", nargs="+", type=Path, help="files and/or folders the run produced")
    a = ap.parse_args()
    if not a.secret:
        print("warning: no --secret given and RAKSHA_SECRET unset; the secret is not searched", file=sys.stderr)
    missing = [str(p) for p in a.paths if not p.exists()]
    if missing:
        sys.exit(f"path(s) not found: {', '.join(missing)}")
    truth = json.loads(Path(a.truth).read_text(encoding="utf-8"))
    needles = build_needles(truth, a.secret, a.pii_scope)
    files, nbytes, hits = scan(a.paths, needles)
    counts = {c: sum(1 for x in needles if x[0] == c) for c in dict.fromkeys(n[0] for n in needles)}
    print(f"scanned {len(files)} files, {nbytes} bytes; needles: " + ", ".join(f"{c}={n}" for c, n in counts.items()))
    if not files:
        print("ERROR: no files scanned (check the paths)")
        return 2
    for h in hits:
        print("HIT", *h, sep=" | ")
    print("TOTAL HITS:", len(hits), "->", "FAIL" if hits else "PASS")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
