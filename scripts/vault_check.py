#!/usr/bin/env python3
"""Quarantine vault check (dev / operator tool).

  --check : prove every vault file (1) opens to the exact original input, (2) refuses the wrong
            secret, (3) refuses a tampered copy, (4) shares no 12-byte run with its plaintext.
  --open SHA --to PATH : authorised operator restores one quarantined input (needs RAKSHA_SECRET).

Usage: RAKSHA_SECRET=... python scripts/vault_check.py --input IN --output OUT --check
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secretward import vault  # noqa: E402


def shares_run(a: bytes, b: bytes, n: int = 12) -> bool:
    if len(b) < n:
        return False
    grams = {b[i:i + n] for i in range(0, len(b) - n + 1)}
    return any(a[i:i + n] in grams for i in range(0, len(a) - n + 1))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--input")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--open")
    ap.add_argument("--to")
    a = ap.parse_args()
    if not vault.AVAILABLE:
        print("vault: cryptography not installed, quarantined files are not kept")
        return 0
    secret = os.environ.get("RAKSHA_SECRET", "").encode()
    qdir = Path(a.output) / "quarantine"
    if a.open:
        Path(a.to).write_bytes(vault.open_sealed((qdir / f"{a.open}.swv").read_bytes(), a.open, secret))
        return 0
    originals = {}
    for p in Path(a.input).rglob("*"):
        if p.is_file():
            raw = p.read_bytes()
            originals[hashlib.sha256(raw).hexdigest()] = raw
    ok = bad = 0
    for f in sorted(qdir.glob("*.swv")):
        sha = f.stem
        blob = f.read_bytes()
        good = True
        try:
            plain = vault.open_sealed(blob, sha, secret)
            good &= plain == originals.get(sha) and hashlib.sha256(plain).hexdigest() == sha
        except Exception:  # noqa: BLE001
            good = False
        for trial in (lambda: vault.open_sealed(blob, sha, secret + b"x"),
                      lambda: vault.open_sealed(blob[:-1] + bytes([blob[-1] ^ 1]), sha, secret)):
            try:
                trial()
                good = False            # wrong key or tampered copy must NOT open
            except Exception:  # noqa: BLE001
                pass
        good &= not shares_run(blob, originals.get(sha, b""))
        ok += good
        bad += not good
    print(f"vault: {ok} of {ok + bad} quarantined files sealed correctly "
          f"(exact restore, wrong key refused, tampering refused, no plaintext runs)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
