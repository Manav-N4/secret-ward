#!/usr/bin/env python3
"""Held-out stress tests (dev tool, practice data only).

The practice self-check runs on the same data we tuned on, so it flatters us. These
variants remove the sources our runtime gazetteer learns names from, which is what
"new patients we have never seen" looks like:

  full            the whole practice set (baseline)
  no_registration registration/ removed: no clean patient tables to learn names from
  free_text_only  only notes/, prescriptions/, discharge/ and lab/*.txt: names must be
                  found from context alone

For each variant we build a matching subset of truth.json, run main.py, then the kit's
check_dev.py, and print one comparable line.

Usage: python scripts/heldout.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
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


def run_variant(kit: Path, name: str, keep, work: Path) -> str:
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
            shutil.copyfile(src / "input" / rel, dest)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
