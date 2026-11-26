#!/usr/bin/env python3
"""Train the name classifier (dev only) and write src/secretward/ner_weights.json.

Training data (all synthetic, as the rules allow):
  1. the practice free-text files, with name spans taken from the practice answer key
     (this teaches what is NOT a name in real clinical text: Paracetamol, Course, Ward ...)
  2. synthetic sentences from scripts/nocue_data.py, TRAIN split only (the TEST split's
     templates and names are never seen here)

Usage: python scripts/train_ner.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from nocue_data import generate                                       # noqa: E402
from secretward.ner import WEIGHTS, Perceptron, features, is_candidate, medical, standalone, tokens  # noqa: E402

NAME_TYPES = {"PATIENT_NAME", "RELATIVE_NAME", "CANARY", "OTHER_NAME"}


def label_tokens(text: str, name_spans: list[tuple[int, int]]):
    tk = tokens(text)
    words = [t for t, _, _ in tk]
    out = []
    for i, (t, s, e) in enumerate(tk):
        if not is_candidate(t) or not standalone(text, s, e) or medical(t):
            continue                  # same candidate filter as at run time
        y = 1 if any(s >= a and e <= b for a, b in name_spans) else 0
        out.append((features(words, i), y))
    return out


def practice_examples(kit: Path):
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    ex = []
    for rel, f in truth["files"].items():
        if not rel.endswith(".txt"):
            continue
        p = kit / "dev/input" / rel
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        spans = []
        for u in f["units"].values():
            for e in u["entities"]:
                if e["type"] in NAME_TYPES and e.get("channel") == "content" and e.get("script") != "deva":
                    start = 0
                    while True:
                        j = text.find(e["surface"], start)
                        if j < 0:
                            break
                        spans.append((j, j + len(e["surface"])))
                        start = j + 1
        ex += label_tokens(text, spans)
    return ex


def synthetic_examples(n: int):
    ex = []
    for sent, names, _ in generate("train", n):
        spans = []
        for nm in names:
            j = sent.find(nm)
            spans.append((j, j + len(nm)))
        ex += label_tokens(sent, spans)
    return ex


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--epochs", type=int, default=12)
    ap.add_argument("--threshold", type=float, default=0.0)
    a = ap.parse_args()
    data = practice_examples(Path(a.kit)) + synthetic_examples(1500)
    pos = sum(y for _, y in data)
    print(f"training tokens: {len(data)} ({pos} name tokens, {len(data) - pos} other capitalised tokens)")
    rnd = random.Random(42)
    model = Perceptron()
    for _ in range(a.epochs):
        rnd.shuffle(data)
        for feats, y in data:
            model.update(feats, y)
    w = model.averaged()
    WEIGHTS.write_text(json.dumps({"model": "averaged perceptron, trained by secret-ward on synthetic data",
                                   "threshold": a.threshold, "weights": dict(sorted(w.items()))},
                                  ensure_ascii=False, indent=0, sort_keys=False) + "\n", encoding="utf-8")
    tp = fp = fn = 0
    for feats, y in data:
        g = 1 if sum(w.get(f, 0.0) for f in feats) > a.threshold else 0
        tp += g and y
        fp += g and not y
        fn += (not g) and y
    print(f"weights: {len(w)} features -> {WEIGHTS.name}")
    print(f"training-set precision {tp / max(1, tp + fp):.3f}  recall {tp / max(1, tp + fn):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
