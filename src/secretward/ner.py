"""A small name classifier we train ourselves (classical ML, no pretrained model, no LLM).

Model: averaged perceptron over hand-designed features, one decision per capitalised Latin
token. Weights live in ner_weights.json (a few thousand numbers); inference is pure Python.

Design rule against memorisation: the model NEVER sees the identity of the word it is
judging. It only sees its shape (capitalisation, length), its endings (-esh, -ita, -mycin)
and the words around it. Capitalised neighbours are reduced to their shape too, so no name
from the training data can be stored in the weights.

It runs AFTER the rules: the rules catch names with cues; this catches names without cues
("Spoke with Ramprasad Kushwaha about the discharge").
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .rules import MEDICAL_STEMS, MEDICAL_WORDS, SAFE_WORDS

WEIGHTS = Path(__file__).resolve().parent / "ner_weights.json"
TOKEN = re.compile(r"[A-Za-z][A-Za-z'’]*|\d+|\S")
WORDLIKE = re.compile(r"[A-Za-z][A-Za-z'’]*$")
NUM = re.compile(r"\d+$")
SENT_END = {".", ";", ":", "!", "?", "\n", "-", "|", "]", ")"}


def tokens(text: str):
    return [(m.group(0), m.start(), m.end()) for m in TOKEN.finditer(text)]


MIN_WORDS = 6                 # the model only judges real sentences, not 2-3 word field values


def is_candidate(tok: str) -> bool:
    """Title-case words only: ALL-CAPS tokens are abbreviations (ABHA, OPD, BP) far more
    often than names in free text; structured CAPS names are handled by column rules."""
    return bool(WORDLIKE.match(tok)) and tok[:1].isupper() and not tok.isupper() and len(tok) >= 2


def medical(tok: str, extra=frozenset()) -> bool:
    """Veto: drug stems (-statin, -sartan ...), medical suffixes (-itis, -ology ...), a generic
    clinical word list, and medical words learned from THIS input's drug/test columns."""
    low = tok.lower()
    return (low in MEDICAL_WORDS or low in extra or low in SAFE_WORDS
            or (len(low) > 5 and low.endswith(MEDICAL_STEMS)))


def standalone(text: str, s: int, e: int) -> bool:
    """A separate word, not part of a URL, code or compound ("v3-ActCode", "PSN-KMVVSC")."""
    before = text[s - 1:s]
    after = text[e:e + 1]
    return (before == "" or before in " \t\n(\"'") and (after == "" or after in " \t\n,.;:!?)\"'")


def _shape(w: str) -> str:
    if NUM.match(w):
        return "<num>"
    if not WORDLIKE.match(w):
        return "<p>" + w if len(w) == 1 else "<p>"
    if w.isupper():
        return "<CAPS>"
    if w[:1].isupper():
        return "<Title>"
    return w.lower()            # lowercase context words keep their identity (function words)


def features(toks: list[str], i: int) -> list[str]:
    w = toks[i]
    low = w.lower()
    f = ["bias",
         "shape=" + ("CAPS" if w.isupper() else "Title"),
         "len=" + ("2-3" if len(w) <= 3 else "4-5" if len(w) <= 5 else "6-8" if len(w) <= 8 else "9+"),
         "suf2=" + low[-2:], "suf3=" + low[-3:], "suf4=" + low[-4:],
         "safe=" + str(low in SAFE_WORDS)]
    prev = toks[i - 1] if i > 0 else "<s>"
    nxt = toks[i + 1] if i + 1 < len(toks) else "</s>"
    prev2 = toks[i - 2] if i > 1 else "<s>"
    nxt2 = toks[i + 2] if i + 2 < len(toks) else "</s>"
    f += ["w-1=" + _shape(prev), "w+1=" + _shape(nxt), "w-2=" + _shape(prev2), "w+2=" + _shape(nxt2),
          "w-1w+1=" + _shape(prev) + "|" + _shape(nxt),
          "start=" + str(prev in SENT_END or prev == "<s>")]
    return f


class NameTagger:
    def __init__(self, weights: dict | None = None, threshold: float = 0.0) -> None:
        if weights is None:
            data = json.loads(WEIGHTS.read_text(encoding="utf-8")) if WEIGHTS.exists() else {}
            weights, threshold = data.get("weights", {}), data.get("threshold", 0.0)
        self.w = weights
        self.threshold = threshold

    def score(self, feats) -> float:
        return sum(self.w.get(f, 0.0) for f in feats)

    def spans(self, text: str, extra_medical=frozenset()) -> list[tuple[int, int]]:
        """Character spans of predicted names. Each line is judged on its own: a note line
        starts fresh, so "...gaye.\nSunil Das ko" reads like "Sunil Das ko" at file start."""
        if not self.w:
            return []
        out, pos = [], 0
        for line in text.split("\n"):
            out += [(pos + a, pos + b) for a, b in self._line_spans(line, extra_medical)]
            pos += len(line) + 1
        return out

    def _line_spans(self, text: str, extra_medical=frozenset()) -> list[tuple[int, int]]:
        tk = tokens(text)
        words = [t for t, _, _ in tk]
        if sum(1 for t in words if WORDLIKE.match(t)) < MIN_WORDS:
            return []
        hits = []
        for i, (t, s, e) in enumerate(tk):
            if not is_candidate(t) or medical(t, extra_medical):
                continue
            prev = words[i - 1] if i > 0 else "<s>"
            if (prev in SENT_END or prev == "<s>") and t.lower().endswith(("ed", "ing")) and len(t) > 4:
                continue                       # sentence-initial past tense / gerund: "Informed ..."
            if text[max(0, s - 1):s] == "[" or t.startswith("PSN") or not standalone(text, s, e):
                continue                       # our placeholders, pseudonyms, URL/code fragments
            if self.score(features(words, i)) > self.threshold:
                hits.append((s, e))
        merged = []
        for s, e in hits:
            if merged and re.fullmatch(r"[ \t]+", text[merged[-1][1]:s] or "x"):
                merged[-1] = (merged[-1][0], e)
            else:
                merged.append((s, e))
        return merged


class Perceptron:
    """Averaged perceptron trainer (used by scripts/train_ner.py, not at run time)."""

    def __init__(self) -> None:
        self.w: dict[str, float] = {}
        self._tot: dict[str, float] = {}
        self._ts: dict[str, int] = {}
        self.t = 0

    def update(self, feats, y: int) -> None:
        self.t += 1
        guess = 1 if sum(self.w.get(f, 0.0) for f in feats) > 0 else 0
        if guess == y:
            return
        delta = 1.0 if y == 1 else -1.0
        for f in feats:
            self._tot[f] = self._tot.get(f, 0.0) + (self.t - self._ts.get(f, 0)) * self.w.get(f, 0.0)
            self._ts[f] = self.t
            self.w[f] = self.w.get(f, 0.0) + delta

    def averaged(self) -> dict[str, float]:
        out = {}
        for f, wv in self.w.items():
            tot = self._tot.get(f, 0.0) + (self.t - self._ts.get(f, 0)) * wv
            avg = tot / max(1, self.t)
            if abs(avg) > 1e-4:
                out[f] = round(avg, 5)
        return out
