"""Loads the human-editable rule files in config/rules/.

Why data files and not code: teammates who don't write Python can add a Hindi label or
a new honorific without touching the engine, and nothing about the practice data is
hardcoded in the code itself.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "config" / "rules"


def _lines(name: str) -> list[str]:
    p = RULES / name
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("#") else ""
        if line:
            out.append(line)
    return out


def word_set(name: str) -> set[str]:
    return {x.lower() for x in _lines(name)}


def load_policy() -> dict:
    policy = {}
    p = ROOT / "config" / "policy.yaml"
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" in line:
            k, v = (x.strip() for x in line.split(":", 1))
            policy[k] = int(v) if v.lstrip("-").isdigit() else v
    return policy


def header_hints() -> list[tuple[str, list[str]]]:
    out = []
    for line in _lines("headers.txt"):
        typ, _, hints = line.partition("\t")
        out.append((typ.strip(), [h.strip().lower() for h in hints.split(",") if h.strip()]))
    return out


def months() -> dict[str, int]:
    out = {}
    for line in _lines("months.txt"):
        num, _, names = line.partition("\t")
        for n in names.split():
            out[n.lower()] = int(num)
    return out


def place_suffixes() -> tuple[tuple[str, ...], set[str]]:
    ends, words = [], set()
    for x in _lines("place_suffixes.txt"):
        (words.add(x[1:].lower()) if x.startswith("=") else ends.append(x.lower()))
    return tuple(sorted(ends, key=len, reverse=True)), words


def icd_chapters() -> list[tuple[str, str, str]]:
    out = []
    for line in _lines("icd_chapters.txt"):
        a, b, label = line.split("\t")
        out.append((a.strip(), b.strip(), label.strip()))
    return out


POLICY = load_policy()
ICD_CHAPTERS = icd_chapters()
PLACE_ENDS, PLACE_WORDS = place_suffixes()
LABELS_NAME = sorted(word_set("labels_name.txt"), key=len, reverse=True)
RELATIONS = sorted(word_set("relations.txt"), key=len, reverse=True)
TRIGGERS = sorted(word_set("triggers.txt"), key=len, reverse=True)
HON_AFTER = word_set("honorifics_after.txt")
HON_BEFORE = word_set("honorifics_before.txt")
DOCTOR_TITLES = word_set("doctor_titles.txt")
SAFE_WORDS = word_set("safe_words.txt")
GENERIC_TOKENS = word_set("generic_name_tokens.txt")
HEADER_HINTS = header_hints()
MONTHS = months()
