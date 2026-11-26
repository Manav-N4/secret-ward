"""Rare-condition generalisation (defence against the targeted attack, A5).

An attacker who knows "she was admitted with kala-azar" finds her instantly if only one
patient in the release has kala-azar: per-patient date shifting cannot hide that. So a
diagnosis or procedure that appears in very few patients of THIS release is replaced by
its ICD-10 chapter ("Infectious and parasitic disease"), with the code reduced to the
chapter range. Common conditions keep full detail. The threshold is a policy setting.
"""
from __future__ import annotations

import re

from .rules import ICD_CHAPTERS

ICD = re.compile(r"\b([A-TV-Z])(\d{2})(?:\.\d{1,2})?\b")
# "Diagnosis: Anaemia, unspecified (D64.9);"  "K/C/O addison's disease"  "Procedure: ..."
TEXT_COND = re.compile(
    r"(?im)(?:final\s+)?(?:diagnosis|diagnoses|dx|procedure|operation|surgery done|k/c/o|known case of)"
    r"\s*[:\-]?\s*([^\n;]{4,80}?)\s*(?:\(([A-TV-Z]\d{2}(?:\.\d{1,2})?)\))?\s*(?:[;\n.]|$)")


def norm_cond(s: str) -> str:
    s = re.sub(r"\([A-TV-Z]\d{2}(?:\.\d{1,2})?\)", "", s)
    return re.sub(r"\s+", " ", s).strip(" .,;:").lower()


def chapter(code: str | None) -> tuple[str, str] | None:
    if not code:
        return None
    m = ICD.match(code)
    if not m:
        return None
    key = m.group(1) + m.group(2)
    for a, b, label in ICD_CHAPTERS:
        if a <= key <= b:
            return label, f"{a}-{b}"
    return None


def mentions_in_text(text: str):
    for m in TEXT_COND.finditer(text):
        c = norm_cond(m.group(1))
        if len(c) >= 4:
            yield c, m.group(2)


class RareConditions:
    def __init__(self) -> None:
        self.patients: dict[str, set] = {}
        self.codes: dict[str, str] = {}
        self.rare: dict[str, tuple[str, str]] = {}
        self.rx = None

    def add(self, cond: str, code: str | None, who: str) -> None:
        c = norm_cond(cond)
        if len(c) < 4:
            return
        self.patients.setdefault(c, set()).add(who)
        if code and c not in self.codes:
            self.codes[c] = code

    def finalise(self, max_patients: int) -> None:
        if max_patients <= 0:
            return
        for c, who in self.patients.items():
            if len(who) <= max_patients:
                ch = chapter(self.codes.get(c))
                self.rare[c] = ch or ("Other condition", "")
        if self.rare:
            alt = "|".join(re.escape(c) for c in sorted(self.rare, key=len, reverse=True))
            self.rx = re.compile(rf"(?i)(?<![A-Za-z])({alt})(?![A-Za-z])(\s*\(([A-TV-Z]\d{{2}}(?:\.\d{{1,2}})?)\))?")

    def generalise(self, text: str, counts) -> str:
        if not self.rx or not text:
            return text

        def sub(m):
            label, rng = self.rare[m.group(1).lower()]
            counts["RARE_CONDITION"] += 1
            return f"[RARE: {label}]" + (f" ({rng})" if m.group(2) and rng else "")
        return self.rx.sub(sub, text)

    def generalise_code(self, code: str, counts) -> str:
        """A bare ICD code that belongs to a rare condition becomes its chapter range."""
        for c, (label, rng) in self.rare.items():
            if self.codes.get(c) == code and rng:
                counts["RARE_CODE"] += 1
                return rng
        return code
