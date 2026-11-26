"""Patient linking: which records belong to the same person?

1. Strong keys (hospital IDs, phone, Aadhaar, ABHA) join records with union-find.
2. Every join is checked first: different gender, ages more than 3 years apart, or
   names that share no sound-alike token BLOCK the merge. This stops the classic
   chain error (A~B, B~C, so A=C) and keeps same-name different people apart.
3. Records with only a name (Hindi prescriptions, nursing notes) join a cluster only if
   exactly ONE cluster fits name + gender + age (+ relative). Otherwise: null.
A wrong link costs more than a missing one, so every rule leans towards "don't merge".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .gazetteer import identifying, name_tokens, skeleton

MALE = {"m", "male", "पुरुष", "purush", "man"}
FEMALE = {"f", "female", "महिला", "स्त्री", "mahila", "woman"}


def norm_gender(v) -> str | None:
    s = str(v).strip().lower()
    return "M" if s in MALE else "F" if s in FEMALE else None


def name_key(name: str) -> frozenset:
    return frozenset(s for s in (skeleton(t) for t in name_tokens(name) if identifying(t)) if len(s) >= 2)


@dataclass
class Evidence:
    keys: set = field(default_factory=set)
    names: set = field(default_factory=set)      # frozensets of skeletons
    relatives: set = field(default_factory=set)
    genders: set = field(default_factory=set)
    ages: list = field(default_factory=list)

    def has_patient(self) -> bool:
        return bool(self.keys or self.names)


def norm_id(v: str) -> str | None:
    s = re.sub(r"[^A-Za-z0-9]", "", str(v)).upper()
    return s if len(re.sub(r"\D", "", s)) >= 5 else None


class Linker:
    def __init__(self, units: list) -> None:
        self.units = units                       # list of (unit_id, Evidence), deterministic order
        self.parent = list(range(len(units)))
        self.cl = {i: self._summary(ev) for i, (_, ev) in enumerate(units)}

    @staticmethod
    def _summary(ev: Evidence) -> dict:
        return {"names": set(ev.names), "rel": set(ev.relatives), "g": set(ev.genders),
                "ages": list(ev.ages), "keys": set(ev.keys)}

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    @staticmethod
    def _conflict(a: dict, b: dict) -> bool:
        if a["g"] and b["g"] and not (a["g"] & b["g"]):
            return True
        if a["ages"] and b["ages"] and min(abs(x - y) for x in a["ages"] for y in b["ages"]) > 3:
            return True
        if a["names"] and b["names"]:
            ta = set().union(*a["names"])
            tb = set().union(*b["names"])
            if not (ta & tb):
                return True
        return False

    def union(self, i: int, j: int) -> None:
        ri, rj = self.find(i), self.find(j)
        if ri == rj or self._conflict(self.cl[ri], self.cl[rj]):
            return
        lo, hi = min(ri, rj), max(ri, rj)
        self.parent[hi] = lo
        a, b = self.cl[lo], self.cl.pop(hi)
        for k in ("names", "rel", "g", "keys"):
            a[k] |= b[k]
        a["ages"] += b["ages"]

    def run(self) -> dict:
        by_key: dict[str, list[int]] = {}
        for i, (_, ev) in enumerate(self.units):
            for k in ev.keys:
                by_key.setdefault(k, []).append(i)
        for k in sorted(by_key):
            members = by_key[k]
            for j in members[1:]:
                self.union(members[0], j)
        # weak attach: name-only records
        roots = {self.find(i) for i, (_, ev) in enumerate(self.units) if ev.keys}
        for i, (_, ev) in enumerate(self.units):
            if ev.keys or not ev.names:
                continue
            me = self._summary(ev)
            cands = []
            for r in sorted(roots):
                c = self.cl[r]
                if self._conflict(me, c):
                    continue
                ctoks = set().union(*c["names"]) if c["names"] else set()
                strong_name = any(len(n) >= 2 and n <= ctoks for n in ev.names)
                rel_ok = ev.relatives and c["rel"] and any(
                    n <= set().union(*c["rel"]) for n in ev.relatives if n)
                one_name = any(n and n <= ctoks for n in ev.names)
                if strong_name or (one_name and rel_ok):
                    cands.append(r)
            if len(cands) == 1:
                self.union(cands[0], i)
        out = {}
        for i, (uid, ev) in enumerate(self.units):
            r = self.find(i)
            c = self.cl[r]
            if not c["keys"]:
                out[uid] = None
                continue
            members_keys = sorted(c["keys"])
            out[uid] = "|".join(members_keys)     # canonical cluster key (HMAC'd later)
        return out
