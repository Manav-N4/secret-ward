"""Runtime gazetteer: names, villages and ID numbers harvested from THIS input.

Nothing here is hardcoded. Pass 1 reads every structured name/village/ID field in the
dataset; pass 2 uses what it learned to find the same people inside free text, file
names and JSON keys, in Latin and Devanagari. New hidden patients are learned the same way.
"""
from __future__ import annotations

import re

from .rules import GENERIC_TOKENS, SAFE_WORDS
from .translit import deva_to_latin

DEVA = re.compile(r"[ऀ-ॿ]")
TOKEN = re.compile(r"[A-Za-zऀ-ॿ][A-Za-zऀ-ॿ'’]*")
ALIASES = {"mohd": "mohammad", "md": "mohammad", "mohammed": "mohammad", "muhammad": "mohammad",
           "mohamad": "mohammad", "mohammad": "mohammad"}


def skeleton(token: str) -> str:
    """Cross-script phonetic key: मोहम्मद, Mohammad, Mohd -> 'mhmd'. Coarse on purpose."""
    t = token.strip(".'’").lower()
    if DEVA.search(t):
        t = deva_to_latin(t).lower()
        t = t[:-1] if t.endswith("a") and len(t) > 3 else t
    t = ALIASES.get(t, t)
    t = re.sub(r"[^a-z]", "", t)
    for a, b in (("sh", "s"), ("ph", "f"), ("bh", "b"), ("dh", "d"), ("th", "t"), ("kh", "k"),
                 ("gh", "g"), ("chh", "c"), ("ch", "c"), ("jh", "j"), ("w", "v"), ("z", "j"),
                 ("q", "k"), ("ee", "i"), ("oo", "u"), ("y", "i")):
        t = t.replace(a, b)
    if not t:
        return ""
    head, rest = t[0], re.sub(r"[aeiou]", "", t[1:])
    rest = re.sub(r"h(?=.)|h$", "", rest)
    return re.sub(r"(.)\1+", r"\1", head + rest)


def name_tokens(name: str) -> list[str]:
    return [t for t in TOKEN.findall(name)]


def identifying(tok: str) -> bool:
    low = tok.lower().strip(".")
    return len(low) >= 2 and low not in GENERIC_TOKENS and low not in SAFE_WORDS


class Gazetteer:
    def __init__(self) -> None:
        self.latin_full: set[str] = set()
        self.latin_tokens: set[str] = set()
        self.deva_strings: set[str] = set()
        self.pair_skeletons: set[tuple[str, str]] = set()
        self.places: set[str] = set()
        self.id_cores: set[str] = set()
        self.pins: set[str] = set()
        self.districts: set[str] = set()
        self.medical: set[str] = set()
        self.strong_tokens: set[str] = set()
        self._rx = None

    # ------------------------------------------------------------------ learning
    def add_name(self, name: str, strong: bool = False) -> None:
        name = re.sub(r"^\s*(?:[SDWC]/[Oo]|[Ll]ate|Smt\.?|Shri|Mr\.?|Mrs\.?)\s+", "", name.strip())
        toks = [t for t in name_tokens(name) if identifying(t)]
        if not toks:
            return
        if any(DEVA.search(t) for t in toks):
            self.deva_strings.add(" ".join(toks))
            self.deva_strings.update(t for t in toks if len(t) >= 2)
        else:
            low = [t.lower().strip(".'’") for t in toks]
            if len(low) >= 2:
                self.latin_full.add(" ".join(low))
            self.latin_tokens.update(t for t in low if len(t) >= 3)
            if strong:
                self.strong_tokens.update(low)
        sk = [skeleton(t) for t in toks]
        for a, b in zip(sk, sk[1:]):
            if len(a) >= 2 and len(b) >= 2:
                self.pair_skeletons.add((a, b))

    def add_place(self, place: str) -> None:
        p = place.strip()
        if (len(p) >= 3 and p.lower() not in SAFE_WORDS and p.lower() not in self.districts
                and not re.match(r"(?i)(ward|bed|room|opd|icu)\b", p)):
            self.places.add(p)

    def add_id(self, value: str) -> None:
        for core in re.findall(r"\d{5,}", value):
            self.id_cores.add(core.lstrip("0") or core)

    # ------------------------------------------------------------------ matching
    def compile(self) -> None:
        med = self.medical - self.strong_tokens
        self.latin_tokens = {t for t in self.latin_tokens if t not in med and t not in self.districts}
        self.latin_full = {f for f in self.latin_full if not (set(f.split()) & med)}
        self.places = {p for p in self.places if p.lower() not in self.districts and p.lower() not in med}
        latin = sorted(self.latin_full | self.latin_tokens, key=len, reverse=True)
        deva = sorted(self.deva_strings, key=len, reverse=True)
        places = sorted(self.places, key=len, reverse=True)
        lat_alt = "|".join(re.escape(x).replace(r"\ ", r"[\s_]+") for x in latin) or "(?!x)x"
        self.rx_latin = re.compile(rf"(?<![A-Za-z])(?:{lat_alt})(?![A-Za-z])", re.I)
        deva_alt = "|".join(re.escape(x).replace(r"\ ", r"\s+") for x in deva) or "(?!x)x"
        self.rx_deva = re.compile(rf"(?<![ऀ-ॿ])(?:{deva_alt})(?![ऀ-ॿ])")
        pl_alt = "|".join(re.escape(x).replace(r"\ ", r"[\s_]+") for x in places) or "(?!x)x"
        self.rx_place = re.compile(rf"(?<![A-Za-zऀ-ॿ])(?:{pl_alt})(?![A-Za-zऀ-ॿ])", re.I)
