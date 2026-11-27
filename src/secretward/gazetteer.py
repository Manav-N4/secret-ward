"""Runtime gazetteer: names, villages and ID numbers harvested from THIS input.

Nothing here is hardcoded. Pass 1 reads every structured name/village/ID field in the
dataset; pass 2 uses what it learned to find the same people inside free text, file
names and JSON keys, in Latin and Devanagari. New hidden patients are learned the same way.
"""
from __future__ import annotations

import re
from functools import lru_cache

from .rules import GENERIC_TOKENS, SAFE_WORDS
from .translit import deva_to_latin

DEVA = re.compile(r"[ऀ-ॿ]")
TOKEN = re.compile(r"[A-Za-zऀ-ॿ][A-Za-zऀ-ॿ'’]*")
ALIASES = {"mohd": "mohammad", "md": "mohammad", "mohammed": "mohammad", "muhammad": "mohammad",
           "mohamad": "mohammad", "mohammad": "mohammad"}


@lru_cache(maxsize=200_000)
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
        """Build LINEAR-time matchers.

        One regex alternation of every learned name costs O(text x vocabulary): Python's
        regex engine tries each alternative at each position, so runtime grew
        quadratically with the number of patients (QA: 200 files 2.5 s, 4,000 files 118 s).
        Instead, entries made only of letters and spaces go into hash sets and are matched
        word-sequence by word-sequence; the rare entries with other characters keep a
        small regex. Same boundaries, same longest-match-first rule, same output.
        """
        med = self.medical - self.strong_tokens
        self.latin_tokens = {t for t in self.latin_tokens if t not in med and t not in self.districts}
        self.latin_full = {f for f in self.latin_full if not (set(f.split()) & med)}
        self.places = {p for p in self.places if p.lower() not in self.districts and p.lower() not in med}
        self.m_latin = _Matcher(self.latin_full | self.latin_tokens, r"[A-Za-z]+", r"[\s_]+", True, "A-Za-z")
        self.m_deva = _Matcher(self.deva_strings, r"[\u0900-\u097F]+", r"\s+", False, "\u0900-\u097F")
        self.m_place = _Matcher(self.places, r"[A-Za-z\u0900-\u097F]+", r"[\s_]+", True, "A-Za-z\u0900-\u097F")


class _Matcher:
    """Longest-first, word-aligned matching of a phrase list in linear time."""

    def __init__(self, entries, word: str, gap: str, fold: bool, letters: str) -> None:
        self.word = re.compile(word)
        self.gap = re.compile(gap)
        self.fold = fold
        wre = re.compile(rf"^{word}(?:{gap}{word})*$")
        simple, other = set(), []
        for e in entries:
            if wre.match(e):
                simple.add(" ".join(self.word.findall(e.lower() if fold else e)))
            else:
                other.append(e)
        self.phrases = simple
        self.max_words = max((len(p.split(" ")) for p in simple), default=0)
        other = sorted(other, key=len, reverse=True)
        alt = "|".join(re.escape(x).replace(r"\ ", gap) for x in other)
        self.rx_other = re.compile(rf"(?<![{letters}])(?:{alt})(?![{letters}])", re.I if fold else 0) if other else None

    def subn(self, repl: str, text: str):
        n_total = 0
        if self.rx_other is not None:
            text, n = self.rx_other.subn(repl, text)
            n_total += n
        if not self.phrases or not text:
            return text, n_total
        runs = list(self.word.finditer(text))
        out, last, i = [], 0, 0
        while i < len(runs):
            hit = 0
            for n in range(min(self.max_words, len(runs) - i), 0, -1):
                if any(not self.gap.fullmatch(text[runs[k].end():runs[k + 1].start()]) for k in range(i, i + n - 1)):
                    continue
                key = " ".join((r.group(0).lower() if self.fold else r.group(0)) for r in runs[i:i + n])
                if key in self.phrases:
                    hit = n
                    break
            if hit:
                out.append(text[last:runs[i].start()])
                out.append(repl)
                last = runs[i + hit - 1].end()
                n_total += 1
                i += hit
            else:
                i += 1
        out.append(text[last:])
        return "".join(out), n_total
