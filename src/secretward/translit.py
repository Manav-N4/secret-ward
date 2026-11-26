"""Tiny Devanagari -> Latin transliterator (standard library only).

Used only to build the cross-script phonetic key (मोहम्मद ~ Mohammad). It does not need
to be a perfect romanisation, just consistent. Keeping it in-house removes our only
third-party dependency, so nothing can fail to install on the evaluation machine.
"""
from __future__ import annotations

VOWELS = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ii", "उ": "u", "ऊ": "uu", "ऋ": "ri", "ए": "e",
          "ऐ": "ai", "ओ": "o", "औ": "au", "ऑ": "o", "ऍ": "e"}
MATRAS = {"ा": "aa", "ि": "i", "ी": "ii", "ु": "u", "ू": "uu", "ृ": "ri", "े": "e", "ै": "ai",
          "ो": "o", "ौ": "au", "ॉ": "o", "ॅ": "e"}
CONSONANTS = {"क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j",
              "झ": "jh", "ञ": "n", "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t",
              "थ": "th", "द": "d", "ध": "dh", "न": "n", "प": "p", "फ": "ph", "ब": "b", "भ": "bh",
              "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh", "ष": "sh", "स": "s",
              "ह": "h", "ळ": "l", "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh",
              "फ़": "f", "य़": "y"}
NUKTA, VIRAMA = "़", "्"
NASAL = {"ं": "n", "ँ": "n", "ः": "h"}
NUKTA_FORMS = {"क": "क़", "ख": "ख़", "ग": "ग़", "ज": "ज़", "ड": "ड़", "ढ": "ढ़", "फ": "फ़", "य": "य़"}


def deva_to_latin(text: str) -> str:
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in CONSONANTS:
            if i + 1 < n and text[i + 1] == NUKTA:
                ch = NUKTA_FORMS.get(ch, ch)
                i += 1
            out.append(CONSONANTS[ch])
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt in MATRAS:
                out.append(MATRAS[nxt])
                i += 1
            elif nxt == VIRAMA:
                i += 1
            else:
                out.append("a")              # inherent vowel
        elif ch in VOWELS:
            out.append(VOWELS[ch])
        elif ch in NASAL:
            out.append(NASAL[ch])
        else:
            out.append(ch)
        i += 1
    return "".join(out)
