"""Text normalisation that mirrors what the scorer does BEFORE it counts leaks.

The scorer folds look-alike letters, strips zero-width characters and converts Indian
digits to ASCII. If we detect on raw text, "R​amesh" or "Rаmesh" (Cyrillic а)
slip past our rules but the scorer still sees "Ramesh". So we normalise first.
"""
from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
# Cyrillic / Greek letters that look like Latin ones
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
})
DEVA_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH.sub("", text)
    text = text.translate(HOMOGLYPHS)
    return text.translate(DEVA_DIGITS)
