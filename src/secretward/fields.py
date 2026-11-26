"""Structured fields: decide what a CSV column / JSON key holds, then clean its value.

Two signals, combined:
  * the header or key name (hints in config/rules/headers.txt, token-matched), and
  * the VALUES themselves (shape checks). Values win when they are clear, so a renamed
    column ("Contact#", "Gram/Mohalla", "Naam") is still caught on unseen data.
"""
from __future__ import annotations

import re

from . import dates
from .detect import Ctx, _is_person, sanitize
from .gazetteer import DEVA
from .privacy import age_band, pin_prefix
from .rules import HEADER_HINTS, PLACE_ENDS, PLACE_WORDS

NONPERSON_PATH = {"facility", "hospital", "organization", "organisation", "lab", "panel", "panels",
                  "test", "drug", "rx", "medication", "medicine", "package", "procedure", "department",
                  "diagnosis", "coding", "code", "ward", "system", "unit", "results", "qualification",
                  "type", "class", "category", "export", "schema", "profile", "status"}
PHONE_V = re.compile(r"^\+?[\d\s\-().]{10,16}$")
AADHAAR_V = re.compile(r"^(?:\d{4}[\s-]?\d{4}[\s-]?\d{4}|[Xx*]{4}[\s-]?[Xx*]{4}[\s-]?\d{4})$")
ABHA_V = re.compile(r"^\d{2}-?\d{4}-?\d{4}-?\d{4}$")
PIN_V = re.compile(r"^[1-8]\d{5}$")
AGE_V = re.compile(r"^\s*(\d{1,3})\s*([^\d]*)$")


def key_tokens(key: str) -> tuple[list[str], str]:
    k = re.sub(r"([a-z])([A-Z])", r"\1 \2", key)
    toks = [t.lower() for t in re.split(r"[\s_\-/.#()'’:]+", k) if t]
    return toks, "".join(toks)


def hint_type(key: str) -> str | None:
    toks, glued = key_tokens(key)
    for typ, hints in HEADER_HINTS:
        for h in hints:
            if h.startswith("="):
                if glued == h[1:].replace("_", "") or (len(toks) == 1 and toks[0] == h[1:]):
                    return typ
            elif h in toks or (len(h) >= 6 and h in glued):
                return typ
    return None


def value_type(values: list[str]) -> str | None:
    vals = [v.strip() for v in values if isinstance(v, str) and v.strip()]
    if not vals:
        return None

    def share(pred):
        return sum(1 for v in vals if pred(v)) / len(vals)
    digits = lambda v: re.sub(r"\D", "", v)  # noqa: E731
    if share(lambda v: bool(ABHA_V.match(v)) and len(digits(v)) == 14) >= 0.6:
        return "ABHA"
    if share(lambda v: bool(AADHAAR_V.match(v))) >= 0.6:
        return "AADHAAR"
    if share(lambda v: bool(PHONE_V.match(v)) and len(digits(v)) in (10, 11, 12) and digits(v)[-10] in "6789") >= 0.6:
        return "PHONE"
    if share(lambda v: "@" in v and "." in v.split("@")[-1]) >= 0.6:
        return "EMAIL"
    if share(lambda v: bool(PIN_V.match(v))) >= 0.8:
        return "PIN"
    uniq = len(set(vals)) / len(vals)
    if len(vals) >= 3 and share(place_like) >= 0.6:
        return "PLACE"
    if len(vals) >= 3 and uniq >= 0.6 and share(lambda v: _is_person(v) and not v.lower().startswith("dr")
                                                 and len(v.split()) >= 2) >= 0.7:
        return "NAME_LIKE"
    return None


def place_like(v: str) -> bool:
    toks = re.findall(r"[A-Za-z]+", v)
    if not toks or len(toks) > 3 or not v[:1].isupper() or any(c.isdigit() for c in v):
        return False
    low = [t.lower() for t in toks]
    return bool(set(low) & PLACE_WORDS) or (low[-1].endswith(PLACE_ENDS) and len(low[-1]) > 4)


def classify(key: str, values: list, path: tuple = ()) -> str:
    h = hint_type(key)
    v = value_type([x for x in values if isinstance(x, str)])
    path_toks = set()
    for p in path:
        path_toks.update(key_tokens(str(p))[0])
    if h == "NAME" and path_toks & NONPERSON_PATH:
        h = None
    if v in ("PHONE", "AADHAAR", "ABHA", "EMAIL") and h not in ("PATIENTID", "OTHERID"):
        return v
    if h:
        return h
    if v == "PIN":
        return "PIN"
    if v == "PLACE":
        return "VILLAGE"
    if v == "NAME_LIKE" and not (path_toks & NONPERSON_PATH):
        return "NAME"
    return "TEXT"


REL_PREFIX = re.compile(r"^\s*((?:[SDWC]/[Oo]|[Ss]on of|[Ww]ife of|[Dd]aughter of)\.?\s*)", re.I)


def clean_field(typ: str, value, ctx: Ctx, patient_slot: bool = False):
    """Clean one structured value. Keeps JSON types where the value stays meaningful."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and typ not in ("AGE", "PHONE", "AADHAAR", "PIN", "PATIENTID", "OTHERID", "ABHA"):
        return value
    s = str(value)
    if not s.strip():
        return value
    if typ == "MEDICAL":
        return sanitize(s, ctx) if re.search(r"\d{5,}|@", s) else value
    if typ == "NAME":
        if s.strip().lower().startswith(("dr ", "dr.")):
            return value
        if not _is_person(s) and not DEVA.search(s):
            return sanitize(s, ctx)
        ctx.counts["PATIENT_NAME"] += 1
        if patient_slot and ctx.pseudonym and not ctx.used_pseudonym:
            ctx.used_pseudonym = True
            return ctx.pseudonym
        return "[NAME]"
    if typ == "RELNAME":
        m = REL_PREFIX.match(s)
        ctx.counts["RELATIVE_NAME"] += 1
        return (m.group(1) if m else "") + "[NAME]"
    if typ in ("PHONE", "AADHAAR", "ABHA", "PAN", "EMAIL"):
        ctx.counts[typ] += 1
        return f"[{typ}]"
    if typ == "PATIENTID":
        ctx.counts["MRN"] += 1
        if ctx.pseudonym:
            ctx.used_pseudonym = True
            return ctx.pseudonym
        return "[ID]"
    if typ == "OTHERID":
        ctx.counts["ID"] += 1
        return "[ID]"
    if typ == "DOB":
        ctx.counts["DOB"] += 1
        return "[DOB]"
    if typ == "AGE":
        m = AGE_V.match(s)
        if m and int(m.group(1)) <= 120:
            ctx.counts["AGE_BANDED"] += 1
            return age_band(int(m.group(1))) + (m.group(2) if m.group(2).strip() else "")
        return sanitize(s, ctx)
    if typ in ("ADDRESS", "VILLAGE", "TEHSIL"):
        ctx.counts["ADDRESS"] += 1
        return "[ADDRESS]"
    if typ == "PIN":
        ctx.counts["PIN"] += 1
        return pin_prefix(s)
    if typ in ("GENDER", "DISTRICT", "RELATION", "DOCTOR"):
        return value
    if isinstance(value, (int, float)):
        return value
    return sanitize(s, ctx)


def harvest_value(typ: str, value, gaz, strong: bool = False) -> None:
    """Pass 1: learn names, places and ID numbers from a typed field."""
    if value is None or isinstance(value, bool):
        return
    s = str(value)
    if typ == "MEDICAL":
        gaz.medical.update(t.lower() for t in re.findall(r"[A-Za-z]{3,}", s))
    elif typ in ("NAME", "RELNAME"):
        n = REL_PREFIX.sub("", s)
        if _is_person(n) or DEVA.search(n):
            gaz.add_name(n, strong=strong)
    elif typ in ("VILLAGE", "ADDRESS", "TEHSIL") and len(s) <= 40 and "," not in s:
        gaz.add_place(s)
    elif typ in ("PATIENTID", "OTHERID", "AADHAAR", "ABHA", "PHONE"):
        gaz.add_id(s)
    elif typ == "PIN" and PIN_V.match(s.strip()):
        gaz.pins.add(s.strip())
    elif typ == "DISTRICT":
        gaz.districts.add(s.strip().lower())
