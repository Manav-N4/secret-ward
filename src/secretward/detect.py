"""The free-text sanitizer: finds personal data in a string and replaces it.

Layers, in order (each one is a separate function so it can be tested alone):
  0. normalise (mirror the scorer)          5. dates: DOB removed, other dates shifted
  1. protect doctor spans ("Dr. Ramesh")    6. ages -> bands, addresses -> district + PIN prefix
  2. decode + clean base64 payloads         7. names: labels, relatives, triggers, honorifics,
  3. emails, PAN, hospital/insurance IDs       gazetteer (Latin + Devanagari + cross-script),
  4. phones / Aadhaar / ABHA (digit view)      phone proximity
                                            8. restore doctor spans
Everything returns typed placeholders such as [NAME] or [PHONE], never fake values.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass, field

from . import dates
from .gazetteer import DEVA, Gazetteer, skeleton
from .normalize import normalize
from .privacy import age_band, band_text, pin_prefix
from .rules import (DOCTOR_TITLES, GENERIC_TOKENS, HON_AFTER, HON_BEFORE, LABELS_NAME, RELATIONS, SAFE_WORDS,
                    TRIGGERS)

L = r"[A-Z][a-zA-Z'’]*\.?"                       # one Latin name token (Title or CAPS)
LATIN_SPAN = rf"{L}(?: {L}){{0,3}}"
DV = r"[ऀ-ॿ]+"
DEVA_SPAN = rf"{DV}(?: {DV}){{0,3}}"
SPAN = rf"(?:{LATIN_SPAN}|{DEVA_SPAN})"
DEVA_STOP = {"आयु", "उम्र", "को", "का", "की", "के", "ने", "है", "हैं", "ग्राम", "पिता", "पति", "तारीख",
             "वर्ष", "से", "में", "और", "पता", "मो", "मोबाइल", "जिला", "तहसील", "निवासी", "उम्र:"}
ALT = lambda words: "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in words)  # noqa: E731


@dataclass
class Ctx:
    gaz: Gazetteer
    shift: int = 0
    conv: str = "DMY"
    pseudonym: str | None = None
    used_pseudonym: bool = False
    counts: Counter = field(default_factory=Counter)
    found_names: list = field(default_factory=list)   # patient-label names (for linking)
    own_ids: set = field(default_factory=set)         # this record's own hospital IDs
    band: tuple | None = None                         # the patient's single age band, if known
    hide_location: bool = False                       # small group: district + PIN prefix hidden too

    def age_text(self, age: int) -> str:
        if self.band and self.band[0] <= age <= self.band[1]:
            return band_text(self.band)
        return age_band(age)


# ---------------------------------------------------------------------------- helpers
def _trim_span(span: str) -> str:
    """Cut a captured name before the first word that can't be part of a name."""
    out = []
    for tok in span.split(" "):
        low = tok.lower().strip(".:,")
        if low in SAFE_WORDS or low in DEVA_STOP or low in DOCTOR_TITLES:
            break
        out.append(tok)
    return " ".join(out)


def _is_person(span: str) -> bool:
    toks = [t.strip(".,:") for t in span.split()]
    if not toks or len(toks) > 4:
        return False
    if any(t.lower() in SAFE_WORDS for t in toks):
        return False
    return all(t[:1].isupper() or DEVA.search(t) for t in toks)


def _replace_span(ctx: Ctx, kind: str, patient: bool = False) -> str:
    ctx.counts[kind] += 1
    if patient and ctx.pseudonym and not ctx.used_pseudonym:
        ctx.used_pseudonym = True
        return ctx.pseudonym
    return "[NAME]"


# ---------------------------------------------------------------------------- 1. doctors
DOC_RX = re.compile(rf"(?<![A-Za-z])(?:{ALT(sorted(DOCTOR_TITLES, key=len, reverse=True))})\s*(?:{SPAN})", re.I)


ASHA_RX = re.compile(r"(?<![A-Za-z])ASHA(?:\s+(?:worker|didi|karyakarta|sahayogini|kaaryakarta|team|visit))?(?![A-Za-z])")


def protect_doctors(text: str):
    keep = []

    def sub(m):
        keep.append(m.group(0))
        return f"\x00{len(keep) - 1}\x00"
    text = DOC_RX.sub(sub, text)
    return ASHA_RX.sub(lambda m: sub(m) if not re.match(r"ASHA\s+[A-Z]{2,}", m.group(0)) else m.group(0), text), keep


def restore(text: str, keep: list) -> str:
    return re.sub(r"\x00(\d+)\x00", lambda m: keep[int(m.group(1))], text)


# ---------------------------------------------------------------------------- 2. base64
B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def clean_base64(text: str, ctx: Ctx) -> str:
    def sub(m):
        s = m.group(0)
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
            dec = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return s
        if sum(c.isprintable() or c in "\n\r\t" for c in dec) < 0.9 * len(dec):
            return s
        cleaned = sanitize(dec, ctx, _nested=True)
        ctx.counts["BASE64"] += cleaned != dec
        return base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
    return B64.sub(sub, text)


# ---------------------------------------------------------------------------- 3-4. ids, digits
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
ID_TOKEN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{1,6}(?:[-/][A-Za-z]{1,4})*[-/]?(?:\d{1,4}[-/])*\d{5,}(?![A-Za-z0-9])")
MASKED_AADHAAR = re.compile(r"(?<![A-Za-z0-9])[Xx*]{4}[\s-]?[Xx*]{4}[\s-]?\d{4}(?!\d)")
MASKED_PHONE = re.compile(r"(?<![A-Za-z0-9])\d{2}[Xx*]{4,6}\d{2,4}(?![A-Za-z0-9])")
DIGITS = re.compile(r"(?<![A-Za-z0-9.])\+?\d[\d \-().]{7,22}\d(?![0-9])")
UNIT_AFTER = re.compile(r"^\s*(?:mg|ml|mcg|g\b|gm|iu|units?|mmhg|mm|cm|kg|%|/min|bpm|cells|lakh|/cumm|/ul)", re.I)


def clean_ids(text: str, ctx: Ctx) -> str:
    text, n = EMAIL.subn("[EMAIL]", text); ctx.counts["EMAIL"] += n
    text, n = MASKED_AADHAAR.subn("[AADHAAR]", text); ctx.counts["AADHAAR"] += n
    text, n = MASKED_PHONE.subn("[PHONE]", text); ctx.counts["PHONE"] += n
    text, n = PAN.subn("[PAN]", text); ctx.counts["PAN"] += n
    def idsub(m):
        ctx.counts["ID"] += 1
        key = re.sub(r"[^A-Za-z0-9]", "", m.group(0)).upper()
        if ctx.pseudonym and key in ctx.own_ids:
            ctx.used_pseudonym = True
            return ctx.pseudonym
        return "[ID]"
    return ID_TOKEN.sub(idsub, text)


def clean_digits(text: str, ctx: Ctx) -> str:
    def sub(m):
        s = m.group(0)
        if UNIT_AFTER.match(text[m.end():m.end() + 8]):
            return s
        if dates.looks_like_date(s) and not re.fullmatch(r"[\d\s\-+()]+", s.replace("/", "x")):
            return s
        parts = re.findall(r"\d+", s)
        if re.fullmatch(r"\d{1,7}\s*-\s*\d{1,7}", s.strip()) and not (
                [len(x) for x in parts] == [5, 5] and parts[0][0] in "6789"):
            return s                       # a range such as 150000-410000, not an ID
        d = re.sub(r"\D", "", s)
        if len(d) == 12 and not (d.startswith("91") and d[2] in "6789" and ("+" in s or s.startswith("91 "))):
            ctx.counts["AADHAAR"] += 1
            return "[AADHAAR]"
        if len(d) == 14:
            ctx.counts["ABHA"] += 1
            return "[ABHA]"
        core = d[2:] if d.startswith("91") and len(d) == 12 else d[1:] if d.startswith("0") and len(d) == 11 else d
        if len(core) == 10 and core[0] in "6789":
            ctx.counts["PHONE"] += 1
            return "[PHONE]"
        if (d.lstrip("0") or d) in ctx.gaz.id_cores:
            ctx.counts["ID"] += 1
            return "[ID]"
        return s
    text = DIGITS.sub(sub, text)

    # bare digit runs that are known ID cores (e.g. "Anita_Sharma_010565")
    def core_sub(m):
        d = m.group(0)
        if (d.lstrip("0") or d) in ctx.gaz.id_cores:
            ctx.counts["ID"] += 1
            return "[ID]"
        if len(d) == 10 and d[0] in "6789":
            ctx.counts["PHONE"] += 1
            return "[PHONE]"
        return d
    return re.sub(r"(?<![0-9])\d{5,}(?![0-9])", core_sub, text)


# ---------------------------------------------------------------------------- 5. dates
DOB_RX = re.compile(r"(?i)(\b(?:dob|d\.o\.b\.?|date of birth|birth date|janm tithi)|जन्म\s*तिथि)(\s*[:\-]?\s*)([^\n,;|]{6,30})")


def clean_dates(text: str, ctx: Ctx) -> str:
    def dob(m):
        if dates.looks_like_date(m.group(3)):
            ctx.counts["DOB"] += 1
            return m.group(1) + m.group(2) + "[DOB]"
        return m.group(0)
    text = DOB_RX.sub(dob, text)
    text, n = dates.shift_text(text, ctx.shift, ctx.conv)
    ctx.counts["DATE_SHIFTED"] += n
    return text


# ---------------------------------------------------------------------------- 6. ages, addresses
AGE_PATTERNS = [
    re.compile(r"(?i)(\bage(?:d)?\s*(?:/\s*sex)?\s*[:\-]?\s*)(\d{1,3})(?!\d)"),
    re.compile(r"(?i)(\bumar\s*[:\-]?\s*)(\d{1,3})(?!\d)"),
    re.compile(r"((?:आयु|उम्र)\s*[:\-]?\s*)(\d{1,3})(?!\d)"),
    re.compile(r"(?i)()(?<![x×]\s)(?<![\d.])(\d{1,3})(?=\s*(?:years?|yrs?\.?|y)\s*(?:old|/\s*[MF]\b|\s+[MF]\b|,\s*(?:male|female)))"),
    re.compile(r"(?i)()(?<![\d.])(\d{1,3})(?=\s*/\s*[MF](?![a-z]))"),
    re.compile(r"()(?<![\d.])(\d{1,3})(?=\s*(?:वर्ष|साल)(?!\s*से))"),
]


def clean_ages(text: str, ctx: Ctx) -> str:
    for rx in AGE_PATTERNS:
        def sub(m, text=text):
            if text[max(0, m.start(2) - 1):m.start(2)] in ("-", "+") or m.group(0).endswith("+"):
                return m.group(0)          # already a band (e.g. "30-39"): never band twice
            age = int(m.group(2))
            if age > 120:
                return m.group(0)
            ctx.counts["AGE_BANDED"] += 1
            return m.group(1) + ctx.age_text(age)
        text = rx.sub(sub, text)
    return text


ADDR_LINE = re.compile(r"(?im)^(\s*(?:address|addr|add|pata|residence|पता|निवास)(?:\s*\([^)\n]{0,25}\))?\s*[:\-]\s*)(.+)$")
DISTRICT = re.compile(r"(?i)(?:distt?\.?|district|jila|zila|जिला)\s*[:\-]?\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+)?|[ऀ-ॿ]+)")
PIN6 = re.compile(r"(?<!\d)([1-8]\d{5})(?!\d)")
ADDR_PARTS = re.compile(
    r"(?i)(?<![A-Za-z])(?:h\.?\s?no\.?|house(?:\s*no\.?)?|makan\s*no\.?|flat|plot)\s*[:\-]?\s*[\w/-]+"
    r"|(?<![A-Za-z])(?:gram|village|vill\.?|mohalla|mohalla:|ward\s+\d+,|tehsil|teh\.?|post|p\.o\.)\s*[:\-]?\s*(?:[A-Z][a-z]+(?:\s[A-Z][a-z]+)?)"
    r"|(?<![A-Za-z])(?:near|opp\.?|opposite|behind|beside)\s+(?:[A-Za-z]+\s){0,3}[A-Za-z]+"
    r"|(?:ग्राम|गांव|गाँव|मोहल्ला|तहसील|मकान\s*नं\.?)\s*[:\-]?\s*[ऀ-ॿ\d]+(?:\s[ऀ-ॿ]+)?"
    r"|(?:[ऀ-ॿ]+\s){1,3}के\s+(?:पास|पीछे|सामने|बगल\s+में|बगल)")   # Hindi landmarks: "... के पीछे"


def clean_address(text: str, ctx: Ctx) -> str:
    def line(m):
        body = m.group(2)
        dm = DISTRICT.search(body)
        pm = PIN6.search(body)
        parts = ["[ADDRESS]"]
        if dm and not ctx.hide_location:
            parts.append(dm.group(0).strip())
        out = ", ".join(parts)
        if pm and not ctx.hide_location:
            out += " - " + pin_prefix(pm.group(1))
        ctx.counts["ADDRESS"] += 1
        return m.group(1) + out
    text = ADDR_LINE.sub(line, text)
    text, n = ADDR_PARTS.subn("[ADDRESS]", text); ctx.counts["ADDRESS"] += n
    text, n = ctx.gaz.rx_place.subn("[ADDRESS]", text); ctx.counts["VILLAGE"] += n
    for pin in sorted(ctx.gaz.pins):
        text, n = re.subn(rf"(?<!\d){pin}(?!\d)", "[PIN]" if ctx.hide_location else pin_prefix(pin), text)
        ctx.counts["PIN"] += n
    text = re.sub(r"(?i)(\bpin(?:\s*code)?\s*[:\-]?\s*)(\d{6})(?!\d)",
                  lambda m: m.group(1) + ("[PIN]" if ctx.hide_location else pin_prefix(m.group(2))), text)
    if ctx.hide_location:
        text = DISTRICT.sub("[ADDRESS]", text)
    return text


# ---------------------------------------------------------------------------- 7. names
LABEL_RX = re.compile(rf"(?<![A-Za-z])((?i:{ALT(LABELS_NAME)})\s*[:\-–]\s*)({SPAN})")
REL_RX = re.compile(rf"(?<![A-Za-z/])((?i:{ALT(RELATIONS)})\.?\s*[:\-]?\s*(?:(?i:late|shri|smt|श्री|स्व\.)\.?\s+)?)({SPAN})")
TRIG_RX = re.compile(rf"(?<![A-Za-z])((?i:{ALT(TRIGGERS)})\s*[:\-]?\s*(?:\(\s*)?)({SPAN})")
HON_B_RX = re.compile(rf"(?<![A-Za-z])((?i:{ALT(sorted(HON_BEFORE, key=len, reverse=True))})\.?\s+)({SPAN})")
HON_A_RX = re.compile(rf"(?<![A-Za-zऀ-ॿ])({L}(?: {L}){{0,2}}|{DV}(?: {DV})?)(\s+(?i:{ALT(sorted(HON_AFTER, key=len, reverse=True))}))(?![A-Za-zऀ-ॿ])")
PRE_REL_RX = re.compile(rf"(?<![A-Za-z\u0900-\u097F])({LATIN_SPAN}|{DEVA_SPAN}),?\s+(?=(?i:[SDW]/o|पत्नी|पुत्र|पुत्री)\b)")
_GEN = "|".join(re.escape(g.rstrip(".")) for g in sorted(GENERIC_TOKENS, key=len, reverse=True))
GEN_AFTER = re.compile(rf"\[NAME\](?:[\s_]+(?i:{_GEN})\.?(?![A-Za-z]))+")
GEN_BEFORE = re.compile(rf"(?<![A-Za-z])(?:(?i:{_GEN})\.?[\s_]+)+\[NAME\]")
# log lines: "14:00 - Parvathi Pandeya - K/C/O ..." (timestamp, a name between dashes)
LOG_LINE = re.compile(rf"(?m)(^\s*\d{{1,2}}:\d{{2}}(?:\s*[AaPp][Mm])?\s*[-–]\s*)({LATIN_SPAN}|{DEVA_SPAN})(?=\s*[-–:,]\s)")
# a name right before a clinical history marker: "Zenab Bano - K/C/O bell's palsy"
BEFORE_CLINICAL = re.compile(rf"(?<![A-Za-z])({LATIN_SPAN})(?=\s*[-–:,]\s*(?i:k/c/o|c/o|h/o|known case)\b)")
NEAR_PHONE = re.compile(r"(?<![A-Za-z])([A-Z][a-z]+(?: [A-Z][a-z]+){1,2})(?=[^\n\[\]]{0,40}\[PHONE\])")
NONPERSON_BEFORE = ("drug", "test", "medicine", "hospital", "facility", "lab", "doctor", "consultant",
                   "package", "procedure", "file", "company", "insurer", "scheme", "ward", "panel", "user")
RELATIVE_BEFORE = ("father", "husband", "guardian", "mother", "pita", "pati", "relative", "attendant",
                   "spouse", "wife", "son", "daughter", "पिता", "पति")
DEVA_RUN = re.compile(rf"{DV}(?:\s+{DV})+")


def clean_names(text: str, ctx: Ctx) -> str:
    def labeled(m):
        span = _trim_span(m.group(2))
        if not span or not _is_person(span):
            return m.group(0)
        before = text[max(0, m.start() - 20):m.start()].lower()
        rest = m.group(2)[len(span):]
        if any(w in before for w in NONPERSON_BEFORE):
            return m.group(0)
        if any(w in before for w in RELATIVE_BEFORE):
            return m.group(1) + _replace_span(ctx, "RELATIVE_NAME") + rest
        ctx.found_names.append(span)
        return m.group(1) + _replace_span(ctx, "PATIENT_NAME", patient=True) + rest
    text = LABEL_RX.sub(labeled, text)

    def generic(kind):
        def sub(m):
            span = _trim_span(m.group(2))
            if not span or not _is_person(span):
                return m.group(0)
            rest = m.group(2)[len(span):]
            return m.group(1) + _replace_span(ctx, kind) + rest
        return sub
    def pre_rel(m):
        span = m.group(1)
        if not _is_person(span):
            return m.group(0)
        ctx.found_names.append(span)
        return _replace_span(ctx, "PATIENT_NAME", patient=True) + m.group(0)[len(span):]
    text = PRE_REL_RX.sub(pre_rel, text)
    def log_name(m):
        span = _trim_span(m.group(2))
        if not span or not _is_person(span) or span.lower().startswith(("patient", "next", "morning")):
            return m.group(0)
        ctx.found_names.append(span)
        return m.group(1) + _replace_span(ctx, "PATIENT_NAME") + m.group(2)[len(span):]
    text = LOG_LINE.sub(log_name, text)

    def before_clinical(m):
        span = m.group(1)
        if not _is_person(span) or len(span.split()) < 2:
            return m.group(0)
        return _replace_span(ctx, "PATIENT_NAME")
    text = BEFORE_CLINICAL.sub(before_clinical, text)
    text = REL_RX.sub(generic("RELATIVE_NAME"), text)
    text = TRIG_RX.sub(generic("OTHER_NAME"), text)
    text = HON_B_RX.sub(generic("PATIENT_NAME"), text)

    def hon_after(m):
        span = m.group(1)
        if not _is_person(span):
            return m.group(0)
        return _replace_span(ctx, "PATIENT_NAME") + m.group(2)
    text = HON_A_RX.sub(hon_after, text)

    text, n = ctx.gaz.rx_latin.subn("[NAME]", text); ctx.counts["NAME_GAZ"] += n
    text, n = ctx.gaz.rx_deva.subn("[NAME]", text); ctx.counts["NAME_GAZ"] += n

    def deva_pairs(m):  # cross-script: a Devanagari pair whose sound matches a known Latin name
        toks = m.group(0).split()
        sk = [skeleton(t) for t in toks]
        hit = [False] * len(toks)
        for i in range(len(toks) - 1):
            if (sk[i], sk[i + 1]) in ctx.gaz.pair_skeletons:
                hit[i] = hit[i + 1] = True
        if not any(hit):
            return m.group(0)
        ctx.counts["NAME_XSCRIPT"] += 1
        return " ".join("[NAME]" if h else t for t, h in zip(toks, hit))
    text = DEVA_RUN.sub(deva_pairs, text)

    def near_phone(m):
        span = m.group(1)
        if not _is_person(span) or any(t.lower() in ctx.gaz.districts for t in span.split()):
            return span
        ctx.counts["OTHER_NAME"] += 1
        return "[NAME]"
    text = NEAR_PHONE.sub(near_phone, text)
    text = re.sub(r"\[NAME\](?:[\s_]+\[NAME\])+", "[NAME]", text)
    # name parts that are "generic" on their own (Singh, Bano, Devi) still help an attacker
    # when they sit next to a removed name: absorb them into the placeholder
    text = GEN_AFTER.sub("[NAME]", text)
    text = GEN_BEFORE.sub("[NAME]", text)
    return text


# ---------------------------------------------------------------------------- entry point
def sanitize(text: str, ctx: Ctx, _nested: bool = False) -> str:
    if not text:
        return text
    text = normalize(text)
    text, keep = protect_doctors(text)
    if not _nested:
        text = clean_base64(text, ctx)
    text = clean_ids(text, ctx)
    text = clean_digits(text, ctx)
    text = clean_dates(text, ctx)
    text = clean_ages(text, ctx)
    text = clean_address(text, ctx)
    text = clean_names(text, ctx)
    return restore(text, keep)
