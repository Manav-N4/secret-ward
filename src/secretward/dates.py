"""Find dates in any common Indian format and shift them by a per-patient number of days.

The output keeps the exact written format (separators, zero padding, 2- or 4-digit
year, month-name style), so a CSV date column still looks like the same column.

DD/MM vs MM/DD: "02/06/2026" is ambiguous. Each file votes using its unambiguous dates
(a part > 12). Files with no evidence borrow the convention from other files that share
their ID prefixes (same hospital), then fall back to DD/MM (Indian default).
"""
from __future__ import annotations

import datetime as dt
import re

from .rules import MONTHS

ISO = re.compile(r"(?<!\d)(\d{4})-(\d{2})-(\d{2})(?=T|\b|$)")
NUM = re.compile(r"(?<![\d/.\-])(\d{1,2})([/\-.])(\d{1,2})\2(\d{4}|\d{2})(?![\d/\-]|\.\d)")
_MON = "|".join(sorted((re.escape(m) for m in MONTHS), key=len, reverse=True))
DMONY = re.compile(rf"(?<!\d)(\d{{1,2}})(st|nd|rd|th)?([\s\-]+)({_MON})\.?(,?[\s\-]+)(\d{{4}})(?!\d)", re.I)
MONDY = re.compile(rf"(?<![\w])({_MON})\.?(\s+)(\d{{1,2}})(st|nd|rd|th)?(,?\s+)(\d{{4}})(?!\d)", re.I)
_MONTH_NAMES = {}
for name, num in MONTHS.items():
    _MONTH_NAMES.setdefault(num, []).append(name)


def infer_convention(text: str) -> str | None:
    dmy = mdy = 0
    for m in NUM.finditer(text):
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 >= b:
            dmy += 1
        elif b > 12 >= a:
            mdy += 1
    if dmy > mdy:
        return "DMY"
    if mdy > dmy:
        return "MDY"
    return None


def _year(y: str) -> int:
    v = int(y)
    return v if len(y) == 4 else (2000 + v if v <= 40 else 1900 + v)


def _fmt_year(orig: str, year: int) -> str:
    return f"{year:04d}" if len(orig) == 4 else f"{year % 100:02d}"


def _pad(orig: str, v: int) -> str:
    return f"{v:0{len(orig)}d}" if len(orig) == 2 and orig.startswith("0") else str(v) if len(orig) == 1 else f"{v:02d}"


def _month_name(orig: str, month: int) -> str:
    names = _MONTH_NAMES[month]
    latin = [n for n in names if n.isascii()]
    deva = [n for n in names if not n.isascii()]
    pool = latin if orig.isascii() else (deva or latin)
    short = [n for n in pool if len(n) <= 4] or pool
    full = [n for n in pool if len(n) > 4] or pool
    pick = (short if len(orig.rstrip(".")) <= 4 else full)[0]
    if orig.isupper():
        return pick.upper()
    if orig[:1].isupper():
        return pick.capitalize()
    return pick


def shift_text(text: str, days: int, conv: str = "DMY") -> tuple[str, int]:
    """Shift every date in text by `days`. Returns (new_text, number_of_dates)."""
    count = 0
    delta = dt.timedelta(days=days)

    def iso(m):
        nonlocal count
        try:
            d = dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))) + delta
        except ValueError:
            return m.group(0)
        count += 1
        return f"{d.year:04d}-{d.month:02d}-{d.day:02d}"

    def num(m):
        nonlocal count
        a, sep, b, y = m.group(1), m.group(2), m.group(3), m.group(4)
        day, mon = (a, b) if conv == "DMY" else (b, a)
        if int(day) > 12 and conv == "MDY" and int(a) <= 12 < int(b):
            pass
        try:
            d = dt.date(_year(y), int(mon), int(day)) + delta
        except ValueError:
            # the file convention may be wrong for this one value; try the other order
            try:
                d = dt.date(_year(y), int(day), int(mon)) + delta
                day, mon = mon, day
                a_new, b_new = (d.day, d.month) if conv != "DMY" else (d.month, d.day)
                count += 1
                return f"{_pad(a, a_new)}{sep}{_pad(b, b_new)}{sep}{_fmt_year(y, d.year)}"
            except ValueError:
                return m.group(0)
        count += 1
        first, second = (d.day, d.month) if conv == "DMY" else (d.month, d.day)
        return f"{_pad(a, first)}{sep}{_pad(b, second)}{sep}{_fmt_year(y, d.year)}"

    def dmony(m):
        nonlocal count
        mon = MONTHS.get(m.group(4).lower())
        try:
            d = dt.date(int(m.group(6)), mon, int(m.group(1))) + delta
        except (ValueError, TypeError):
            return m.group(0)
        count += 1
        suf = m.group(2) or ""
        if suf:
            suf = "th" if 11 <= d.day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(d.day % 10, "th")
        dd = f"{d.day:02d}" if len(m.group(1)) == 2 else str(d.day)
        return f"{dd}{suf}{m.group(3)}{_month_name(m.group(4), d.month)}{m.group(5)}{d.year}"

    def mondy(m):
        nonlocal count
        mon = MONTHS.get(m.group(1).lower())
        try:
            d = dt.date(int(m.group(6)), mon, int(m.group(3))) + delta
        except (ValueError, TypeError):
            return m.group(0)
        count += 1
        suf = m.group(4) or ""
        if suf:
            suf = "th" if 11 <= d.day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(d.day % 10, "th")
        return f"{_month_name(m.group(1), d.month)}{m.group(2)}{d.day}{suf}{m.group(5)}{d.year}"

    text = ISO.sub(iso, text)
    text = NUM.sub(num, text)
    text = DMONY.sub(dmony, text)
    text = MONDY.sub(mondy, text)
    return text, count


def looks_like_date(value: str) -> bool:
    return bool(ISO.search(value) or NUM.search(value) or DMONY.search(value) or MONDY.search(value))
