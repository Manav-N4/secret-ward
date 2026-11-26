"""Keyed pseudonyms, per-patient date shifts and generalisation helpers.

* Pseudonym = HMAC-SHA256(secret, "psn|" + cluster key): not reversible without the
  secret (beats attack A6), changes when the secret changes (beats A7).
* Shift = HMAC(secret, "shift|" + cluster key) mapped to [-max, max] minus 0: one patient's
  dates all move together (intervals survive), different patients move differently
  (beats the attacker's "global shift recovery" in A5).
"""
from __future__ import annotations

import hashlib
import hmac
import os

from .rules import POLICY

SECRET = os.environ.get("RAKSHA_SECRET", "").encode()  # never print or write this
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _mac(tag: str, key: str) -> bytes:
    return hmac.new(SECRET, f"{tag}|{key}".encode("utf-8"), hashlib.sha256).digest()


def pseudonym(cluster_key: str) -> str:
    n = int.from_bytes(_mac("psn", cluster_key)[:5], "big")
    return "PSN-" + "".join(_ALPHABET[(n >> (5 * i)) & 31] for i in range(6))


def short_tag(key: str, n: int = 8) -> str:
    """Keyed short tag for renamed files (never derived from the original name alone)."""
    v = int.from_bytes(_mac("file", key)[:6], "big")
    return "".join(_ALPHABET[(v >> (5 * i)) & 31] for i in range(n))


def shift_days(cluster_key: str) -> int:
    m = int(POLICY.get("date_shift_max_days", 180))
    v = int.from_bytes(_mac("shift", cluster_key)[:4], "big") % (2 * m) - m
    return v if v != 0 else 1


def age_band(age: int) -> str:
    w = int(POLICY.get("age_band_years", 10))
    if age >= 90:
        return "90+"
    lo = (age // w) * w
    return f"{lo}-{lo + w - 1}"


def pin_prefix(pin: str) -> str:
    k = int(POLICY.get("pin_keep_digits", 3))
    digits = "".join(c for c in pin if c.isdigit())
    if len(digits) != 6:
        return "[PIN]"
    return digits[:k] + "*" * (6 - k)


def cluster_band(ages: list[int]) -> tuple[int, int] | None:
    """One truthful band for ALL records of a patient.

    If a patient is 49 in one file and 50 in another, per-record banding gives "40-49" and
    "50-59"; an attacker who pools both learns the age is 49-50. Instead we pick a single
    10-year window that contains every stated age (grid offset 0, then 5), and widen to
    20 years only if no 10-year window fits.
    """
    ages = sorted(a for a in ages if 0 <= a <= 120)
    if not ages:
        return None
    lo_a, hi_a = ages[0], ages[-1]
    if lo_a >= 90:
        return (90, 200)
    w = int(POLICY.get("age_band_years", 10))
    for off in (0, w // 2):
        lo = ((lo_a - off) // w) * w + off
        if hi_a <= lo + w - 1:
            return (lo, lo + w - 1)
    lo = (lo_a // w) * w
    return (lo, max(lo + 2 * w - 1, ((hi_a // w) + 1) * w - 1))


def band_text(b: tuple[int, int]) -> str:
    return f"{b[0]}+" if b[1] >= 150 else f"{b[0]}-{b[1]}"


def widen(b: tuple[int, int] | None) -> tuple[int, int] | None:
    """Coarser truthful band for patients in small groups (k-anonymity, local only)."""
    if b is None:
        return None
    if b[0] >= 80:
        return (80, 200)
    if b[1] < 20:
        return (0, 19)
    lo = (b[0] // 20) * 20
    hi = max(lo + 19, ((b[1] // 20) + 1) * 20 - 1)
    return (lo, hi)
