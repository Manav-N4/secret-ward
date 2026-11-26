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
