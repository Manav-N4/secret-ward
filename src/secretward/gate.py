"""Release gate: the pipeline audits its own output before anything is written.

Every detection layer can miss something. The gate is an independent second check that needs
no answer key: it collects every identifier the pipeline itself LEARNED from this input (phone,
Aadhaar, ABHA and hospital-ID numbers from the linking keys; full patient / relative names from
structured columns) and looks for any of them in each output file and in its path, just before
the file is written. A hit is repaired on the spot and counted in report.json.

It uses different matching from the cleaners on purpose: digits are compared with every space
and hyphen removed ("98765-43210", "9876 543 210"), names as whole words in any case. A name
straight after "Dr." is left alone (doctors are kept by design).
"""
from __future__ import annotations

import json
import re

DIGIT_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9](?:[0-9 \-]*[0-9])?(?![0-9A-Za-z])")   # not glued to letters: UUIDs, codes
WORD = re.compile(r"[A-Za-z]+")
GAP = re.compile(r"[\s_.]+")
DOCTOR_BEFORE = re.compile(r"(?:\bDr|\bDoctor)\.?\s*$", re.I)


class ReleaseGate:
    def __init__(self, keys, full_names) -> None:
        self.digits: dict[str, str] = {}
        for k in keys:
            kind, _, v = k.partition(":")
            d = re.sub(r"\D", "", v)
            if kind == "PH" and len(d) == 10:
                self.digits[d] = "[PHONE]"
            elif kind == "AA" and len(d) == 12:
                self.digits[d] = "[AADHAAR]"
            elif kind == "AB" and len(d) == 14:
                self.digits[d] = "[ABHA]"
            elif kind == "ID" and len(d.lstrip("0")) >= 7:   # short cores could collide with lab values
                self.digits.setdefault(d, "[ID]")
                self.digits.setdefault(d.lstrip("0"), "[ID]")
        self.names = {n for n in full_names if len(n.split()) >= 2}
        self.max_words = max((len(n.split()) for n in self.names), default=0)
        self.repaired = 0

    # ------------------------------------------------------------------ text
    def _digit_hit(self, run: str) -> str | None:
        d = re.sub(r"\D", "", run)
        if d in self.digits:
            return self.digits[d]
        if len(d) in (11, 12) and d[-10:] in self.digits and self.digits[d[-10:]] == "[PHONE]" \
                and (d.startswith("0") or d.startswith("91")):
            return "[PHONE]"                          # 0- or 91-prefixed form of a known phone
        return None

    def clean(self, text: str) -> str:
        if not text or (not self.digits and not self.names):
            return text
        if self.digits:
            def dsub(m):
                p = self._digit_hit(m.group(0))
                if p:
                    self.repaired += 1
                    return p
                return m.group(0)
            text = DIGIT_RUN.sub(dsub, text)
        if self.names and self.max_words >= 2:
            runs = list(WORD.finditer(text))
            out, last, i = [], 0, 0
            while i < len(runs):
                hit = 0
                for n in range(min(self.max_words, len(runs) - i), 1, -1):
                    if any(not GAP.fullmatch(text[runs[k].end():runs[k + 1].start()]) for k in range(i, i + n - 1)):
                        continue
                    if " ".join(r.group(0).lower() for r in runs[i:i + n]) in self.names:
                        hit = n
                        break
                if hit and not DOCTOR_BEFORE.search(text[max(0, runs[i].start() - 10):runs[i].start()]):
                    out.append(text[last:runs[i].start()])
                    out.append("[NAME]")
                    last = runs[i + hit - 1].end()
                    self.repaired += 1
                    i += hit
                else:
                    i += 1
            out.append(text[last:])
            text = "".join(out)
        return text

    # ------------------------------------------------------------------ files
    def _clean_json(self, o):
        if isinstance(o, dict):
            return {self.clean(k) if isinstance(k, str) else k: self._clean_json(v) for k, v in o.items()}
        if isinstance(o, list):
            return [self._clean_json(v) for v in o]
        if isinstance(o, str):
            return self.clean(o)
        if isinstance(o, int) and not isinstance(o, bool):
            p = self._digit_hit(str(o))
            if p:
                self.repaired += 1
                return p
        return o

    def check_file(self, kind: str, result: str) -> str:
        """Returns the result unchanged (byte for byte) unless something learned is still in it."""
        before = self.repaired
        if kind == "json":
            fixed = self._clean_json(json.loads(result))
            if self.repaired == before:
                return result
            return json.dumps(fixed, ensure_ascii=False, indent=2) + "\n"
        out = self.clean(result)
        return out if self.repaired != before else result
