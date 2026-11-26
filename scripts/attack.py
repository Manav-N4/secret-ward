#!/usr/bin/env python3
"""Our own re-identification attacker (dev tool, practice data only).

Re-implements the attacks published in the kit's docs/ATTACKS.md as closely as the spec
allows, so we can MEASURE privacy instead of guessing it. The official attacker code is
not public, so treat these numbers as an approximation of the official arena.

  A1 direct exposure     share of patients with a surviving direct identifier / full name
  A3 record linkage      mean probability the registry attacker gives the true person (per record)
  A4 profile attack      share of patients re-identified with confidence >= 0.5 after pooling
                         every record that shares a pseudonym
  A5 targeted attack     success against people in known_facts (visit date, condition,
                         length of stay, hospital), with global-shift recovery

Each of A3-A5 is also run on the RAW input and reported as ours / raw, like the official
arena ("how much of the attack surface you removed").

Usage:
  python scripts/attack.py --kit ../Secret-Wards-ToolKit --output out
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from secretward.gazetteer import skeleton  # noqa: E402

# ----------------------------------------------------------------------------- loading
def norm(s: str) -> str:
    return unicodedata.normalize("NFKC", s)


def load_csv_text(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def json_at(data, pointer: str):
    cur = data
    for part in pointer.strip("/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    return cur


def flatten(o, prefix=""):
    """(field, value) pairs from JSON, so the attacker can read keys like a human would."""
    out = []
    stack = [(prefix, o)]
    while stack:
        k, x = stack.pop()
        if isinstance(x, dict):
            stack.extend((kk, v) for kk, v in x.items())
        elif isinstance(x, list):
            stack.extend((k, v) for v in x)
        else:
            out.append((str(k), "" if x is None else str(x)))
    return out


def record_pairs(path: Path, loc: str):
    """Return (field, value) pairs plus the free text of one record."""
    raw = path.read_bytes()
    text = load_csv_text(raw)
    suf = path.suffix.lower()
    if suf in (".csv", ".tsv") and loc.startswith("row:"):
        delim = "\t" if suf == ".tsv" or text.count("\t") > text.count(",") else ","
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
        i = int(loc[4:]) + 1
        if i >= len(rows):
            return [], ""
        pairs = list(zip(rows[0], rows[i]))
        return pairs, " | ".join(f"{h}: {v}" for h, v in pairs)
    if suf == ".json":
        try:
            data = json.loads(text)
            sub = data if loc == "doc" else json_at(data, loc)
        except (ValueError, KeyError, IndexError, TypeError):
            return [], text
        pairs = flatten(sub)
        return pairs, " | ".join(f"{k}: {v}" for k, v in pairs)
    return [], text


# ----------------------------------------------------------------------------- evidence
GENDER_WORDS = {"m": "M", "male": "M", "पुरुष": "M", "f": "F", "female": "F", "महिला": "F"}
AGE_FORMS = [
    re.compile(r"(?i)\bage\s*(?:/\s*sex)?\s*[:\-]?\s*(\d{1,3})(?:\s*-\s*(\d{1,3}))?"),
    re.compile(r"(?i)(?<![\d\-])(\d{1,3})(?:\s*-\s*(\d{1,3}))?\s*(?:yrs?|years?|y)\b\.?\s*/?\s*[MF]?"),
    re.compile(r"(?i)(?<![\d\-])(\d{1,3})(?:\s*-\s*(\d{1,3}))?\s*/\s*[MF](?![a-z])"),
    re.compile(r"(?<![\d\-])(\d{1,3})(?:\s*-\s*(\d{1,3}))?\s*वर्ष"),
    re.compile(r"(?:आयु|उम्र)\s*[:\-]?\s*(\d{1,3})(?:\s*-\s*(\d{1,3}))?"),
]
PLUS_AGE = re.compile(r"(?<!\d)(\d{2})\+")
PHONE = re.compile(r"(?<![\dA-Fa-f-])(?:\+?91[\s-]?)?0?([6-9]\d{4}[\s-]?\d{5})(?![\dA-Fa-f])")
LAST4 = re.compile(r"[Xx*]{4}[\s-]?[Xx*]{4}[\s-]?(\d{4})")
MASKED_PHONE = re.compile(r"(?<![\dA-Za-z])(\d{2})[Xx*]{4,6}(\d{2,4})(?![\dA-Za-z])")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PIN6 = re.compile(r"(?<!\d)([1-8]\d{5})(?!\d)")
PIN3 = re.compile(r"(?<!\d)([1-8]\d{2})\*{3}")
HOUSE = re.compile(r"(?i)(?:h\.?\s?no\.?|house(?:\s*no\.?)?|makan\s*no\.?|मकान\s*नं\.?)\s*[:\-]?\s*(\d+)")
REL = re.compile(r"(?i)(?<![A-Za-z/])(s/o|d/o|w/o|c/o)\.?\s*[:\-]?\s*([A-Za-zऀ-ॿ]+(?:\s[A-Za-zऀ-ॿ]+)?)")
DOCTOR = re.compile(r"(?i)\bdr\.?\s+[A-Za-z]+(?:\s[A-Za-z]+)?")
ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
NUM = re.compile(r"(?<!\d)(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})(?!\d)")
TOKEN = re.compile(r"[A-Za-zऀ-ॿ]+")


class Ev:
    def __init__(self):
        self.phones, self.last4, self.emails, self.masked = set(), set(), set(), set()
        self.genders, self.districts, self.tehsils, self.villages = set(), set(), set(), set()
        self.pins, self.pin3, self.houses = set(), set(), set()
        self.age = None                        # (lo, hi)
        self.birth_years = set()
        self.tokens, self.rel_tokens = set(), set()
        self.dates, self.intervals = set(), set()
        self.text = ""

    def add_age(self, lo, hi):
        lo, hi = lo - 1, hi + 2               # encounter-date drift, as the spec says
        if self.age is None:
            self.age = (lo, hi)
        else:
            a, b = max(self.age[0], lo), min(self.age[1], hi)
            self.age = (a, b) if a <= b else self.age

    def merge(self, o: "Ev"):
        for k, v in vars(o).items():
            if isinstance(v, set):
                getattr(self, k).update(v)
        if o.age:
            self.add_age(o.age[0] + 1, o.age[1] - 2)
        self.text += "\n" + o.text


class Vocab:
    def __init__(self, registry):
        self.district = {r["district"].lower() for r in registry if r["district"]}
        self.tehsil = {r["tehsil"].lower() for r in registry if r["tehsil"]}
        self.village = {r["village"].lower() for r in registry if r["village"]}
        self.pins = {r["pin"] for r in registry if r["pin"]}
        self.given, self.surname = set(), set()
        for r in registry:
            parts = r["name"].lower().split()
            if parts:
                self.given.add(parts[0])
                self.surname.add(parts[-1])
        self.sk = {}
        for w in self.given | self.surname | self.village | self.district | self.tehsil:
            self.sk.setdefault(skeleton(w), set()).add(w)


def extract(pairs, text, vocab: Vocab) -> Ev:
    ev = Ev()
    t = norm(text)
    ev.text = t.lower()
    for k, v in pairs:
        kl = k.lower()
        if any(x in kl for x in ("gender", "sex", "ling")):
            g = GENDER_WORDS.get(v.strip().lower())
            if g:
                ev.genders.add(g)
        if ("age" in kl or "umar" in kl) and "page" not in kl:
            m = re.match(r"\s*(\d{1,3})(?:\s*-\s*(\d{1,3}))?", v)
            if m:
                ev.add_age(int(m.group(1)), int(m.group(2) or m.group(1)))
        if "dob" in kl or "birth" in kl or "janm" in kl:
            m = re.search(r"(19|20)\d{2}", v)
            if m:
                ev.birth_years.add(int(m.group(0)))
    for rx in AGE_FORMS:
        m = rx.search(t)
        if m:
            lo = int(m.group(1)); hi = int(m.group(2) or lo)
            if 0 < lo <= 110 and hi >= lo:
                ev.add_age(lo, hi)
            break
    m = PLUS_AGE.search(t)
    if m:
        ev.add_age(int(m.group(1)), 110)
    for m in re.finditer(r"/\s*([MF])\b|\b(male|female)\b", t, re.I):
        ev.genders.add(GENDER_WORDS[(m.group(1) or m.group(2)).lower()])
    for m in re.finditer(r"(?i)\b(s/o)\b|\b(w/o|d/o)\b|\b(sahab|bhaiya)\b|\b(behenji|didi)\b", t):
        if m.group(1) or m.group(3):
            ev.genders.add("M")
        elif m.group(2) or m.group(4):
            ev.genders.add("F")
    ev.phones = {re.sub(r"\D", "", m.group(1)) for m in PHONE.finditer(t)}
    ev.last4 = set(LAST4.findall(t))
    ev.masked = {(a, b) for a, b in MASKED_PHONE.findall(t)}
    ev.emails = {e.lower() for e in EMAIL.findall(t)}
    ev.pins = {p for p in PIN6.findall(t) if p in vocab.pins}
    ev.pin3 = set(PIN3.findall(t)) | {p[:3] for p in ev.pins}
    ev.houses = set(HOUSE.findall(t))
    no_doc = DOCTOR.sub(" ", t)
    toks = [x.lower() for x in TOKEN.findall(no_doc)]
    for tok in toks:
        cands = {tok}
        if re.search(r"[ऀ-ॿ]", tok):
            cands = vocab.sk.get(skeleton(tok), set())
        for c in cands:
            if c in vocab.district:
                ev.districts.add(c)
            if c in vocab.tehsil:
                ev.tehsils.add(c)
            if c in vocab.village:
                ev.villages.add(c)
            if c in vocab.given or c in vocab.surname:
                ev.tokens.add(c)
    low = no_doc.lower()
    for v in vocab.village:
        if " " in v and v in low:
            ev.villages.add(v)
    for m in REL.finditer(no_doc):
        ev.rel_tokens.update(x.lower() for x in TOKEN.findall(m.group(2)))
    ds = []
    for m in ISO.finditer(t):
        try:
            ds.append(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
        except ValueError:
            pass
    for m in NUM.finditer(t):
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        for d, mo in ((a, b), (b, a)):
            try:
                ds.append(dt.date(y, mo, d))
            except ValueError:
                pass
    ev.dates = set(ds)
    ev.intervals = {abs((x - y).days) for x in ds for y in ds if x != y and abs((x - y).days) <= 60}
    return ev


# ----------------------------------------------------------------------------- attacks
def registry_attack(ev: Ev, registry, ref_year=2026) -> dict:
    cands = registry
    filters = [
        lambda r: r["phone"] in ev.phones if ev.phones else None,
        lambda r: r["email"].lower() in ev.emails if ev.emails else None,
        lambda r: r["aadhaar_last4"] in ev.last4 if ev.last4 else None,
        lambda r: any(r["phone"].startswith(a) and r["phone"].endswith(b) for a, b in ev.masked) if ev.masked else None,
        lambda r: r["district"].lower() in ev.districts if ev.districts else None,
        lambda r: r["gender"] in ev.genders if len(ev.genders) == 1 else None,
        lambda r: ev.age[0] <= int(r["age"] or -99) <= ev.age[1] if ev.age else None,
        lambda r: any(abs((ref_year - int(r["age"] or 0)) - y) <= 1 for y in ev.birth_years) if ev.birth_years else None,
        lambda r: r["tehsil"].lower() in ev.tehsils if ev.tehsils else None,
        lambda r: r["village"].lower() in ev.villages if ev.villages else None,
        lambda r: r["pin"] in ev.pins if ev.pins else None,
        lambda r: r["pin"][:3] in ev.pin3 if ev.pin3 else None,
    ]
    for f in filters:
        if f(registry[0]) is None:
            continue
        nxt = [r for r in cands if f(r)]
        if nxt:                                   # a filter that empties the set is skipped
            cands = nxt
    weights = {}
    for r in cands:
        parts = r["name"].lower().split()
        w = 1.0
        if parts and parts[0] in ev.tokens and parts[-1] in ev.tokens:
            w *= 60
        elif parts and parts[0] in ev.tokens:
            w *= 8
        elif parts and parts[-1] in ev.tokens:
            w *= 3
        rel = r["relative_name"].lower().split()
        if rel and rel[0] in ev.rel_tokens:
            w *= 8
        if r["house_no"] and r["house_no"] in ev.houses:
            w *= 2
        weights[r["rid"]] = w
    total = sum(weights.values()) or 1.0
    return {rid: w / total for rid, w in weights.items()}


PATHS = {}


def run(kit: Path, root: Path, mode: str):
    """mode 'ours': read our output; mode 'raw': read the original input (upper bound)."""
    truth = json.loads(Path(PATHS.get("truth", kit / "dev/truth/truth.json")).read_text(encoding="utf-8"))
    registry = list(csv.DictReader(open(PATHS.get("registry", kit / "dev/attacker/registry.csv"), encoding="utf-8")))
    facts = [json.loads(l) for l in open(PATHS.get("facts", kit / "dev/attacker/known_facts.jsonl"), encoding="utf-8")]
    raw_input = Path(PATHS.get("input", kit / "dev/input"))
    pt2rid = {pt: p["rid"] for pt, p in truth["patients"].items()}
    vocab = Vocab(registry)
    if mode == "ours":
        report = json.loads((root / "report.json").read_text(encoding="utf-8"))
        out_of = {e["input_sha256"]: e["output"] for e in report["files"]}
        pseud = {}
        for line in open(root / "records.jsonl", encoding="utf-8"):
            r = json.loads(line)
            pseud[(r["file"], r["loc"])] = r["patient"]
    records = []                                  # (true rid, profile key, Ev)
    for rel, f in truth["files"].items():
        if mode == "ours":
            o = out_of.get(f["sha256"])
            if not o:
                continue
            path = root / o
        else:
            path = raw_input / rel
        if not path.is_file():
            continue
        for loc, u in f["units"].items():
            if loc.startswith("@") or not u.get("patient"):
                continue
            rid = pt2rid.get(u["patient"])
            try:
                pairs, text = record_pairs(path, loc)
            except Exception:  # noqa: BLE001
                continue
            ev = extract(pairs, text, vocab)
            if mode == "ours":
                key = pseud.get((o, loc)) or f"single:{rel}:{loc}"
            else:
                key = f"true:{u['patient']}"      # raw: the attacker can join on raw UHIDs
            records.append((rid, key, ev))

    # A3: per-record linkage
    a3 = [registry_attack(ev, registry).get(rid, 0.0) for rid, _, ev in records]
    # A4: pool by profile
    prof = defaultdict(Ev)
    prof_rids = defaultdict(Counter)
    for rid, key, ev in records:
        prof[key].merge(ev)
        prof_rids[key][rid] += 1
    best = defaultdict(float)
    for key, ev in prof.items():
        probs = registry_attack(ev, registry)
        for rid in prof_rids[key]:
            best[rid] = max(best[rid], probs.get(rid, 0.0))
    for rid, _, ev in records:
        best[rid] = max(best[rid], 0.0)
    patients = {rid for rid, _, _ in records}
    a4 = sum(1 for rid in patients if best[rid] >= 0.5) / max(1, len(patients))
    # A5: targeted, with global shift recovery
    cond_count = Counter()
    for key, ev in prof.items():
        for f in facts:
            c = (f.get("condition_hint") or "").lower()
            if c and c in ev.text:
                cond_count[c] += 1
    confident = {}
    for key, ev in prof.items():
        probs = registry_attack(ev, registry)
        if probs:
            rid, p = max(probs.items(), key=lambda x: x[1])
            if p >= 0.9:
                confident[rid] = key
    offsets = Counter()
    for f in facts:
        key = confident.get(f["rid"])
        if key:
            for vd in f["visit_dates"]:
                v = dt.date.fromisoformat(vd)
                ds = prof[key].dates
                if ds:
                    near = min(ds, key=lambda d: abs((d - v).days))
                    offsets[(near - v).days] += 1
    shift = 0
    if offsets:
        off, n = offsets.most_common(1)[0]
        if n >= 2:
            shift = off
    a5_scores, targets = [], 0
    for f in facts:
        if f["rid"] not in patients:
            continue
        targets += 1
        visits = {dt.date.fromisoformat(v) + dt.timedelta(days=shift) for v in f["visit_dates"]}
        c = (f.get("condition_hint") or "").lower()
        weights = {}
        for key, ev in prof.items():
            w, hit = 1.0, False
            if visits & ev.dates:
                w *= 4; hit = True
            if c and c in ev.text:
                w *= 8 if cond_count[c] <= 3 else 2; hit = True
            if f.get("stay_days") and f["stay_days"] in ev.intervals:
                w *= 4; hit = True
            if not hit:
                continue
            if f.get("hospital", "").lower() in ev.text:
                w *= 2
            if registry_attack(ev, registry).get(f["rid"], 0.0) == 0.0:
                continue                          # evidence must be consistent with the person
            weights[key] = w
        tot = sum(weights.values())
        true_keys = {k for k in prof if f["rid"] in prof_rids[k]}
        a5_scores.append(sum(w for k, w in weights.items() if k in true_keys) / tot if tot else 0.0)
    return {
        "records": len(records), "patients": len(patients),
        "A3_mean_prob_true_person": round(sum(a3) / max(1, len(a3)), 4),
        "A4_share_reidentified": round(a4, 4),
        "A5_targeted_success": round(sum(a5_scores) / max(1, len(a5_scores)), 4),
        "A5_targets": targets, "A5_global_shift_recovered": shift != 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--input", help="raw input the output was made from (default: kit dev/input)")
    ap.add_argument("--truth", help="truth.json matching --input (default: kit dev/truth/truth.json)")
    ap.add_argument("--registry", help="attacker registry.csv (default: kit dev/attacker/registry.csv)")
    ap.add_argument("--facts", help="attacker known_facts.jsonl (default: kit dev/attacker/known_facts.jsonl)")
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    for k in ("input", "truth", "registry", "facts"):
        if getattr(a, k):
            PATHS[k] = getattr(a, k)
    if a.input and not a.truth:
        print("warning: --input given without --truth; scores will not match the data", file=sys.stderr)
    raw = run(kit, kit, "raw")
    ours = run(kit, out, "ours")
    print("attack                         raw       ours    ours/raw")
    comp = []
    for k in ("A3_mean_prob_true_person", "A4_share_reidentified", "A5_targeted_success"):
        ratio = ours[k] / raw[k] if raw[k] else 0.0
        comp.append(min(1.0, ratio))
        print(f"{k:28s} {raw[k]:8.3f}  {ours[k]:8.3f}  {ratio:8.3f}")
    print(f"records {ours['records']} patients {ours['patients']} A5 targets {ours['A5_targets']}"
          f" global shift recovered: {ours['A5_global_shift_recovered']}")
    risk = sum(comp) / len(comp)
    print(f"approx. privacy resistance (1 - mean ratio over A3-A5): {1 - risk:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
