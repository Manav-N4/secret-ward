#!/usr/bin/env python3
"""Independent, simplified re-implementation of the Secret Wards attacks A2/A3 and A5
(toolkit docs/ATTACKS.md) against a sanitized release.

Written from the public spec only, NOT from scripts/attack.py, so the two can cross-check
each other. Stdlib only. Reads; never writes outside --json-out.

What it does
  Records   one per line of the release's records.jsonl (CSV row, JSON pointer, or whole doc),
            read as "field: value" text from sanitized/ (or, with --raw, from the raw input file
            at the same locator, to measure the attack surface before sanitising).
  Evidence  phones, emails, last-4 Aadhaar, masked phones, district / tehsil / village (Latin;
            districts also in Devanagari), gender, ages and age bands, PINs and PIN prefixes,
            Latin names and relative names, house numbers, dates, free text (for conditions).
  A2/A3     registry candidates filtered in the spec's order (phone, email, last4, masked phone,
            district, gender, age, tehsil, village, PIN, PIN prefix); a filter that would empty
            the set is skipped. Weights: full name x60, given x8, surname x3, relative x8,
            house x2. Risk = probability mass on the true person.
  Profiles  records pooled by the release's pseudonym (A4-style), used for the patient-level
            headline and for A5.
  A5        per known-facts target: profiles matching a visit date, the condition (x8 if <= 3
            profiles share it) or a length of stay; evidence must be consistent with the target;
            hospital match doubles. Global-shift recovery from profiles re-identified with
            confidence >= 0.9 (two people agreeing on one offset un-shift every date).
            Success = score share of the target's true profiles; decoy matches = false claims.

Simplifications (vs the official arena): no Devanagari/variant name transliteration, no
Devanagari village matching, no birth-year filter, union semantics when pooling evidence,
no A1/A6/A7. So this is a LOWER bound on the official attacker's strength.

Usage
  python3 qa/attack_sim.py --kit ../Secret-Wards-ToolKit --output qa/out/X            # release
  python3 qa/attack_sim.py --kit ../Secret-Wards-ToolKit --output qa/out/X --raw      # raw input
"""
import argparse
import collections
import csv
import datetime as dt
import io
import json
import re
import sys
from pathlib import Path

REF = dt.date(2026, 11, 20)  # dataset ref_date (dataset_manifest.json)
DEVA_DISTRICTS = {"सुल्तानपुर": "Sultanpur", "रायबरेली": "Rae Bareli", "राय बरेली": "Rae Bareli",
                  "बाराबंकी": "Barabanki", "उन्नाव": "Unnao", "सीतापुर": "Sitapur", "बहराइच": "Bahraich",
                  "लखनऊ": "Lucknow", "हरदोई": "Hardoi"}
W_FULL, W_GIVEN, W_SUR, W_REL, W_HOUSE = 60, 8, 3, 8, 2


# ---------------------------------------------------------------- reading the release
def decode(raw: bytes) -> str:
    for bom, enc in ((b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"), (b"\xef\xbb\xbf", "utf-8-sig")):
        if raw.startswith(bom):
            return raw.decode(enc)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def flatten(o, prefix=""):
    if isinstance(o, dict):
        return "\n".join(flatten(v, k) for k, v in o.items())
    if isinstance(o, list):
        return "\n".join(flatten(v, prefix) for v in o)
    return f"{prefix}: {o}"


def resolve(obj, ptr):
    for seg in ptr.split("/")[1:]:
        seg = seg.replace("~1", "/").replace("~0", "~")
        obj = obj[int(seg)] if isinstance(obj, list) else obj[seg]
    return obj


class FileCache:
    def __init__(self):
        self.text, self.rows, self.json = {}, {}, {}

    def get_text(self, p):
        if p not in self.text:
            self.text[p] = decode(p.read_bytes())
        return self.text[p]

    def record_text(self, p, loc):
        try:
            if loc.startswith("row:"):
                if p not in self.rows:
                    t = self.get_text(p)
                    delim = "\t" if p.suffix.lower() == ".tsv" else ","
                    self.rows[p] = list(csv.reader(io.StringIO(t, newline=""), delimiter=delim))
                rows = self.rows[p]
                hdr, row = rows[0], rows[int(loc[4:]) + 1]
                return "\n".join(f"{hdr[i] if i < len(hdr) else i}: {v}" for i, v in enumerate(row))
            if loc.startswith("/"):
                if p not in self.json:
                    self.json[p] = json.loads(self.get_text(p))
                return flatten(resolve(self.json[p], loc))
        except (IndexError, KeyError, ValueError, TypeError, RecursionError):
            pass
        return self.get_text(p)


# ---------------------------------------------------------------- evidence extraction
RX = {
    "phone": re.compile(r"(?<![\dX])(?:\+?91[\s-]?)?(\d(?:[\s-]?\d){9})(?![\d])"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"),
    "last4": re.compile(r"X{4}[\s-]?X{4}[\s-]?(\d{4})"),
    "mphone": re.compile(r"\b(\d{2})X{6}(\d{2})\b"),
    "band": re.compile(r"(?<!\d)(\d{1,3})\s*-\s*(\d{1,3})\s*(?=Yrs|yrs|Y\b|वर्ष|/\s*[MF]\b)"),
    "band_br": re.compile(r"\[(\d{1,3}),\s*(\d{1,3})\)"),
    "plus": re.compile(r"(?<!\d)(\d{2,3})\+"),
    "age_lab": re.compile(r"(?:\bAge|\bUmar|आयु|\bumar)\s*[:=]?\s*(\d{1,3})(?!\s*-\s*\d)"),
    "age_suf": re.compile(r"(?<![\d-])(\d{1,3})\s*(?:/\s*[MF]\b|Y(?:rs|ears)?\b|yrs\b|वर्ष)"),
    "pin": re.compile(r"(?<!\d)(\d{6})(?!\d)"),
    "pinpre": re.compile(r"(?<!\d)(\d{3})\*{3}"),
    "house": re.compile(r"(?:H\.?\s?No\.?|House|Makan No\.?|मकान नं\.?)\s*(\d+)", re.I),
    "rel": re.compile(r"\b(?:S/o|D/o|W/o|C/O)\s+([A-Za-z]+(?:\s+[A-Za-z]+){0,2})", re.I),
    "iso": re.compile(r"\b(\d{4})-(\d{2})-(\d{2})"),
    "dmy": re.compile(r"(?<![\d/.-])(\d{1,2})[/.-](\d{1,2})[/.-](\d{4}|\d{2})(?![\d/.-])"),
}
GENDER_RX = [(re.compile(r"/\s*M\b|\bMale\b|\bS/o\b|पुरुष|\bsahab\b|\b(?:Sex|Gender|Ling)\s*:\s*M\b", re.I), "M"),
             (re.compile(r"/\s*F\b|\bFemale\b|\b[DW]/o\b|महिला|\bbehenji\b|\bSmt\.?\b|\b(?:Sex|Gender|Ling)\s*:\s*F\b", re.I), "F")]


def mkdate(y, m, d):
    try:
        return dt.date(y, m, d)
    except ValueError:
        return None


def extract_dates(text):
    out = set()
    for y, m, d in RX["iso"].findall(text):
        x = mkdate(int(y), int(m), int(d))
        if x:
            out.add(x)
    for a, b, y in RX["dmy"].findall(text):
        yy = int(y) if len(y) == 4 else (2000 + int(y) if int(y) <= 30 else 1900 + int(y))
        x = mkdate(yy, int(b), int(a)) or mkdate(yy, int(a), int(b))  # D/M first, then M/D
        if x:
            out.add(x)
    return out


class Gaz:
    def __init__(self, registry):
        self.reg = registry
        self.districts = {r["district"] for r in registry if r["district"]}
        self.tehsils = {r["tehsil"] for r in registry if r["tehsil"]}
        self.villages = {r["village"] for r in registry if r["village"]}
        self.pins = {r["pin"] for r in registry if r["pin"]}
        self.phones = {r["phone"] for r in registry if r["phone"]}

    @staticmethod
    def find(names, text_cf):
        return {n for n in names if re.search(r"(?<![a-z])" + re.escape(n.casefold()) + r"(?![a-z])", text_cf)}


def evidence(text, gaz):
    cf = text.casefold()
    e = collections.defaultdict(set)
    for m in RX["phone"].finditer(text):
        d = re.sub(r"\D", "", m.group(1))[-10:]
        if d in gaz.phones:
            e["phone"].add(d)
    e["email"] = {x.casefold() for x in RX["email"].findall(text)}
    e["last4"] = set(RX["last4"].findall(text))
    e["mphone"] = {a + b for a, b in RX["mphone"].findall(text)}
    e["district"] = gaz.find(gaz.districts, cf) | {v for k, v in DEVA_DISTRICTS.items() if k in text}
    e["tehsil"] = gaz.find(gaz.tehsils, cf)
    e["village"] = gaz.find(gaz.villages, cf)
    e["gender"] = {g for rx, g in GENDER_RX if rx.search(text)}
    # ages: bands first (so "40-59 Yrs" is never read as an exact 59), then exact ages
    rest = text
    for rx in (RX["band"], RX["band_br"]):
        for m in rx.finditer(text):
            lo, hi = int(m.group(1)), int(m.group(2))
            if 0 <= lo <= hi <= 120:
                e["age"].add((lo, hi if rx is RX["band"] else hi - 1))
        rest = rx.sub(" ", rest)
    for m in RX["plus"].finditer(rest):
        e["age"].add((int(m.group(1)), 120))
    rest = RX["plus"].sub(" ", rest)
    for rx in (RX["age_lab"], RX["age_suf"]):
        for a in rx.findall(rest):
            if 0 < int(a) <= 110:
                e["age"].add((int(a), int(a)))
    e["pin"] = {p for p in RX["pin"].findall(text) if p in gaz.pins}
    e["pinpre"] = set(RX["pinpre"].findall(text))
    e["house"] = set(RX["house"].findall(text))
    e["rel"] = {r.casefold() for r in RX["rel"].findall(text)}
    e["tokens"] = set(re.findall(r"[a-z]+", cf))
    e["dates"] = extract_dates(text)
    e["text"] = {cf}
    return e


def pool(evs):
    out = collections.defaultdict(set)
    for e in evs:
        for k, v in e.items():
            out[k] |= v
    return out


# ---------------------------------------------------------------- A2/A3 record linkage
FILTERS = [
    ("phone", lambda r, v: r["phone"] in v),
    ("email", lambda r, v: r["email"].casefold() in v),
    ("last4", lambda r, v: r["aadhaar_last4"] in v),
    ("mphone", lambda r, v: bool(r["phone"]) and r["phone"][:2] + r["phone"][-2:] in v),
    ("district", lambda r, v: r["district"] in v),
    ("gender", lambda r, v: r["gender"] in v),
    ("age", lambda r, v: r["age"].isdigit() and any(lo - 1 <= int(r["age"]) <= hi + 2 for lo, hi in v)),
    ("tehsil", lambda r, v: r["tehsil"] in v),
    ("village", lambda r, v: r["village"] in v),
    ("pin", lambda r, v: r["pin"] in v),
    ("pinpre", lambda r, v: r["pin"][:3] in v),
]


def candidates(e, registry):
    cand = registry
    for key, ok in FILTERS:
        v = e.get(key)
        if not v or (key == "gender" and len(v) > 1):
            continue
        nxt = [r for r in cand if ok(r, v)]
        if nxt:  # a filter that would empty the set is skipped
            cand = nxt
    return cand


def weights(e, cand):
    text = next(iter(e["text"]), "") if len(e["text"]) == 1 else "\n".join(e["text"])
    toks, out = e["tokens"], {}
    for r in cand:
        name = r["name"].casefold()
        parts = name.split()
        w = 1.0
        if name and name in text:
            w *= W_FULL
        else:
            if parts and parts[0] in toks:
                w *= W_GIVEN
            if len(parts) > 1 and parts[-1] in toks:
                w *= W_SUR
        rel = r["relative_name"].casefold()
        if rel and (rel in e["rel"] or rel in text):
            w *= W_REL
        if r["house_no"] and r["house_no"] in e["house"]:
            w *= W_HOUSE
        out[r["rid"]] = w
    return out


def link(e, registry):
    w = weights(e, candidates(e, registry))
    tot = sum(w.values())
    return {k: v / tot for k, v in w.items()} if tot else {}


# ---------------------------------------------------------------- A5 targeted attack
def hosp_key(name):
    return re.sub(r"[^a-z]", "", name.casefold().split(" hospital")[0].split(" charitable")[0].split(" multi")[0])


def a5(profiles, kf, registry, patient_rids, gaz):
    by_rid = {r["rid"]: r for r in registry}
    # global-shift recovery from confidently re-identified profiles
    offsets = collections.defaultdict(set)
    known = {k["rid"]: [dt.date.fromisoformat(d) for d in k["visit_dates"]] for k in kf}
    for p in profiles:
        if p["top_p"] >= 0.9 and p["top"] in known:
            for d in p["ev"]["dates"]:
                for kd in known[p["top"]]:
                    off = (d - kd).days
                    if abs(off) <= 366:
                        offsets[off].add(p["top"])
    agreed = [o for o, who in offsets.items() if len(who) >= 2]
    shift = max(agreed, key=lambda o: len(offsets[o])) if agreed else 0
    if 0 in agreed or not agreed:
        shift = 0
    cond_count = collections.Counter()
    for k in kf:
        if k.get("condition_hint"):
            c = k["condition_hint"].casefold()
            cond_count[c] = sum(1 for p in profiles if c in p["blob"])
    results, decoy_claims = [], 0
    for k in kf:
        target = by_rid.get(k["rid"])
        kd = set(known[k["rid"]])
        hk = hosp_key(k["hospital"])
        scored = []
        for p in profiles:
            dates = {d - dt.timedelta(days=shift) for d in p["ev"]["dates"]}
            s = 0.0
            if kd & dates:
                s += 1
            c = (k.get("condition_hint") or "").casefold()
            if c and c in p["blob"]:
                s += 8 if cond_count[c] <= 3 else 1
            if k.get("stay_days") and k["stay_days"] in p["intervals"]:
                s += 1
            if not s:
                continue
            if target is not None and k["rid"] not in {r["rid"] for r in candidates(p["ev"], registry)}:
                continue  # evidence inconsistent with this person
            if hk and hk in p["blob_nospace"]:
                s *= 2
            scored.append((s, p))
        tot = sum(s for s, _ in scored)
        if k["rid"] not in patient_rids:
            decoy_claims += 1 if scored else 0
            continue
        hit = sum(s for s, p in scored if p["true_rid"] == k["rid"]) / tot if tot else 0.0
        results.append((k["rid"], hit, len(scored)))
    return results, decoy_claims, shift


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kit", required=True, help="Secret-Wards-ToolKit folder")
    ap.add_argument("--output", required=True, help="the engine's output folder (sanitized/, records.jsonl)")
    ap.add_argument("--raw", action="store_true", help="attack the raw input at the same record locators")
    ap.add_argument("--input", help="raw input folder for --raw (default <kit>/dev/input)")
    ap.add_argument("--truth", help="truth.json for scoring (default <kit>/dev/truth/truth.json)")
    ap.add_argument("--json-out", help="write the summary as JSON here")
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = json.loads(Path(a.truth or kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    raw_in = Path(a.input or kit / "dev/input")
    registry = list(csv.DictReader(open(kit / "dev/attacker/registry.csv", encoding="utf-8")))
    kf = [json.loads(l) for l in open(kit / "dev/attacker/known_facts.jsonl", encoding="utf-8") if l.strip()]
    gaz = Gaz(registry)
    pt_rid = {pt: p["rid"] for pt, p in truth["patients"].items()}
    sha2rel = {f["sha256"]: rel for rel, f in truth["files"].items()}
    out2rel = {}
    for e in json.loads((out / "report.json").read_text(encoding="utf-8"))["files"]:
        if e.get("output"):
            out2rel[e["output"].replace("sanitized/", "", 1)] = sha2rel.get(e["input_sha256"])

    fc = FileCache()
    recs = []
    for line in open(out / "records.jsonl", encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        orel = r["file"].replace("sanitized/", "", 1)
        trel = out2rel.get(orel)
        path = (raw_in / trel) if a.raw and trel else out / "sanitized" / orel
        if not path.is_file():
            continue
        text = fc.record_text(path, r["loc"]) + f"\nsource_path: {orel}"
        unit = (truth["files"].get(trel) or {}).get("units", {}).get(r["loc"]) if trel else None
        true_rid = pt_rid.get(unit.get("patient")) if unit else None
        ev = evidence(text, gaz)
        ds = sorted(ev["dates"])
        intervals = {(b - x).days for i, x in enumerate(ds) for b in ds[i + 1:]}
        recs.append({"pseudo": r.get("patient"), "ev": ev, "true_rid": true_rid, "intervals": intervals})

    # A2/A3 record level
    rec_risk = []
    for rc in recs:
        rc["probs"] = link(rc["ev"], registry)
        if rc["true_rid"]:
            rec_risk.append(rc["probs"].get(rc["true_rid"], 0.0))
    # profiles (pooled by pseudonym; records without one stay single)
    groups = collections.defaultdict(list)
    for i, rc in enumerate(recs):
        groups[rc["pseudo"] or f"_single{i}"].append(rc)
    profiles = []
    for key, members in groups.items():
        ev = pool(m["ev"] for m in members)
        probs = link(ev, registry)
        top = max(probs, key=probs.get) if probs else None
        trues = collections.Counter(m["true_rid"] for m in members if m["true_rid"])
        blob = "\n".join(ev["text"])
        prof = {"ev": ev, "probs": probs, "top": top, "top_p": probs.get(top, 0.0) if top else 0.0,
                "true_rid": trues.most_common(1)[0][0] if trues else None, "blob": blob,
                "blob_nospace": re.sub(r"[^a-z]", "", blob),
                "intervals": set().union(*(m["intervals"] for m in members))}
        profiles.append(prof)
        for m in members:
            m["prof_risk"] = probs.get(m["true_rid"], 0.0) if m["true_rid"] else 0.0
    patients = {rc["true_rid"] for rc in recs if rc["true_rid"]}
    reid_rec = {rc["true_rid"] for rc in recs if rc["true_rid"] and rc["probs"].get(rc["true_rid"], 0) >= 0.5}
    reid_prof = {rc["true_rid"] for rc in recs if rc["true_rid"]
                 and max(rc["probs"].get(rc["true_rid"], 0), rc["prof_risk"]) >= 0.5}
    a5res, decoys, shift = a5(profiles, kf, registry, set(pt_rid.values()), gaz)

    s = {
        "mode": "raw input" if a.raw else "sanitized release",
        "records_scored": len(rec_risk), "patients_present": len(patients),
        "A3_mean_record_risk": round(sum(rec_risk) / len(rec_risk), 4) if rec_risk else None,
        "A3_records_conf_ge_0.5": round(sum(x >= 0.5 for x in rec_risk) / len(rec_risk), 4) if rec_risk else None,
        "patients_reid_record_level": round(len(reid_rec) / len(patients), 4) if patients else None,
        "patients_reid_with_profiles": round(len(reid_prof) / len(patients), 4) if patients else None,
        "A5_targets": len(a5res),
        "A5_targeted_success": round(sum(h for _, h, _ in a5res) / len(a5res), 4) if a5res else None,
        "A5_targets_mostly_hit": sum(1 for _, h, _ in a5res if h >= 0.5),
        "A5_decoy_false_claims": decoys, "A5_recovered_global_shift_days": shift,
    }
    for k, v in s.items():
        print(f"{k:<32} {v}")
    print("A5 per target (rid, success share, matching profiles):")
    for rid, h, n in a5res:
        print(f"   {rid}  {h:.2f}  {n}")
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(s, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.setrecursionlimit(10000)
    raise SystemExit(main())
