#!/usr/bin/env python3
"""Make a format-mutated copy of the Secret Wards dev set (CSV/TSV files), with matching truth.

Why: check_dev.py scores leaks by searching the output for each truth "surface" string. If we
reformat "Mohammad Shahid" -> "Shahid, Md." in the input but keep the old truth, a leak of the
new form is never counted and the score looks falsely perfect. So this script rewrites the
truth alongside the input and verifies every truth string still occurs in the mutated file.

Mutations (CSV/TSV only, each toggleable):
  headers  rename PII column headers (e.g. "Village/Mohalla" -> "Gram/Mohalla",
           "Patient Name" -> "Rogi ka Naam")
  dates    DD/MM/YYYY or DD-MM-YYYY -> MM-DD-YY in a random fraction of date cells
           (columns whose header says MM/DD are left alone)
  names    "First [Middle] Last" -> "Last, First [Middle]" in a fraction of name cells,
           with Mohammad/Mohd/Muhammad -> "Md." (e.g. "Mohammad Shahid" -> "Shahid, Md.")

Mutations (TXT / JSON, a random share of files; separate RNG so CSV output is unchanged):
  text     free-text labels: "Name:" -> "Rogi ka Naam:", "Mob:" -> "Sampark:", "Mobile:", "DOB:", ...
           (line start or after a column gap only)
  json     plain-JSON keys: "patient_name" -> "rogi_ka_naam", "visits" -> "opd_bhent", ... (textual
           rename, so every other byte is identical; truth JSON-pointer locators renamed to match;
           file skipped if any value changes or keys collide)
  fhir     FHIR bundles keep their keys (renaming them breaks FHIR); hospital / ABHA identifier
           system URIs are swapped for other valid URIs instead

Output layout (what check_dev.py expects for --truth):
  <out>/input/...            mutated copy of dev/input (untouched files copied byte-for-byte)
  <out>/truth/truth.json     truth with surfaces / preserve texts / sha256 / size updated
  <out>/mutation_log.json    every change made, for reproducibility

The source folder is only read, never written. Stdlib only.

Usage:
  python3 qa/mutate.py --dev ../Secret-Wards-ToolKit/dev --out qa/mutated/all
  python3 qa/mutate.py --dev ... --out qa/mutated/names_only --no-headers --no-dates
"""
import argparse
import copy
import csv
import hashlib
import io
import json
import random
import re
import shutil
import sys
import unicodedata
from pathlib import Path

HEADER_MAP = {
    # names
    "Patient Name": "Rogi ka Naam", "patient_name": "rogi_ka_naam", "Naam": "Rogi ka Naam",
    "Relative Name": "Parijan ka Naam", "Pita/Pati ka Naam": "Abhibhavak (S/o-W/o-D/o)",
    "Guardian": "Abhibhavak", "LastName": "Upnaam", "FirstName": "Pehla Naam",
    # places
    "Village/Mohalla": "Gram/Mohalla", "Gaon": "Gram/Mohalla", "City": "Gram/Shehar",
    "Address": "Pata", "Pata": "Address", "Street": "Gali/Makan",
    "PIN": "Pincode", "Pin Code": "Dak Pin", "Zip": "Pin",
    # dates
    "DOB": "Janm Tithi", "Janm Tithi": "D.O.B", "DOB (MM/DD/YYYY)": "Birth Dt (MM/DD/YYYY)",
    # contact / ids
    "Mobile": "Sampark Sutra", "Mobile No": "Phone", "Phone": "Sampark No", "Email": "E-mail Pata",
    "Aadhaar No": "UID No", "Aadhar": "UIDAI", "ABHA No": "Swasthya ID",
    "UHID": "Rogi Kramank", "uhid": "reg_no", "Reg No": "Panjikaran Sankhya", "PatientID": "Rogi ID",
    "pmjay_id": "ayushman_card", "payer_pan": "pan_no", "policy_no": "bima_policy",
}
# --- free-text labels (TXT). Matched only at line start or after a column gap (2+ spaces / tab),
#     and only when followed by ":", so "Doctor Name:" or prose is never touched.
TEXT_LABELS = {
    "Patient Name": "Rogi ka Naam", "Name": "Rogi ka Naam", "Mob": "Sampark", "Mobile": "Sampark No.",
    "Address": "Pata", "DOB": "Janm Tithi", "UHID": "Panjikaran", "Reg No": "Panjikaran No",
    "Attendant": "Parijan", "ABHA No": "Swasthya ID", "Age/Sex": "Umar/Ling", "Age": "Umar",
}
TEXT_LABEL_RE = re.compile(r"(?:^|(?<=  )|(?<=\t))[ \t]*(" + "|".join(
    re.escape(k) for k in sorted(TEXT_LABELS, key=len, reverse=True)) + r")(?=[ \t]*:)", re.M)
# --- plain-JSON keys (not FHIR: renaming FHIR keys would make it invalid FHIR)
JSON_KEYS = {
    "patient_name": "rogi_ka_naam", "uhid": "panjikaran_id", "patient_ref": "rogi_sandarbh",
    "hospital_uhid": "aspatal_kramank", "mobile": "sampark_no", "phone": "sampark", "age_sex": "umar_ling",
    "age": "umar", "sex": "ling", "gender": "ling", "name": "naam", "dob": "janm_tithi",
    "guardian": "abhibhavak", "contact": "sampark_vivran", "email": "e_mail_pata", "address": "pata",
    "village": "gram", "district": "jila", "pin": "dak_pin", "aadhar_no": "uid_sankhya",
    "abha": "swasthya_id", "abha_address": "swasthya_pata", "visits": "opd_bhent", "patients": "rogi_suchi",
    "first": "pehla_naam", "last": "upnaam", "address_note": "pata_tippani", "patient": "rogi",
}
JSON_KEY_RE = re.compile(r'"(' + "|".join(re.escape(k) for k in JSON_KEYS) + r')"(\s*:)')
# --- FHIR: valid-FHIR value changes only (identifier.system URIs)
FHIR_SYS_RE = re.compile(r'"https://(\w+)\.hospital\.example/(uhid|ipd|bundles)"|"https://healthid\.abdm\.gov\.in"')
NAME_COLUMNS = {"Patient Name", "patient_name", "Naam", "Relative Name"}  # original header names
NAME_RE = re.compile(r"^[A-Za-z]+(?: [A-Za-z]+){1,2}$")
MD_ALIASES = {"mohammad", "mohammed", "muhammad", "mohd"}
DATE_RE = re.compile(r"^(\d{2})([/-])(\d{2})\2(\d{4})$")


def norm(s: str) -> str:  # identical to check_dev.py
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def decode(raw: bytes):
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16"), "utf-16"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8"), "utf-8-sig"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("cp1252"), "cp1252"


def reformat_name(s: str) -> str:
    toks = s.split(" ")
    first, last = toks[:-1], toks[-1]
    if first[0].casefold() in MD_ALIASES:
        first[0] = "MD." if first[0].isupper() else "Md."
    return f"{last}, {' '.join(first)}"


def reformat_date(s: str):
    m = DATE_RE.match(s)
    if not m:
        return None
    dd, _, mm, yyyy = m.groups()
    if not (1 <= int(dd) <= 31 and 1 <= int(mm) <= 12):
        return None
    return f"{mm}-{dd}-{yyyy[2:]}"


def serialize(rows, delim, lineterm):
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delim, lineterminator=lineterm, quoting=csv.QUOTE_MINIMAL)
    w.writerows(rows)
    return buf.getvalue()


def truth_strings(unit):
    """Mutable references to every string check_dev searches for in file content."""
    out = []
    for e in unit.get("entities", []):
        if e.get("channel") != "filename":
            out.append((e, "surface"))
    for p in unit.get("preserve") or []:
        out.append((p, "text"))
    return out


def mutate_file(rel, raw, ftruth, opts, rng, log):
    text, enc = decode(raw)
    if not text.strip():
        return None
    delim = "\t" if rel.endswith(".tsv") else ","
    lineterm = "\r\n" if "\r\n" in text else "\n"
    rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
    if len(rows) < 2:
        return None
    header = rows[0]
    lossless = serialize(rows, delim, lineterm) == text
    new_rows = [list(r) for r in rows]
    changes = []  # (record_index or None for header, col, old, new, kind)

    if opts.headers:
        for c, h in enumerate(header):
            if h in HEADER_MAP:
                new_rows[0][c] = HEADER_MAP[h]
                changes.append((None, c, h, HEADER_MAP[h], "header"))
    for ri in range(1, len(rows)):
        for c, cell in enumerate(rows[ri]):
            col = header[c] if c < len(header) else ""
            if opts.dates and "MM/DD" not in col.upper():
                nd = reformat_date(cell.strip())
                if nd and rng.random() < opts.date_frac:
                    new_rows[ri][c] = cell.replace(cell.strip(), nd)
                    changes.append((ri - 1, c, cell.strip(), nd, "date"))
                    continue
            if opts.names and col in NAME_COLUMNS and NAME_RE.match(cell.strip()) \
                    and rng.random() < opts.name_frac:
                nn = reformat_name(cell.strip())
                new_rows[ri][c] = cell.replace(cell.strip(), nn)
                changes.append((ri - 1, c, cell.strip(), nn, "name"))
    if not changes:
        return None

    # ---- rewrite truth: per record, move exactly as many truth strings as occurrences we removed
    units = ftruth["units"] if ftruth else {}
    by_row = {}
    for ri, c, old, new, kind in changes:
        if ri is not None:
            by_row.setdefault(ri, []).append((old, new))
    joined = lambda r: delim.join(r)
    for ri, pairs in by_row.items():
        unit = units.get(f"row:{ri}")
        if not unit:
            continue
        old_t, new_t = norm(joined(rows[ri + 1])), norm(joined(new_rows[ri + 1]))
        for old, new in dict.fromkeys(pairs):
            need = old_t.count(norm(old)) - new_t.count(norm(old))
            for obj, key in truth_strings(unit):
                if need <= 0:
                    break
                if old in obj[key]:
                    obj[key] = obj[key].replace(old, new)
                    need -= 1
    if ftruth:  # header renames: keep "col:<header>" references in sync
        hmap = {old: new for ri, c, old, new, k in changes if ri is None}
        fix = lambda p: "col:" + hmap.get(p[4:], p[4:]) if isinstance(p, str) and p.startswith("col:") else p
        ftruth["generalizable"] = [fix(g) for g in ftruth.get("generalizable") or []]
        for u in units.values():
            for p in u.get("preserve") or []:
                if "path" in p:
                    p["path"] = fix(p["path"])

    new_text = serialize(new_rows, delim, lineterm)
    new_raw = (b"\xef\xbb\xbf" + new_text.encode("utf-8")) if enc == "utf-8-sig" else new_text.encode(enc)
    log.append({"file": rel, "encoding": enc, "roundtrip_lossless": lossless,
                "changes": [{"row": ri, "col": header[c] if c < len(header) else c, "kind": k,
                             "old": o, "new": n} for ri, c, o, n, k in changes]})
    return new_raw, text, new_text


def _leaves(o, keys, vals):
    if isinstance(o, dict):
        keys.append(len(o))
        for v in o.values():
            _leaves(v, keys, vals)
    elif isinstance(o, list):
        for v in o:
            _leaves(v, keys, vals)
    else:
        vals.append(o)
    return keys, vals


def mutate_doc(rel, raw, opts, rng):
    """TXT label / JSON key / FHIR system mutation. Returns (new_raw, old_text, new_text, keymap, counts)."""
    try:
        text, enc = decode(raw)
    except UnicodeDecodeError:
        return None
    if text.encode("utf-8" if enc == "utf-8-sig" else enc) != (raw[3:] if enc == "utf-8-sig" else raw):
        return None  # not losslessly re-encodable: leave untouched
    counts, keymap = {}, {}
    if rel.endswith(".txt"):
        if not opts.text or rng.random() >= opts.text_frac:
            return None
        def sub(m):
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
            return m.group(0).replace(m.group(1), TEXT_LABELS[m.group(1)])
        new_text = TEXT_LABEL_RE.sub(sub, text)
    else:
        try:
            old_obj = json.loads(text)
            old_sig = _leaves(old_obj, [], [])
        except (ValueError, RecursionError):
            return None  # malformed / trap files stay as they are
        fhir = isinstance(old_obj, dict) and "resourceType" in old_obj
        if fhir:
            if not opts.fhir or rng.random() >= opts.json_frac:
                return None
            def sub(m):
                counts[m.group(0)] = counts.get(m.group(0), 0) + 1
                if m.group(1):
                    return f'"urn:oid:2.16.356.{sum(map(ord, m.group(1))) % 1000}.{"uhid ipd bundles".split().index(m.group(2)) + 1}"'
                return '"https://abha.abdm.gov.in/identifier/abha-number"'
            new_text = FHIR_SYS_RE.sub(sub, text)
        else:
            if not opts.json or rng.random() >= opts.json_frac:
                return None
            def sub(m):
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
                keymap[m.group(1)] = JSON_KEYS[m.group(1)]
                return f'"{JSON_KEYS[m.group(1)]}"{m.group(2)}'
            new_text = JSON_KEY_RE.sub(sub, text)
        try:  # structural validity: parses, same number of keys per object, identical leaf values
            new_sig = _leaves(json.loads(new_text), [], [])
        except (ValueError, RecursionError):
            return None
        if fhir:
            ok = new_sig[0] == old_sig[0] and len(new_sig[1]) == len(old_sig[1])
        else:
            ok = new_sig == old_sig
        if not ok:
            return None  # key collision or damage: skip this file rather than emit bad JSON
    if new_text == text:
        return None
    new_raw = (b"\xef\xbb\xbf" + new_text.encode("utf-8")) if enc == "utf-8-sig" else new_text.encode(enc)
    return new_raw, text, new_text, keymap, counts


def fix_ptr(p, keymap):
    if not keymap or not isinstance(p, str) or not p.startswith("/"):
        return p
    return "/".join(keymap.get(seg, seg) for seg in p.split("/"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dev", required=True, help="toolkit dev/ folder (has input/ and truth/truth.json)")
    ap.add_argument("--out", required=True, help="new folder to create (must not exist)")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--date-frac", type=float, default=0.5)
    ap.add_argument("--name-frac", type=float, default=0.35)
    ap.add_argument("--no-headers", dest="headers", action="store_false")
    ap.add_argument("--no-dates", dest="dates", action="store_false")
    ap.add_argument("--no-names", dest="names", action="store_false")
    ap.add_argument("--text-frac", type=float, default=0.7, help="share of .txt files whose labels are renamed")
    ap.add_argument("--json-frac", type=float, default=0.7, help="share of .json files mutated")
    ap.add_argument("--no-text", dest="text", action="store_false", help="skip TXT label renames")
    ap.add_argument("--no-json", dest="json", action="store_false", help="skip plain-JSON key renames")
    ap.add_argument("--no-fhir", dest="fhir", action="store_false", help="skip FHIR identifier-system changes")
    ap.add_argument("--no-csv", dest="csv", action="store_false", help="skip all CSV/TSV mutations")
    opts = ap.parse_args()
    if not opts.csv:
        opts.headers = opts.dates = opts.names = False

    dev, out = Path(opts.dev).resolve(), Path(opts.out).resolve()
    src_in = dev / "input"
    if out.exists():
        sys.exit(f"refusing to overwrite existing folder: {out}")
    if out == dev or dev in out.parents or src_in in out.parents:
        sys.exit("output folder must be outside the source dev folder")
    truth = json.loads((dev / "truth" / "truth.json").read_text(encoding="utf-8"))
    orig_truth = copy.deepcopy(truth)
    rng = random.Random(opts.seed)

    shutil.copytree(src_in, out / "input")  # byte-for-byte copy; mutated files overwritten below
    log, problems = [], []
    for p in sorted(src_in.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (".csv", ".tsv"):
            continue
        rel = p.relative_to(src_in).as_posix()
        ft = truth["files"].get(rel)
        res = mutate_file(rel, p.read_bytes(), ft, opts, rng, log)
        if not res:
            continue
        new_raw, old_text, new_text = res
        (out / "input" / rel).write_bytes(new_raw)
        if ft:
            ft["sha256"] = hashlib.sha256(new_raw).hexdigest()
            ft["size"] = len(new_raw)
            # invariant: every truth string findable before must be findable after
            on, nn = norm(old_text), norm(new_text)
            ou = orig_truth["files"][rel]["units"]
            for loc, u in ft["units"].items():
                for (o_obj, k), (n_obj, _) in zip(truth_strings(ou[loc]), truth_strings(u)):
                    if norm(o_obj[k]) in on and norm(n_obj[k]) not in nn:
                        problems.append((rel, loc, o_obj[k], n_obj[k]))

    # ---- TXT / JSON / FHIR (separate RNG so CSV results stay identical for a given seed)
    rng2 = random.Random(opts.seed + 1)
    for p in sorted(src_in.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in (".txt", ".json"):
            continue
        rel = p.relative_to(src_in).as_posix()
        res = mutate_doc(rel, p.read_bytes(), opts, rng2)
        if not res:
            continue
        new_raw, old_text, new_text, keymap, counts = res
        (out / "input" / rel).write_bytes(new_raw)
        kind = "text_label" if rel.endswith(".txt") else ("json_key" if keymap else "fhir_system")
        log.append({"file": rel, "kind": kind, "changes": [{"kind": kind, "old": k, "new":
                    TEXT_LABELS.get(k) or JSON_KEYS.get(k) or "(uri)", "n": n} for k, n in counts.items()]})
        ft = truth["files"].get(rel)
        if not ft:
            continue
        ft["sha256"], ft["size"] = hashlib.sha256(new_raw).hexdigest(), len(new_raw)
        if keymap:  # renamed keys: rewrite JSON-pointer locators and preserve paths
            new_units = {}
            for loc, u in ft["units"].items():
                nl = fix_ptr(loc, keymap)
                if "loc" in u:
                    u["loc"] = nl
                for pv in u.get("preserve") or []:
                    if "path" in pv:
                        pv["path"] = fix_ptr(pv["path"], keymap)
                new_units[nl] = u
            ft["units"] = new_units
            ft["generalizable"] = [fix_ptr(g, keymap) for g in ft.get("generalizable") or []]
        on, nn = norm(old_text), norm(new_text)
        for ou, u in zip(orig_truth["files"][rel]["units"].values(), ft["units"].values()):
            for (o_obj, k), (n_obj, _) in zip(truth_strings(ou), truth_strings(u)):
                if norm(o_obj[k]) in on and norm(n_obj[k]) not in nn:
                    problems.append((rel, "?", o_obj[k], n_obj[k]))

    (out / "truth").mkdir()
    (out / "truth" / "truth.json").write_text(json.dumps(truth, ensure_ascii=False, indent=1), encoding="utf-8")
    kinds = {}
    for f in log:
        for c in f["changes"]:
            kinds[c["kind"]] = kinds.get(c["kind"], 0) + c.get("n", 1)
    summary = {"seed": opts.seed, "headers": opts.headers, "dates": opts.dates, "names": opts.names,
               "date_frac": opts.date_frac, "name_frac": opts.name_frac,
               "text": opts.text, "json": opts.json, "fhir": opts.fhir,
               "text_frac": opts.text_frac, "json_frac": opts.json_frac,
               "files_mutated": len(log), "changes_by_kind": kinds,
               "truth_invariant_violations": len(problems)}
    (out / "mutation_log.json").write_text(json.dumps({"summary": summary, "files": log}, ensure_ascii=False,
                                                      indent=1), encoding="utf-8")
    print(json.dumps(summary))
    for pr in problems[:20]:
        print("TRUTH INVARIANT VIOLATION:", pr, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
