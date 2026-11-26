"""Orchestration: read -> harvest (pass 1) -> link -> sanitize (pass 2) -> write.

Fail-safe rules from the spec are enforced here: every input file appears in the report,
anything we cannot parse is quarantined (never copied), and no file content ever reaches
stdout, stderr or the report.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import dates
from .detect import AGE_PATTERNS, ID_TOKEN, sanitize_header, LABEL_RX, PRE_REL_RX, REL_RX, Ctx, _is_person, _trim_span, sanitize
from .fields import classify, clean_field, harvest_value, hint_type
from .gazetteer import Gazetteer
from .link import Evidence, Linker, name_key, norm_gender, norm_id
from .normalize import normalize
from .privacy import cluster_band, pseudonym, shift_days, short_tag, widen
from .rules import POLICY
from .conditions import ICD, RareConditions, mentions_in_text

TEXT_EXT = {".txt", ".md", ".log", ".text"}
MAX_DEPTH = 200
UUIDISH = re.compile(r"^(?:urn:uuid:)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^urn:uuid:", re.I)
PHONE_IN_TEXT = re.compile(r"(?<![A-Za-z0-9])(?:\+?91[\s-]?)?0?[6-9]\d{4}[\s-]?\d{5}(?![0-9])")
AADHAAR_IN_TEXT = re.compile(r"(?<![0-9])\d{4}[\s-]?\d{4}[\s-]?\d{4}(?![0-9])")
PHONE_LOOSE = re.compile(r"(?<![A-Za-z0-9])\+?\d[\d \-()]{9,18}\d(?![0-9])")
ABHA_IN_TEXT = re.compile(r"(?<![0-9])\d{2}-\d{4}-\d{4}-\d{4}(?![0-9])")
GENDER_IN_TEXT = re.compile(r"(?i)(?:/\s*|sex\s*[:\-]\s*)(M|F|male|female)\b")


DEVA_CHARS = re.compile(r"[\u0900-\u097F]")


class Quarantine(Exception):
    pass


@dataclass
class Unit:
    uid: str
    loc: str
    ev: Evidence = field(default_factory=Evidence)
    patient: str | None = None
    cluster: str | None = None


@dataclass
class Doc:
    rel: str
    sha: str
    kind: str            # csv | json | text
    data: object = None
    delimiter: str = ","
    units: list = field(default_factory=list)
    conv: str | None = None
    prefixes: set = field(default_factory=set)
    col_types: list = field(default_factory=list)
    path_types: dict = field(default_factory=dict)
    out_rel: str = ""


# ------------------------------------------------------------------------- reading
def decode(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="strict")
    bad = sum(1 for c in text if (ord(c) < 32 and c not in "\t\n\r") or c == "�")
    if bad > max(2, len(text) // 200):
        raise Quarantine("corrupt_text")
    return text


def depth(o, d=0) -> int:
    stack = [(o, 1)]
    best = 0
    while stack:
        x, k = stack.pop()
        best = max(best, k)
        if best > MAX_DEPTH:
            return best
        if isinstance(x, dict):
            stack.extend((v, k + 1) for v in x.values())
        elif isinstance(x, list):
            stack.extend((v, k + 1) for v in x)
    return best


def read_doc(path: Path, rel: str) -> Doc:
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    ext = path.suffix.lower()
    doc = Doc(rel=rel, sha=sha, kind="")
    try:
        if not raw.strip():
            raise Quarantine("empty_file")
        if ext not in (".csv", ".tsv", ".json") and ext not in TEXT_EXT:
            raise Quarantine("unsupported_format")
        text = decode(raw)
        if ext in (".csv", ".tsv"):
            if text.lstrip()[:1] in ("{", "["):
                raise Quarantine("format_mismatch")
            delim = "\t" if ext == ".tsv" or (text.count("\t") > text.count(",")) else ","
            rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delim))
            if not rows or not any(rows[0]):
                raise Quarantine("empty_table")
            doc.kind, doc.data, doc.delimiter = "csv", rows, delim
        elif ext == ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                raise Quarantine("malformed_json") from None
            if depth(data) > MAX_DEPTH:
                raise Quarantine("nesting_too_deep")
            doc.kind, doc.data = "json", data
        else:
            doc.kind, doc.data = "text", text
    except Quarantine as q:
        doc.kind, doc.data = "quarantine", str(q)
    except (UnicodeError, csv.Error, RecursionError):
        doc.kind, doc.data = "quarantine", "unreadable"
    return doc


# ------------------------------------------------------------------------- JSON helpers
def is_record_list(v) -> bool:
    return isinstance(v, list) and bool(v) and all(isinstance(x, dict) for x in v)


PATIENT_KEYS = re.compile(r"(?i)name|naam|uhid|mrn|phone|mobile|patient|aadha|abha|dob")


def _outside_lists_has_patient(data: dict) -> bool:
    """A lab report with a 'patient' block plus a 'panels' list is ONE record, not many."""
    for k, v in data.items():
        if is_record_list(v):
            continue
        for p, leaf in walk_leaves(v, (k,)):
            if isinstance(leaf, (str, int)) and any(PATIENT_KEYS.search(str(x)) for x in p if not isinstance(x, int)) \
                    and not str(p[0]).startswith("_"):
                return True
    return False


def json_units(data) -> list[tuple[str, object]]:
    if isinstance(data, dict) and data.get("resourceType") != "Bundle" and not _outside_lists_has_patient(data):
        lists = [(k, v) for k, v in data.items() if is_record_list(v)]
        if lists:
            out = []
            for k, v in lists:
                pk = str(k).replace("~", "~0").replace("/", "~1")
                out += [(f"/{pk}/{i}", x) for i, x in enumerate(v)]
            return out
    if isinstance(data, list) and is_record_list(data):
        return [(f"/{i}", x) for i, x in enumerate(data)]
    return [("doc", data)]


def walk_leaves(o, path=()):
    stack = [(o, path)]
    while stack:
        x, p = stack.pop()
        if isinstance(x, dict):
            for k in reversed(list(x)):
                stack.append((x[k], p + (k,)))
        elif isinstance(x, list):
            for i in range(len(x) - 1, -1, -1):
                stack.append((x[i], p + (i,)))
        else:
            yield p, x


def schema_path(p: tuple) -> tuple:
    return tuple("*" if isinstance(k, int) else k for k in p)


def last_key(p: tuple) -> str:
    for k in reversed(p):
        if not isinstance(k, int):
            return str(k)
    return ""


# ------------------------------------------------------------------------- pipeline
class Pipeline:
    def __init__(self, inp: Path, out: Path) -> None:
        self.inp, self.out = inp, out
        self.docs: list[Doc] = []
        self.gaz = Gazetteer()
        self.counts = Counter()
        self.cluster_bands: dict = {}

    # pass 0 + 1 ----------------------------------------------------------
    def load(self) -> None:
        for path in sorted(p for p in self.inp.rglob("*") if p.is_file()):
            rel = path.relative_to(self.inp).as_posix()
            self.docs.append(read_doc(path, rel))
        for d in self.docs:
            if d.kind == "csv":
                self._harvest_csv(d)
            elif d.kind == "json":
                self._harvest_json(d)
            elif d.kind == "text":
                self._harvest_text(d.data)
        self.gaz.compile()
        self._reclassify_places()
        self._resolve_conventions()

    def _harvest_csv(self, d: Doc) -> None:
        header, body = d.data[0], d.data[1:]
        cols, strong = [], []
        for j, h in enumerate(header):
            vals = [r[j] for r in body if j < len(r)]
            cols.append(classify(h, vals))
            strong.append(hint_type(h) in ("NAME", "RELNAME"))
        d.col_types = cols
        for r in body:
            for j, v in enumerate(r):
                if j < len(cols):
                    harvest_value(cols[j], v, self.gaz, strong=strong[j])
                    if cols[j] == "TEXT":
                        self._harvest_text(v)

    def _harvest_json(self, d: Doc) -> None:
        groups: dict[tuple, list] = {}
        for p, v in walk_leaves(d.data):
            groups.setdefault(schema_path(p), []).append(v)
        for sp, vals in groups.items():
            key = last_key(sp)
            typ = classify(key, vals, sp[:-1])
            d.path_types[sp] = typ
            strong = hint_type(key) in ("NAME", "RELNAME")
            for v in vals:
                harvest_value(typ, v, self.gaz, strong=strong)
                if typ == "TEXT" and isinstance(v, str):
                    self._harvest_text(v)

    @staticmethod
    def _keys(o):
        stack = [o]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                for k, v in x.items():
                    yield k
                    stack.append(v)
            elif isinstance(x, list):
                stack.extend(x)

    def _harvest_text(self, text: str) -> None:
        t = normalize(text)
        for rx in (LABEL_RX, REL_RX):
            for m in rx.finditer(t):
                span = _trim_span(m.group(2))
                if span and _is_person(span):
                    self.gaz.add_name(span)
        for m in ID_TOKEN.finditer(t):
            self.gaz.add_id(m.group(0))

    def _reclassify_places(self) -> None:
        """Pass 1b: a TEXT column whose values are mostly places learned from OTHER files is
        a village column, whatever its header says ("Gram/Shehar", "Basti", ...)."""
        known = {p.lower() for p in self.gaz.places}
        names = set(self.gaz.latin_tokens)

        def mostly(vals, pool) -> bool:
            vals = [v.strip().lower() for v in vals if isinstance(v, str) and v.strip()]
            return bool(pool) and len(vals) >= 2 and sum(v in pool for v in vals) / len(vals) >= 0.5
        changed = False
        for d in self.docs:
            if d.kind == "csv":
                for j, t in enumerate(d.col_types):
                    col = [r[j] for r in d.data[1:] if j < len(r)]
                    if t == "TEXT" and mostly(col, known):
                        d.col_types[j] = "VILLAGE"
                    elif t == "TEXT" and mostly(col, names):
                        d.col_types[j] = "NAME"          # one-word first/last name columns
                        for v in col:
                            harvest_value("NAME", v, self.gaz)
                        changed = True
                # a name column right after a Relation column holds the RELATIVE's name
                for j in range(1, len(d.col_types)):
                    if d.col_types[j] == "NAME" and d.col_types[j - 1] == "RELATION" and hint_type(d.data[0][j]) is None:
                        d.col_types[j] = "RELNAME"
            elif d.kind == "json":
                groups: dict = {}
                for p, v in walk_leaves(d.data):
                    groups.setdefault(schema_path(p), []).append(v)
                for sp, vals in groups.items():
                    if d.path_types.get(sp) == "TEXT" and mostly(vals, known):
                        d.path_types[sp] = "VILLAGE"
        if changed:
            self.gaz.compile()

    def _resolve_conventions(self) -> None:
        votes: dict[str, Counter] = {}
        for d in self.docs:
            blob = self._doc_text(d)
            if blob is None:
                continue
            d.prefixes = {re.match(r"[A-Za-z]+", m.group(0)).group(0).upper()
                          for m in ID_TOKEN.finditer(blob) if re.match(r"[A-Za-z]+", m.group(0))}
            hdr = blob[:400].lower()
            d.conv = ("MDY" if "mm/dd" in hdr else "DMY" if "dd/mm" in hdr else None) or dates.infer_convention(blob)
            if d.conv:
                for p in d.prefixes:
                    votes.setdefault(p, Counter())[d.conv] += 1
        for d in self.docs:
            if d.conv is None and d.prefixes:
                c = Counter()
                for p in d.prefixes:
                    c.update(votes.get(p, {}))
                d.conv = c.most_common(1)[0][0] if c else None
            d.conv = d.conv or "DMY"

    @staticmethod
    def _doc_text(d: Doc) -> str | None:
        if d.kind == "text":
            return d.data
        if d.kind == "csv":
            return "\n".join(",".join(r) for r in d.data)
        if d.kind == "json":
            return json.dumps(d.data, ensure_ascii=False)
        return None

    # evidence + linking --------------------------------------------------
    def build_units(self) -> None:
        for d in self.docs:
            if d.kind == "csv":
                header = d.data[0]
                for i, row in enumerate(d.data[1:]):
                    u = Unit(uid=f"{d.rel}#row:{i}", loc=f"row:{i}")
                    pairs = [(d.col_types[j], v) for j, v in enumerate(row) if j < len(d.col_types)]
                    self._evidence(u.ev, pairs, [v for (t, v) in pairs if t == "TEXT"])
                    d.units.append(u)
            elif d.kind == "json":
                for loc, sub in json_units(d.data):
                    u = Unit(uid=f"{d.rel}#{loc}", loc=loc)
                    prefix = () if loc == "doc" else tuple(int(x) if x.isdigit() else x.replace("~1", "/").replace("~0", "~") for x in loc.strip("/").split("/"))
                    pairs, texts = [], []
                    for p, v in walk_leaves(sub, prefix):
                        typ = d.path_types.get(schema_path(p), "TEXT")
                        pairs.append((typ, v, p))
                    names = self._json_names(pairs)
                    self._evidence(u.ev, [(t, v) for t, v, _ in pairs if t != "NAME"],
                                   [v for t, v, _ in pairs if t == "TEXT" and isinstance(v, str)], names)
                    d.units.append(u)
            elif d.kind == "text":
                u = Unit(uid=f"{d.rel}#doc", loc="doc")
                self._evidence(u.ev, [], [d.data])
                d.units.append(u)
        self._drop_multi_patient_bridges()
        all_units = [(u.uid, u.ev) for d in self.docs for u in d.units]
        clusters = Linker(all_units).run()
        ages: dict[str, list[int]] = {}
        for d in self.docs:
            for u in d.units:
                u.cluster = clusters.get(u.uid)
                u.patient = pseudonym(u.cluster) if u.cluster else None
                if u.cluster:
                    ages.setdefault(u.cluster, []).extend(u.ev.ages)
        self.cluster_bands = {k: cluster_band(v) for k, v in ages.items()}
        self._k_anonymity()
        self._rare_conditions()

    def _rare_conditions(self) -> None:
        """Count, per patient, every diagnosis/procedure mention; the rare ones get their
        ICD chapter instead of the exact name (see conditions.py)."""
        rc = RareConditions()
        for d in self.docs:
            for u in d.units:
                who = u.cluster or u.uid
                if d.kind == "text":
                    for c, code in mentions_in_text(normalize(d.data)):
                        rc.add(c, code, who)
                elif d.kind == "csv":
                    i = int(u.loc[4:])
                    row = d.data[1 + i]
                    codes = [v for v in row if ICD.fullmatch(v.strip() or "-")]
                    for j, v in enumerate(row):
                        t = d.col_types[j] if j < len(d.col_types) else "TEXT"
                        hdr = d.data[0][j].lower() if j < len(d.data[0]) else ""
                        if t == "MEDICAL" and any(w in hdr for w in ("procedure", "diagnos", "condition", "disease")):
                            rc.add(v, codes[0] if codes else None, who)
                        elif t == "TEXT":
                            for c, code in mentions_in_text(normalize(v)):
                                rc.add(c, code, who)
                elif d.kind == "json":
                    sub = d.data if u.loc == "doc" else self._at(d.data, u.loc)
                    for node in self._dicts(sub):
                        code = node.get("code")
                        disp = node.get("display")
                        if isinstance(code, str) and isinstance(disp, str) and ICD.fullmatch(code.strip()):
                            rc.add(disp, code.strip(), who)
                        for k in ("procedure", "diagnosis", "condition"):
                            if isinstance(node.get(k), str):
                                rc.add(node[k], None, who)
                        for k, v in node.items():
                            if isinstance(v, str) and k not in ("display", "code"):
                                for c, cd in mentions_in_text(normalize(v)):
                                    rc.add(c, cd, who)
        rc.finalise(int(POLICY.get("rare_condition_max_patients", 1)))
        self.rare = rc
        self.counts["RARE_CONDITION_TYPES"] = len(rc.rare)

    @staticmethod
    def _at(data, loc):
        cur = data
        for part in loc.strip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        return cur

    @staticmethod
    def _dicts(o):
        stack = [o]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                yield x
                stack.extend(x.values())
            elif isinstance(x, list):
                stack.extend(x)

    def _drop_multi_patient_bridges(self) -> None:
        """A record carrying several DIFFERENT patient IDs of one hospital (an index, a ward
        list, a bulk export summary) describes many people. Using it to link would glue those
        people into one pseudonym, the worst error in this task. Such records keep no
        linking keys (they get patient: null)."""
        def prefix(k: str) -> str:
            m = re.match(r"ID:([A-Z]+)", k)
            return m.group(1) if m else ""
        patient_prefixes = set()
        for d in self.docs:
            if d.kind == "csv":
                for j, t in enumerate(d.col_types):
                    if t == "PATIENTID":
                        for r in d.data[1:]:
                            if j < len(r) and norm_id(r[j]):
                                patient_prefixes.add(prefix("ID:" + norm_id(r[j])))
            elif d.kind == "json":
                for p, v in walk_leaves(d.data):
                    if d.path_types.get(schema_path(p)) == "PATIENTID" and isinstance(v, (str, int)) and norm_id(str(v)):
                        patient_prefixes.add(prefix("ID:" + norm_id(str(v))))
        patient_prefixes.discard("")
        for d in self.docs:
            for u in d.units:
                per = Counter(prefix(k) for k in u.ev.keys if k.startswith("ID:"))
                phones = sum(1 for k in u.ev.keys if k.startswith("PH:"))
                if any(n > 1 for pfx, n in per.items() if pfx in patient_prefixes) or phones > 3:
                    u.ev.keys = set()
                    self.counts["MULTI_PATIENT_RECORDS"] += 1

    def _k_anonymity(self) -> None:
        """Local generalisation: coarsen only patients in small (gender, band, district) groups.

        Measured with scripts/attack.py: gender + 10-year band + district alone singles out
        rare people (a 92-year-old man, a 5-year-old boy). Everyone else keeps full detail.
        """
        k = int(POLICY.get("min_group_size", 3))
        info = {}
        for d in self.docs:
            for u in d.units:
                if not u.cluster:
                    continue
                g, dist = info.setdefault(u.cluster, (set(), set()))
                g |= u.ev.genders
                dist |= u.ev.districts
        def key(c, band):
            g, dist = info[c]
            return (tuple(sorted(g)), band, tuple(sorted(dist)))
        groups = Counter(key(c, self.cluster_bands.get(c)) for c in info)
        self.hidden_loc = set()
        for c in sorted(info):
            if groups[key(c, self.cluster_bands.get(c))] < k:
                self.cluster_bands[c] = widen(self.cluster_bands.get(c))
                self.counts["K_ANON_WIDENED"] += 1
        groups = Counter(key(c, self.cluster_bands.get(c)) for c in info)
        for c in sorted(info):
            if groups[key(c, self.cluster_bands.get(c))] < int(POLICY.get("hide_location_below", 2)):
                self.hidden_loc.add(c)
                self.counts["K_ANON_LOCATION_HIDDEN"] += 1

    @staticmethod
    def _json_names(pairs) -> list[str]:
        """Join first/last name leaves that sit under the same parent into one name."""
        by_parent: dict[tuple, list[str]] = {}
        for t, v, p in pairs:
            # only person-shaped values: an Organization "name" such as "Sanjeevani
            # Multispeciality Hospital" must not become the patient's name (it blocked links)
            if t == "NAME" and isinstance(v, str) and v.strip() and (_is_person(v) or DEVA_CHARS.search(v)):
                by_parent.setdefault(p[:-1], []).append(v)
        out = []
        for parent in sorted(by_parent, key=str):
            vals = by_parent[parent]
            latin = [v for v in vals if v.isascii()]
            out.append(" ".join(latin) if latin else vals[0])
        return out

    def _evidence(self, ev: Evidence, pairs, texts, names=None) -> None:
        for typ, v in pairs:
            if v is None:
                continue
            s = str(v)
            if typ in ("PATIENTID", "OTHERID"):
                k = norm_id(s)
                if k:
                    ev.keys.add("ID:" + k)
            elif typ == "PHONE":
                dg = re.sub(r"\D", "", s)
                if len(dg) >= 10:
                    ev.keys.add("PH:" + dg[-10:])
            elif typ == "AADHAAR":
                dg = re.sub(r"\D", "", s)
                if len(dg) == 12:
                    ev.keys.add("AA:" + dg)
                    if dg.startswith("91") and dg[2] in "6789":
                        ev.keys.add("PH:" + dg[2:])   # "91XXXXXXXXXX" may be a phone with country code
            elif typ == "ABHA":
                dg = re.sub(r"\D", "", s)
                if len(dg) == 14:
                    ev.keys.add("AB:" + dg)
            elif typ == "NAME" and isinstance(v, str):
                k = name_key(s)
                if k:
                    ev.names.add(k)
            elif typ == "RELNAME":
                k = name_key(re.sub(r"^\s*[SDWC]/[Oo]\s*", "", s))
                if k:
                    ev.relatives.add(k)
            elif typ == "GENDER":
                g = norm_gender(s)
                if g:
                    ev.genders.add(g)
            elif typ == "AGE":
                m = re.match(r"\s*(\d{1,3})", s)
                if m:
                    ev.ages.append(int(m.group(1)))
            elif typ == "DISTRICT" and s.strip():
                ev.districts.add(s.strip().lower())
        for n in names or []:
            k = name_key(n)
            if k:
                ev.names.add(k)
        for t in texts:
            if not isinstance(t, str):
                continue
            t = normalize(t)
            for m in ID_TOKEN.finditer(t):
                k = norm_id(m.group(0))
                if k:
                    ev.keys.add("ID:" + k)
            for m in ABHA_IN_TEXT.finditer(t):
                ev.keys.add("AB:" + re.sub(r"\D", "", m.group(0)))
            for m in PHONE_IN_TEXT.finditer(t):
                ev.keys.add("PH:" + re.sub(r"\D", "", m.group(0))[-10:])
            for m in PHONE_LOOSE.finditer(t):          # "+91 (98765) 43210", "9876-543-210"
                dg = re.sub(r"\D", "", m.group(0))
                core = dg[2:] if len(dg) == 12 and dg.startswith("91") else dg[1:] if len(dg) == 11 and dg.startswith("0") else dg
                if len(core) == 10 and core[0] in "6789":
                    ev.keys.add("PH:" + core)
            for m in LABEL_RX.finditer(t):
                span = _trim_span(m.group(2))
                if span and _is_person(span):
                    k = name_key(span)
                    if k:
                        ev.names.add(k)
            for m in PRE_REL_RX.finditer(t):
                span = _trim_span(m.group(1))
                if span and _is_person(span):
                    k = name_key(span)
                    if k:
                        ev.names.add(k)
            for m in REL_RX.finditer(t):
                span = _trim_span(m.group(2))
                if span and _is_person(span):
                    k = name_key(span)
                    if k:
                        ev.relatives.add(k)
            for m in GENDER_IN_TEXT.finditer(t):
                g = norm_gender(m.group(1))
                if g:
                    ev.genders.add(g)
            # strict age forms only ("Age: 52", "46 Yrs/M", "52 वर्ष"); "x 8 yrs" is a disease
            # duration, and reading it as an age blocked correct links and widened bands
            for rx in AGE_PATTERNS:
                m = rx.search(t)
                if m:
                    a = int(m.group(2))
                    if a <= 120 and t[max(0, m.start(2) - 1):m.start(2)] not in ("-", "+"):
                        ev.ages.append(a)
                    break

    # pass 2 --------------------------------------------------------------
    def ctx_for(self, d: Doc, u: Unit | None) -> Ctx:
        ck = u.cluster if u and u.cluster else (u.uid if u else d.rel)
        ctx = Ctx(gaz=self.gaz, shift=shift_days(ck), conv=d.conv or "DMY",
                  pseudonym=u.patient if u else None)
        if u:
            ctx.own_ids = {k[3:] for k in u.ev.keys if k.startswith("ID:")}
            ctx.band = self.cluster_bands.get(u.cluster) if u.cluster else cluster_band(u.ev.ages)
            ctx.hide_location = u.cluster in getattr(self, "hidden_loc", set())
        ctx.rare = getattr(self, "rare", None)
        return ctx

    def sanitize_csv(self, d: Doc) -> str:
        header, body = d.data[0], d.data[1:]
        hctx = Ctx(gaz=self.gaz, conv=d.conv)
        new_header = [sanitize_header(h, hctx) for h in header]
        has_pid = "PATIENTID" in d.col_types
        first_name = d.col_types.index("NAME") if "NAME" in d.col_types else -1
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=d.delimiter, lineterminator="\n")
        w.writerow(new_header)
        dist_col = d.col_types.index("DISTRICT") if "DISTRICT" in d.col_types else -1
        for u, row in zip(d.units, body):
            ctx = self.ctx_for(d, u)
            if 0 <= dist_col < len(row) and row[dist_col].strip():
                ctx.district = row[dist_col].strip()
            out = []
            for j, v in enumerate(row):
                typ = d.col_types[j] if j < len(d.col_types) else "TEXT"
                out.append(clean_field(typ, v, ctx, patient_slot=(not has_pid and j == first_name)))
            if u.patient and not ctx.used_pseudonym:
                u.patient = None          # pseudonym must appear inside the record, or we don't claim it
            w.writerow(out)
            self.counts.update(ctx.counts)
        self.counts.update(hctx.counts)
        return buf.getvalue()

    def sanitize_json(self, d: Doc) -> str:
        units = {u.loc: u for u in d.units}
        file_ctx = self.ctx_for(d, units.get("doc"))
        if "doc" in units:
            file_ctx.district = self._district_in(d.data, d, ())
        used = {}

        def clean(o, path, ctx):
            loc = "/" + "/".join(str(x).replace("~", "~0").replace("/", "~1") for x in path)
            if loc in units and units[loc] is not None and loc != "/":
                ctx = self.ctx_for(d, units[loc])
                ctx.district = self._district_in(o, d, path)
                used[loc] = ctx
            if isinstance(o, dict):
                url = str(o.get("url", "")).lower()
                if isinstance(o.get("valueString"), str) and re.search(r"name|mother|father|husband|guardian|relative|spouse", url):
                    o = dict(o)
                    o["valueString"] = clean_field("RELNAME", o["valueString"], ctx)
                new = {}
                for k, v in o.items():
                    nk = sanitize(str(k), ctx) if isinstance(k, str) else k
                    if nk in new:
                        nk = f"{nk}_{len(new)}"
                    typ = d.path_types.get(schema_path(path + (k,)), "TEXT")
                    if typ == "DOB" and isinstance(d.data, dict) and d.data.get("resourceType"):
                        ctx.counts["DOB"] += 1
                        continue           # FHIR birthDate must be a valid date or absent
                    new[nk] = clean(v, path + (k,), ctx)
                return new
            if isinstance(o, list):
                return [clean(x, path + (i,), ctx) for i, x in enumerate(o)]
            typ = d.path_types.get(schema_path(path), "TEXT")
            key = last_key(path)
            if isinstance(o, str) and key in ("id", "fullUrl", "reference") and UUIDISH.match(o):
                return o
            slot = typ == "NAME" and not any(t == "PATIENTID" for t in d.path_types.values())
            return clean_field(typ, o, ctx, patient_slot=slot)

        result = clean(d.data, (), file_ctx)
        for u in d.units:
            ctx = file_ctx if u.loc == "doc" else used.get(u.loc)
            if u.patient and not (ctx and ctx.used_pseudonym):
                u.patient = None
            if ctx and ctx is not file_ctx:
                self.counts.update(ctx.counts)
        self.counts.update(file_ctx.counts)
        return json.dumps(result, ensure_ascii=False, indent=2) + "\n"

    def _district_in(self, o, d: Doc, path: tuple):
        """The district stated inside one JSON record (or a nested object of it), if any."""
        for p, v in walk_leaves(o, path):
            if d.path_types.get(schema_path(p)) == "DISTRICT" and isinstance(v, str) and v.strip():
                return v.strip()
        return None

    def sanitize_text(self, d: Doc) -> str:
        u = d.units[0]
        ctx = self.ctx_for(d, u)
        out = sanitize(d.data, ctx)
        if u.patient and not ctx.used_pseudonym:
            out = out.rstrip("\n") + f"\nPatient: {u.patient}\n"
        self.counts.update(ctx.counts)
        return out

    def out_name(self, d: Doc) -> str:
        p = PurePosixPath(d.rel)
        ctx = Ctx(gaz=self.gaz)
        stem = sanitize(p.stem, ctx)
        if stem == normalize(p.stem):
            return d.rel
        safe = re.sub(r"[^A-Za-z0-9_\-]+", "_", stem.replace("[", "").replace("]", "")).strip("_")
        return str(p.with_name(f"{safe}_{short_tag(d.rel)}{p.suffix}"))

    def write(self) -> list[dict]:
        san = self.out / "sanitized"
        files = []
        for d in self.docs:
            entry = {"input_sha256": d.sha}
            if d.kind == "quarantine":
                entry.update(output=None, status="quarantined", reason=d.data)
                files.append(entry)
                continue
            try:
                result = {"csv": self.sanitize_csv, "json": self.sanitize_json, "text": self.sanitize_text}[d.kind](d)
                d.out_rel = self.out_name(d)
                dest = san / d.out_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                # open(..., newline="") works on every Python 3; Path.write_text(newline=)
                # is 3.10+ only and silently broke every file on 3.9
                with open(dest, "w", encoding="utf-8", newline="") as fh:
                    fh.write(result)
                entry.update(output=f"sanitized/{d.out_rel}", status="sanitized")
            except Exception as exc:  # noqa: BLE001 - fail safe, reason never holds content
                d.kind = "quarantine"
                entry.update(output=None, status="quarantined", reason="processing_error_" + type(exc).__name__)
            files.append(entry)
        return files
