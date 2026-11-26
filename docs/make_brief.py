#!/usr/bin/env python3
"""Builds docs/brief.pdf (the 2-page Project Brief). Edit the TEXT below, then run:

    python3 docs/make_brief.py

Requires reportlab (dev machine only; NOT a dependency of the pipeline).
Rules from the kit: A4, 2 pages maximum, 10 pt or larger.
"""
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

HERE = Path(__file__).resolve().parent
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
pdfmetrics.registerFont(TTFont("Body", str(FONT_DIR / "DejaVuSansCondensed.ttf")))
pdfmetrics.registerFont(TTFont("Body-Bold", str(FONT_DIR / "DejaVuSansCondensed-Bold.ttf")))
pdfmetrics.registerFontFamily("Body", normal="Body", bold="Body-Bold", italic="Body", boldItalic="Body-Bold")

INK = colors.HexColor("#1F2933")
ACCENT = colors.HexColor("#0B6E4F")
MUTED = colors.HexColor("#52606D")
RULE = colors.HexColor("#CBD2D9")
FILL = colors.HexColor("#EEF5F1")

BASE = ParagraphStyle("base", fontName="Body", fontSize=10, leading=12.2, textColor=INK, alignment=TA_LEFT)
TITLE = ParagraphStyle("title", parent=BASE, fontName="Body-Bold", fontSize=14.5, leading=17, textColor=ACCENT)
META = ParagraphStyle("meta", parent=BASE, textColor=MUTED, spaceAfter=3)
H = ParagraphStyle("h", parent=BASE, fontName="Body-Bold", fontSize=11, leading=13, textColor=ACCENT,
                   spaceBefore=5, spaceAfter=2)
BUL = ParagraphStyle("bul", parent=BASE, leftIndent=9, bulletIndent=0, spaceAfter=1.2)
CELL = ParagraphStyle("cell", parent=BASE, leading=11.6)
CELLB = ParagraphStyle("cellb", parent=CELL, fontName="Body-Bold")

# ----------------------------------------------------------------------------- text
TEAM = "secret-ward"
MEMBERS = "Manav · Aditya · Nishk · [fourth member]"
REPO = "github.com/Manav-N4/secret-ward"
PITCH = ("A privacy firewall that finds people no dictionary knows, in English, Hindi and Hinglish, "
         "and proves its privacy with its own re-identification attacker.")

ONE_PARA = (
    "secret-ward is an offline, CPU-only, LLM-free pipeline in pure Python (standard library only, "
    "Python 3.9+). It removes every identifier from a messy multi-hospital dump while keeping clinical "
    "values exact, gives each patient one keyed pseudonym across files, languages and hospitals, and "
    "generalises quasi-identifiers only where our own attack shows a patient is still exposed. The key "
    "idea: <b>nothing is memorised</b>. Column meanings are inferred from their values, and the name, "
    "place and ID lists are learned from each new input at run time, so unseen headers, new patients "
    "and planted canaries are still caught.")

HOW = [
    ("Ingestion", "UTF-8, UTF-8-BOM, UTF-16 and cp1252; CSV/TSV, JSON, FHIR R4, text. Empty, corrupt, "
     "truncated, too-deep, mislabelled, binary, PDF, image and XML files are quarantined with a fixed reason "
     "code, never copied. Python errors that hit most files exit non-zero instead of reporting success."),
    ("Detection", "Pass 1 classifies every column/key by header hints <i>and</i> value shape (phones, "
     "Aadhaar, ABHA, hospital-ID pattern, place-name morphology such as -pur/-ganj/Kalan/Khurd, S/o-W/o "
     "prefixes, dates of birth) and harvests a runtime gazetteer. Pass 2 cleans text after normalising like "
     "the scorer (NFKC, homoglyphs, zero-width, Devanagari digits, base64). Names come from labels "
     "(Name:, Naam:, and the Devanagari label), relation markers, context triggers (\"called by\", \"witnessed by\"), honorifics and "
     "Hinglish kinship words (ji, sahab, Papa, Chachu), nursing log lines, phone proximity, the gazetteer and "
     "a cross-script phonetic key (Devanagari to Latin, built in). Doctors, ASHA, doses (1-0-1, 650 mg), "
     "eponyms, wards and C/O-complaint vs C/O-relative are protected."),
    ("Linking", "Union-find over strong keys (hospital IDs, phone, Aadhaar, ABHA) with merge blockers: "
     "different gender, stated ages more than 3 years apart, or names with no shared sound-alike token never "
     "merge. Records listing many patients (indexes) never bridge two people. Name-only records join only if "
     "exactly one patient fits. Pseudonym = PSN- + HMAC-SHA256(secret, cluster), written inside each record."),
    ("Privacy layer", "Per-patient non-zero date shift (HMAC, ±180 days): intervals and stay lengths exact, "
     "no global un-shift. One truthful 10-year age band per patient across all records. DOB removed; house, "
     "mohalla, village, tehsil removed; district and 3-digit PIN kept. Local k-anonymity: patients in small "
     "(gender, band, district) groups get a 20-year band; the smallest also hide district and PIN."),
]

USP = [
    "<b>Schema-agnostic, memorisation-free detection:</b> columns are typed by content and names are learned "
    "per input. All 4 canaries (names from outside the local name pool, hidden in a visitor log, an ambulance "
    "remark, a helpdesk JSON field and a base64 attachment) are caught by context, not by a list.",
    "<b>Privacy we measure ourselves:</b> a re-implementation of attacks A3-A5 from ATTACKS.md runs on every "
    "change. It found that per-record age bands let pooled records reveal exact ages, and drove the "
    "one-band-per-patient and local k-anonymity design.",
    "<b>Precision-first, cross-script linking:</b> Mohammad in Devanagari = Mohammad = Mohd via a phonetic key, with merge "
    "blockers that kept both same-name homonym pairs apart (0 wrong merges).",
]

RESULTS = [
    ("Personal data leaked (overall / Devanagari / Hinglish)", "0 / 3230 (0.0% / 0.0% / 0.0%); canaries 0 / 4; "
     "also 0% in file names, keys, headers, metadata, base64"),
    ("Medical values kept", "4826 / 4855 (99.4%), lost = districts hidden on purpose for the smallest groups; date intervals: 15286 / 15286 pairs exact"),
    ("Linking precision / recall / F0.5", "1.00 / 1.00 / 1.00; 0 wrong merges; homonym traps kept apart"),
    ("Patients pinned to ONE registry person", "45 / 48 on raw input → 1 / 48 on our output"),
    ("Our attacker, ours vs raw (lower is better)", "A3 record linkage 0.67 → 0.031; A4 profile re-ID 93.8% → 6.2% "
     "(kit reference 16.7%); A5 targeted 100% → 51.2%"),
    ("Data we did not tune on", "no registration tables: 3 / 2263 leaked, recall 0.99; free text only: 0 / 569; "
     "headers renamed to unseen wording: 0 / 3230; new phone, ID, DOB, label formats: 0 / 3230, linking 1.00 / 1.00"),
    ("Run time / peak memory", "2.0 s / 27 MB for 200 files; linear scaling: 8,000 synthetic files with new people in "
     "every file in 18 s / 274 MB (limits 15 min / 4 GB); identical on Python 3.9-3.13; byte-identical repeats; offline"),
]

TRADEOFF = (
    "<b>Why these settings.</b> Each was chosen by measurement. 10-year bands: on the registry, gender + 5-year "
    "band + district leaves 101/240 people unique, 10-year bands 50/240. Hiding district for the smallest groups "
    "costs 26 values (0.5%) but halves A4 (12.5% to 6.2%) and lowers A5. Villages are generalised to their district (truthful, already in the record). We also built "
    "rare-diagnosis generalisation to ICD chapters and <b>switched it off</b>: for N = 1..5 it cost 2.1-6.1% of "
    "medical values and left A5 flat. Two independently built attackers (ours and QA's) agree.")

SECURITY = (
    "Assume breach: no raw or intermediate data is ever written to disk (everything stays in memory), so "
    "there is nothing to decrypt at rest. RAKSHA_SECRET is read from the environment only and never printed or "
    "stored; pseudonyms and shifts are keyed HMACs, so a leaked release cannot be reversed or linked to a release "
    "with another secret. stdout prints counts only; a custom exception hook prints only the error type (Python "
    "messages can contain record values); report reasons are fixed codes; files are identified by SHA-256, never "
    "by name; renamed files get a keyed tag. Quarantined files never reach sanitized/.")

TESTING = (
    "<b>How we tested.</b> 22 meaning-trap cases + header round-trips, three held-out variants, our attacker, the "
    "kit validators, and independent QA (Aditya): a clean-machine run that caught a Python 3.9 incompatibility "
    "silently quarantining every file, village leaks under a renamed header and damaged relation markers; a "
    "side-channel scan of stdout, stderr, TMPDIR, HOME, report, records and file names (0 hits; the same scanner "
    "finds all 4 canaries and 1,278 identifiers in the raw input); a scaling test that exposed quadratic name "
    "matching (now linear); and a second, independent attacker that confirms our A5 conclusion.")

LIMITS = [
    "<b>Residual risk, A5 (targeted attack) about 51%:</b> not rare-disease leakage. Of the rare conditions, rabies "
    "is already safe and the kala-azar patient is found purely through exact length of stay + hospital. The rest is "
    "exact length of stay and profile consistency on moderately common conditions (TB, typhoid, diabetes: 6-9 "
    "patients each). Stay length must stay exact for clinical integrity, so this is an accepted trade-off; larger "
    "releases dilute it.",
    "Names in free text with no label, relation, trigger, honorific, log structure or gazetteer match can still "
    "slip (3 / 2263 when registration tables are removed). A small CRF trained on our own synthetic data is the "
    "next step.",
    "The phonetic key is coarse; rare transliterations may not link on unseen data (practice recall 1.00).",
    "XML, PDF and images are quarantined, not cleaned. Our attacker approximates the official arena from its "
    "published spec; the official numbers will differ.",
]


# ----------------------------------------------------------------------------- diagram
def arrow(d, x1, y, x2):
    d.add(Line(x1, y, x2 - 4, y, strokeColor=MUTED, strokeWidth=1))
    d.add(Polygon([x2 - 4, y + 3, x2, y, x2 - 4, y - 3], fillColor=MUTED, strokeColor=MUTED))


def box(d, x, y, w, h, title, lines, fill=FILL):
    d.add(Rect(x, y, w, h, rx=3, ry=3, fillColor=fill, strokeColor=ACCENT, strokeWidth=0.8))
    d.add(String(x + w / 2, y + h - 11, title, fontName="Body-Bold", fontSize=8.6, fillColor=ACCENT, textAnchor="middle"))
    for i, ln in enumerate(lines):
        d.add(String(x + w / 2, y + h - 22 - i * 9.2, ln, fontName="Body", fontSize=7.6, fillColor=INK, textAnchor="middle"))


def diagram(width):
    d = Drawing(width, 74)
    stages = [
        ("Input dump", ["CSV · TSV · JSON", "FHIR · notes", "4 hospitals"]),
        ("Ingest", ["4 encodings", "quarantine", "fail loudly"]),
        ("Pass 1: learn", ["type columns", "by content,", "learn names"]),
        ("Link", ["union-find", "merge blockers", "HMAC IDs"]),
        ("Pass 2: clean", ["normalise, IDs", "dates, ages, places", "names, 3 scripts"]),
        ("Privacy", ["per-patient shift", "one band each", "local k-anon"]),
        ("Outputs", ["sanitized/", "records.jsonl", "report.json"]),
    ]
    n = len(stages)
    gap = 7
    w = (width - gap * (n - 1)) / n
    for i, (t, ls) in enumerate(stages):
        x = i * (w + gap)
        box(d, x, 24, w, 48, t, ls, fill=colors.white if i in (0, n - 1) else FILL)
        if i < n - 1:
            arrow(d, x + w, 48, x + w + gap)
    d.add(Rect(2 * (w + gap), 1, 4 * w + 3 * gap, 16, rx=3, ry=3, fillColor=colors.white,
               strokeColor=RULE, strokeWidth=0.8, strokeDashArray=[2, 2]))
    d.add(String(2 * (w + gap) + (4 * w + 3 * gap) / 2, 6,
                 "dev only: our attacker (A3-A5) + held-out tests + trap tests measure every change",
                 fontName="Body", fontSize=7.6, fillColor=MUTED, textAnchor="middle"))
    return d


# ----------------------------------------------------------------------------- build
def bullets(items, style=BUL):
    return [Paragraph(t, style, bulletText="•") for t in items]


def build(out: Path) -> None:
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=12 * mm, bottomMargin=11 * mm, title=f"{TEAM}: Project Brief",
                            author=MEMBERS)
    width = A4[0] - 30 * mm
    s = [
        Paragraph(f"{TEAM}: {PITCH}", TITLE),
        Paragraph(f"Track 3 · Secret Wards · {MEMBERS} · {REPO}", META),
        Paragraph("1. In one paragraph", H), Paragraph(ONE_PARA, BASE),
        Paragraph("2. Architecture", H), diagram(width),
        Paragraph("3. How it works", H),
    ]
    s += [Paragraph(f"<b>{k}:</b> {v}", BUL, bulletText="•") for k, v in HOW]
    s += [Paragraph("4. USP", H)] + bullets(USP)
    rows = [[Paragraph("<b>Measure (practice data)</b>", CELL), Paragraph("<b>Value</b>", CELL)]]
    rows += [[Paragraph(k, CELLB), Paragraph(v, CELL)] for k, v in RESULTS]
    t = Table(rows, colWidths=[52 * mm, width - 52 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), FILL), ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2), ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ]))
    s += [KeepTogether([Paragraph("5. Privacy-utility trade-off (measured)", H), t]), Spacer(1, 3),
          Paragraph(TRADEOFF, BASE), Spacer(1, 2), Paragraph(TESTING, BASE),
          Paragraph("6. Security design", H), Paragraph(SECURITY, BASE),
          Paragraph("7. Known limitations", H)] + bullets(LIMITS)
    doc.build(s)


if __name__ == "__main__":
    build(HERE / "brief.pdf")
    print("wrote", HERE / "brief.pdf")
