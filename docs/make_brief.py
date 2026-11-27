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
MEMBERS = "Manav · Aditya · Nishk · Kavita"
REPO = "github.com/Manav-N4/secret-ward"
PITCH = ("A privacy firewall that finds people no dictionary knows, in English, Hindi and Hinglish, "
         "and proves its privacy with its own re-identification attacker.")

ONE_PARA = (
    "secret-ward is an offline, CPU-only, LLM-free pipeline in pure Python (standard library, plus "
    "<i>cryptography</i> for the quarantine vault; Python 3.9+). It removes every identifier from a messy multi-hospital dump while keeping clinical "
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
     "a cross-script phonetic key (Devanagari to Latin, built in). Last, <b>our own trained classifier</b> (averaged "
     "perceptron, ~600 weights) catches names with no cue; it sees only word shape, endings and neighbours, never "
     "the word itself, so it cannot memorise names, and drug stems / medical suffixes veto it. Doctors, ASHA, "
     "doses (1-0-1, 650 mg), eponyms, wards and C/O-complaint vs C/O-relative are protected."),
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
    "<b>Our own model for names with no cue:</b> \"Spoke with Ramprasad about discharge\" has no label. Rules alone "
    "catch 0% of such names on our blind test (names and drug words never seen in training); with our classifier "
    "88%, while keeping 100% of drug names. It cannot memorise: it never sees the word itself.",
    "<b>Privacy we measure ourselves:</b> a re-implementation of attacks A3-A5 from ATTACKS.md, plus a second "
    "attacker written independently by QA, run on every change. They found that per-record age bands let pooled "
    "records reveal exact ages, and drove the one-band-per-patient and local k-anonymity design: 0 / 48 patients "
    "unique on what we release.",
    "<b>Precision-first, cross-script linking:</b> Mohammad in Devanagari = Mohammad = Mohd via a phonetic key, with merge "
    "blockers that kept both same-name homonym pairs apart (0 wrong merges).",
]

RESULTS = [
    ("Personal data leaked (overall / Devanagari / Hinglish)", "0 / 3230 (0.0% / 0.0% / 0.0%); canaries 0 / 4; "
     "also 0% in file names, keys, headers, metadata, base64"),
    ("Medical values kept", "4826 / 4855 (99.4%). All 29 lost are district names hidden on purpose; no medicine, "
     "dose, lab or diagnosis lost. Date intervals: 15286 / 15286 pairs exact"),
    ("Linking precision / recall / F0.5", "1.00 / 1.00 / 1.00; 0 wrong merges; both same-name homonym pairs kept apart"),
    ("Re-identification risk (our estimate)", "patients unique on what we release (gender, age band, district) against "
     "the attacker's 240-person register: <b>0 / 48</b> (raw 46 / 48; kit reference setting 20 / 48); each fits 3+ "
     "people, median 21. Dates are shifted per patient, so a known admission week does not narrow it"),
    ("Attackers, raw → ours (lower is better)", "ours: A3 record linkage 0.67 → 0.031, A4 re-identified 93.8% → 6.2%, "
     "A5 targeted 100% → 51.2%; QA's independent attacker: 97.9% → 8.3% re-identified, A5 → 47.6%"),
    ("Run time / peak memory", "200 files: 1.9 s / 35 MB. 8,000 synthetic files: 19.7 s / 282 MB (limits 15 min / "
     "4 GB). Byte-identical repeats; identical on Python 3.9-3.13; offline"),
    ("On data we did not tune on", "no registration tables 0 / 2263 leaked; free text only 0 / 569; headers renamed "
     "0 / 3230; new ID/phone/date/label formats 0 / 3230 (linking 1.00 / 1.00); QA mutation harness, 8 seeds: 0 / 3230 "
     "each; names with no cue (blind) 88% removed, drug decoys 100% kept; 40 Hinglish notes 105 / 105 name parts"),
]

LADDER = [
    ("Setting (each step kept only if the attack justified it)", "Unique", "A4", "A5", "Medical", "Gen. utility"),
    ("10-year bands only", "27%", "27%", "57%", "100%", "0.65"),
    ("+ 20-year band for groups under 3", "15%", "12.5%", "57%", "100%", "0.62"),
    ("+ hide district + PIN if still alone (shipped)", "0%", "6.2%", "51%", "99.4%", "0.41"),
]

TRADEOFF = (
    "<b>What we give up:</b> in a 48-patient release most patients get a 20-year band and 29 lose their district "
    "(generalisation utility 0.65 → 0.41); larger releases have bigger groups, so fewer are coarsened. Medicines, "
    "doses, labs and stay lengths are never touched. <b>Tried and switched off:</b> rare-diagnosis generalisation to "
    "ICD chapters cost 2.1-6.1% of medical values and left A5 flat; two independent attackers agree.")

SECURITY = (
    "Assume breach. Quarantined files, the riskiest thing we hold, are kept only as <b>AES-256-GCM ciphertext</b> "
    "named by SHA-256 (never the original name); each file has its own key and nonce derived with HKDF-SHA256 from "
    "RAKSHA_SECRET, so one leaked key opens one file, and tampering is detected. No plaintext fallback: without the "
    "library nothing is kept. No other intermediate data touches disk. RAKSHA_SECRET lives only in the environment, "
    "never printed or stored; pseudonyms and shifts are keyed HMACs, irreversible without it. stdout prints counts "
    "only; an exception hook prints only the error type; report reasons are fixed codes.")

TESTING = (
    "<b>How we tested.</b> 34 meaning-trap cases + header and number round-trips, five held-out variants, 40 Hinglish "
    "notes, a format-mutation harness that rewrites the answer key too (8 seeds, 0 leaks each), our attacker, the "
    "kit validators, and independent QA (Aditya): a clean-machine run that caught a Python 3.9 incompatibility "
    "silently quarantining every file, village leaks under a renamed header and damaged relation markers; a "
    "side-channel scan of stdout, stderr, TMPDIR, HOME, report, records and file names (0 hits; the same scanner "
    "finds all 4 canaries and 1,278 identifiers in the raw input); a scaling test that exposed quadratic name "
    "matching (now linear); and a second, independent attacker that confirms our A5 conclusion.")

LIMITS = [
    "<b>Targeted attack (A5) about 51%:</b> driven by exact length of stay + a consistent profile on common "
    "conditions (TB, typhoid, diabetes: 6-9 patients each), not by rare diseases. Stay length must stay exact for "
    "clinical integrity, so this is an accepted trade-off; larger releases dilute it.",
    "Small releases are coarsened heavily (above). Names with no cue: 88%, not 100% (sentence-initial words such "
    "as \"Met\" are sometimes taken for names); Devanagari names without cues rely on the learned gazetteer.",
    "The phonetic key is coarse; rare transliterations may not link on unseen data. XML, PDF and images are "
    "quarantined (encrypted), not cleaned. Our attackers follow the published spec; official numbers will differ.",
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
        ("Ingest", ["4 encodings", "quarantine", "(encrypted)"]),
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
    lad = Table([[Paragraph(c, CELLB if i == 0 or j == 0 else CELL) for j, c in enumerate(r)]
                 for i, r in enumerate(LADDER)],
                colWidths=[width - 5 * 19 * mm] + [19 * mm] * 5)
    lad.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), FILL), ("BACKGROUND", (0, 3), (-1, 3), FILL),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.6), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ]))
    s += [KeepTogether([Paragraph("5. Privacy-utility trade-off (measured)", H), t]), Spacer(1, 3), lad,
          Spacer(1, 2), Paragraph(TRADEOFF, BASE), Spacer(1, 2), Paragraph(TESTING, BASE),
          Paragraph("6. Security design", H), Paragraph(SECURITY, BASE),
          Paragraph("7. Known limitations", H)] + bullets(LIMITS)
    doc.build(s)


if __name__ == "__main__":
    build(HERE / "brief.pdf")
    print("wrote", HERE / "brief.pdf")
