#!/usr/bin/env python3
"""Builds docs/brief.pdf (the 2-page Project Brief). Edit the TEXT section, then run:

    python3 docs/make_brief.py

Requires reportlab (dev machine only; NOT a dependency of the pipeline).
Kit rules: A4, 2 pages maximum, 10 pt or larger. Sections follow docs/PROJECT_BRIEF.md.
"""
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

HERE = Path(__file__).resolve().parent
FONTS = Path("/usr/share/fonts/truetype/crosextra")
pdfmetrics.registerFont(TTFont("Body", str(FONTS / "Carlito-Regular.ttf")))
pdfmetrics.registerFont(TTFont("Body-Bold", str(FONTS / "Carlito-Bold.ttf")))
pdfmetrics.registerFont(TTFont("Body-Italic", str(FONTS / "Carlito-Italic.ttf")))
pdfmetrics.registerFont(TTFont("Deva", "/usr/share/fonts/truetype/freefont/FreeSans.ttf"))
pdfmetrics.registerFontFamily("Body", normal="Body", bold="Body-Bold", italic="Body-Italic", boldItalic="Body-Bold")

INK = colors.HexColor("#1F2933")
MUTED = colors.HexColor("#52606D")
GREEN = colors.HexColor("#0B6E4F")
GREEN_D = colors.HexColor("#08503A")
TINT = colors.HexColor("#EEF5F1")
ZEBRA = colors.HexColor("#F6F8F7")
RULE = colors.HexColor("#D5DDD8")
WHITE = colors.white

W = A4[0] - 32 * mm          # text width

S_BODY = ParagraphStyle("body", fontName="Body", fontSize=10.5, leading=13.4, textColor=INK)
S_SMALL = ParagraphStyle("small", parent=S_BODY, fontSize=10, leading=12.4)
S_CELL = ParagraphStyle("cell", parent=S_BODY, fontSize=10, leading=12.3)
S_CELLB = ParagraphStyle("cellb", parent=S_CELL, fontName="Body-Bold", textColor=GREEN_D)
S_H = ParagraphStyle("h", parent=S_BODY, fontName="Body-Bold", fontSize=13, leading=15.5, textColor=GREEN,
                     spaceBefore=6, spaceAfter=3)
S_CARD_T = ParagraphStyle("cardt", parent=S_BODY, fontName="Body-Bold", fontSize=10.5, leading=13, textColor=GREEN_D)
S_TITLE = ParagraphStyle("title", parent=S_BODY, fontName="Body-Bold", fontSize=22, leading=25, textColor=WHITE)
S_PITCH = ParagraphStyle("pitch", parent=S_BODY, fontSize=12, leading=15, textColor=WHITE)
S_META = ParagraphStyle("meta", parent=S_BODY, fontSize=10, leading=12.5, textColor=colors.HexColor("#CFE6DC"))
S_KPI_N = ParagraphStyle("kpin", parent=S_BODY, fontName="Body-Bold", fontSize=17, leading=20, textColor=GREEN_D,
                         alignment=1)
S_KPI_L = ParagraphStyle("kpil", parent=S_BODY, fontSize=10, leading=11.6, textColor=MUTED, alignment=1)
S_BUL = ParagraphStyle("bul", parent=S_SMALL, leftIndent=10, bulletIndent=0, spaceAfter=2)

# ----------------------------------------------------------------------------- TEXT
# Structure and labels follow the kit's brief/PROJECT_BRIEF_TEMPLATE.md exactly.
TEAM = "secret-ward"
PITCH = ("an offline privacy firewall that finds people no dictionary knows, in English, Hindi and Hinglish, "
         "and proves its privacy by attacking itself")
META = ("<b>Track 3 · Secret Wards</b> &nbsp;·&nbsp; <b>Members:</b> Manav, Aditya, Nishk, Kavita "
        "&nbsp;·&nbsp; <b>Repo:</b> github.com/Manav-N4/secret-ward")

ONE_PARA = (
    "secret-ward turns a messy multi-hospital dump (CSV, TSV, JSON, FHIR, notes, in three scripts) into a research "
    "release: every identifier removed, every clinical value exact, one keyed pseudonym per patient across files and "
    "hospitals. <b>The single idea that makes it better than a plain PII tool: nothing is memorised.</b> Column "
    "meanings come from the values, names and IDs are learned from each input at run time, and a small model we "
    "trained ourselves catches names with no cue at all, so unseen headers, new patients and planted canaries are "
    "still caught. Offline, CPU-only, no LLM, and it re-checks its own output before release.")

HOW = [
    ("Ingestion", "UTF-8, UTF-8 BOM, UTF-16 (with or without BOM), cp1252; CSV, TSV, JSON, FHIR R4, text; unknown "
     "extensions sniffed by content. Empty, corrupt, truncated, too-deep, mislabelled, PDF, image and XML files are "
     "<b>quarantined</b> with a fixed reason code, kept only encrypted, never copied. A memory and time governor and "
     "crash isolation mean the report is always written."),
    ("Detection", "<b>Rules:</b> columns typed by header <i>and</i> value shape (Aadhaar, ABHA, phone, ID pattern, "
     "place endings -pur/-ganj); text normalised like the scorer (NFKC, homoglyphs, zero-width, base64). "
     "<b>English, Hindi, Hinglish:</b> labels (Name:, Naam:, <font name='Deva'>नाम</font>:), relation markers "
     "(S/o, W/o), honorifics and kin words (ji, sahab, Chachu). <b>Gazetteer</b> learned per input; "
     "<b>transliteration</b> to a cross-script phonetic key (<font name='Deva'>रमेश</font> = Ramesh); "
     "<b>classical ML:</b> our own averaged perceptron for names with no cue. <b>Meaning traps:</b> doctors, doses "
     "(1-0-1), eponyms and “C/O fever” vs “C/O Ramesh” are protected."),
    ("Linkage &amp;<br/>pseudonyms", "Union-find on strong keys (hospital ID, phone, Aadhaar, ABHA). <b>Blocking:</b> "
     "name-only records are compared only with clusters sharing their name tokens. Phonetic, cross-script name keys "
     "(Mohammad = Mohd). <b>No over-merging:</b> different gender, ages over 3 years apart or no sound-alike name "
     "never merge; records listing many patients never bridge two. <b>Keyed HMAC IDs:</b> PSN- + "
     "HMAC-SHA256(secret, patient), written inside every record."),
    ("Privacy layer", "<b>Date shifting:</b> one secret, non-zero shift per patient (±180 days), so intervals and "
     "stay lengths stay exact. <b>Age bands:</b> one truthful 10-year band per patient. <b>Location:</b> house and "
     "village removed; district and 3-digit PIN kept. <b>Rare-value suppression:</b> local k-anonymity (k = 3): "
     "small groups get a 20-year band, anyone still alone loses district and PIN."),
    ("Security", "<b>Encryption at rest:</b> quarantined files kept only as AES-256-GCM ciphertext, named by hash; "
     "everything else is processed in memory. <b>Keys:</b> RAKSHA_SECRET only in the environment, never written; "
     "per-file keys via HKDF. <b>PII-free logs:</b> counts and fixed codes only (QA side-channel scan: 0 hits). "
     "<b>Release gate:</b> every output file and path is re-checked against all identifiers learned from the input."),
]

USP = [
    ("Works on data it has never seen",
     "Nothing memorised; our classifier never sees the word. Renamed headers, new formats, 8 mutations: 0 leaks. "
     "Cue-less names: 0% → 88%."),
    ("Privacy proven by attack",
     "Two independently built attackers agree: re-identification 98% → 6–8%. Each setting kept only if the "
     "attack justified its cost."),
    ("Built for failure, self-audited",
     "Resource governor, crash isolation, encrypted quarantine, a release gate. Torture test (60 MB bulk, PII "
     "folders, symlinks): 0 leaks."),
]

RESULTS = [
    ("personal data leaked<br/>(overall / Hindi / Hinglish)",
     "<b>0% / 0% / 0%</b>: 0 of 3,230 pieces; canaries 0 / 4; 0% in file names, keys, headers, metadata, base64"),
    ("medical values kept", "<b>99.4%</b> (4,826 / 4,855): all 29 lost are district names hidden on purpose; "
     "15,286 / 15,286 date intervals exact"),
    ("linking precision / recall / F0.5", "<b>1.00 / 1.00 / 1.00</b>; 0 wrong merges; both homonym pairs kept apart"),
    ("re-identification risk<br/>(our estimate)", "<b>0%</b> of patients unique on gender + age band + district "
     "against the attacker's 240-person register (0 / 48; raw data 96%, kit reference setting 42%). Admission week "
     "adds nothing: dates are shifted per patient. Attacks, raw → ours: A4 93.8% → 6.2%, A5 100% → 51%"),
    ("run time / peak memory", "<b>2.0 s / 36 MB</b> for 200 files; 24 s / 267 MB for 8,000 files "
     "(limits 15 min / 4 GB); byte-identical repeats"),
    ("on data you did not tune on", "no registration tables 0 / 2,263 leaked; free text only 0 / 569; renamed "
     "headers and new formats 0 / 3,230; 8 mutation seeds 0 each; 40 Hinglish notes 105 / 105 name parts; "
     "torture test 0"),
]

LADDER = [
    ("How each setting was chosen", "Unique", "A4", "A5", "Medical", "Utility*"),
    ("10-year age bands only", "27%", "27%", "57%", "100%", "0.65"),
    ("+ 20-year band for groups smaller than 3", "15%", "12.5%", "57%", "100%", "0.62"),
    ("<b>+ hide district and PIN if still alone (shipped)</b>", "<b>0%</b>", "<b>6.2%</b>", "<b>51%</b>",
     "<b>99.4%</b>", "<b>0.41</b>"),
]

TRADEOFF = (
    "<b>Why these settings.</b> Each step was kept only if the attack numbers justified its cost. <b>What we give "
    "up:</b> in a 48-patient release most patients get a 20-year band and 29 lose their district (*generalisation "
    "utility 0.65 → 0.41); bigger releases have bigger groups, so fewer are coarsened. Medicines, doses, labs and stay "
    "lengths are never touched. <b>What we gain:</b> no patient is unique on what we release. <b>Tried and switched "
    "off:</b> generalising rare diagnoses to ICD chapters cost 2–6% of medical values and did not lower A5.")

LIMITS = [
    "<b>Targeted attack (A5) about 51%.</b> Driven by the exact length of stay plus a consistent profile on common "
    "conditions (TB, typhoid, diabetes), not by rare diseases. Stay lengths must stay exact, so we accept it; larger "
    "releases dilute it.",
    "<b>Small releases are coarsened heavily</b> (above). <b>Names with no cue: 88%, not 100%</b>: sentence-initial "
    "words such as “Met” are sometimes taken for names.",
    "XML, PDF and images, and any single file above ~43 MB (memory governor), are quarantined rather than cleaned. "
    "<b>Next:</b> stream large files instead of quarantining them, and clean text inside PDFs.",
    "Our attackers follow the published attack spec; the official arena's numbers will differ.",
]

# ----------------------------------------------------------------------------- pieces
def header():
    t = Table([[Paragraph(TEAM, S_TITLE)], [Paragraph(PITCH[0].upper() + PITCH[1:], S_PITCH)],
               [Paragraph(META, S_META)]],
              colWidths=[W + 32 * mm - 2])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), GREEN),
        ("LEFTPADDING", (0, 0), (-1, -1), 16 * mm), ("RIGHTPADDING", (0, 0), (-1, -1), 16 * mm),
        ("TOPPADDING", (0, 0), (-1, 0), 7 * mm), ("BOTTOMPADDING", (0, 0), (-1, 0), 1),
        ("TOPPADDING", (0, 1), (-1, 1), 1), ("BOTTOMPADDING", (0, 1), (-1, 1), 3),
        ("TOPPADDING", (0, 2), (-1, 2), 2), ("BOTTOMPADDING", (0, 2), (-1, 2), 5 * mm),
    ]))
    return t


def kpis():
    cw = W / len(KPIS)
    t = Table([[Paragraph(n, S_KPI_N) for n, _ in KPIS], [Paragraph(l, S_KPI_L) for _, l in KPIS]],
              colWidths=[cw] * len(KPIS))
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), TINT),
        ("LINEAFTER", (0, 0), (-2, -1), 2, WHITE),
        ("TOPPADDING", (0, 0), (-1, 0), 7), ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
        ("TOPPADDING", (0, 1), (-1, 1), 0), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def h(n, text):
    return Paragraph(f"<font color='#9FB8AD'>{n}</font>&nbsp;&nbsp;{text}", S_H)


def arrow(d, x1, y, x2):
    d.add(Line(x1 + 1, y, x2 - 5, y, strokeColor=MUTED, strokeWidth=1.1))
    d.add(Polygon([x2 - 5, y + 3, x2, y, x2 - 5, y - 3], fillColor=MUTED, strokeColor=MUTED))


def diagram():
    d = Drawing(W, 96)
    stages = [("Input files", ["CSV · TSV · JSON", "FHIR · text notes", "EN · HI · Hinglish"], False),
              ("Ingestion", ["4 encodings", "normalise text", "sniff content"], True),
              ("Detection", ["type columns,", "learn names / IDs", "(pass 1)"], True),
              ("Linking", ["strong keys", "merge blockers", "keyed HMAC IDs"], True),
              ("Privacy layer", ["clean text (pass 2)", "shift dates, bands", "local k-anon"], True),
              ("Outputs", ["sanitized/", "report.json", "records.jsonl"], False)]
    n, gap = len(stages), 9
    bw = (W - gap * (n - 1)) / n
    top, bh = 92, 54
    for i, (t, lines, inner) in enumerate(stages):
        x = i * (bw + gap)
        d.add(Rect(x, top - bh, bw, bh, rx=4, ry=4, fillColor=TINT if inner else WHITE,
                   strokeColor=GREEN, strokeWidth=0.9))
        d.add(String(x + bw / 2, top - 14, t, fontName="Body-Bold", fontSize=10.5, fillColor=GREEN_D,
                     textAnchor="middle"))
        for k, ln in enumerate(lines):
            d.add(String(x + bw / 2, top - 27 - k * 10, ln, fontName="Body", fontSize=9.5, fillColor=INK,
                         textAnchor="middle"))
        if i < n - 1:
            arrow(d, x + bw, top - bh / 2, x + bw + gap)
    x_ing = bw + gap + bw / 2
    x_out = (n - 1) * (bw + gap)
    d.add(Line(x_ing, top - bh, x_ing, 14, strokeColor=MUTED, strokeWidth=1.1))
    arrow(d, x_ing, 14, x_out)
    d.add(String((x_ing + x_out) / 2, 18, "files we cannot clean safely → quarantine (AES-256-GCM), never copied",
                 fontName="Body", fontSize=9.5, fillColor=MUTED, textAnchor="middle"))
    d.add(Rect(x_out, 2, bw, 24, rx=4, ry=4, fillColor=colors.HexColor("#FFF7E6"),
               strokeColor=colors.HexColor("#B7791F"), strokeWidth=0.9))
    d.add(String(x_out + bw / 2, 11, "quarantine/", fontName="Body-Bold", fontSize=10,
                 fillColor=colors.HexColor("#975A16"), textAnchor="middle"))
    return d


def two_col(rows, left_w):
    t = Table([[Paragraph(k, S_CELLB), Paragraph(v, S_CELL)] for k, v in rows], colWidths=[left_w, W - left_w])
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -2), 0.5, RULE),
             ("TOPPADDING", (0, 0), (-1, -1), 2.6), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.6),
             ("LEFTPADDING", (0, 0), (-1, -1), 4)]
    style += [("BACKGROUND", (0, i), (-1, i), ZEBRA) for i in range(0, len(rows), 2)]
    t.setStyle(TableStyle(style))
    return t


def cards(items, cols=2):
    cw = (W - 6 * (cols - 1)) / cols
    cells = [[Paragraph(t, S_CARD_T), Spacer(1, 1.5), Paragraph(b, S_SMALL)] for t, b in items]
    rows = [cells[i:i + cols] for i in range(0, len(cells), cols)]
    widths = []
    for c in range(cols):
        widths += [cw] + ([6] if c < cols - 1 else [])
    grid = [[x for c, cell in enumerate(r) for x in ([cell] + ([""] if c < cols - 1 else []))] for r in rows]
    t = Table(grid, colWidths=widths)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 5),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 6),
             ("RIGHTPADDING", (0, 0), (-1, -1), 6)]
    for r in range(len(rows)):
        for c in range(cols):
            col = c * 2
            style += [("BACKGROUND", (col, r), (col, r), TINT), ("LINEBEFORE", (col, r), (col, r), 2.2, GREEN)]
    for r in range(len(rows) - 1):
        style += [("BOTTOMPADDING", (0, r), (-1, r), 9)]
    t.setStyle(TableStyle(style))
    return t


def ladder():
    data = [[Paragraph(c, S_CELLB if i == 0 else S_CELL) for c in r] for i, r in enumerate(LADDER)]
    num = 16 * mm
    t = Table(data, colWidths=[W - 5 * num] + [num] * 5)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TINT), ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#DDEEE5")),
        ("FONTNAME", (0, 3), (-1, 3), "Body-Bold"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, RULE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.6), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.6),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def bullets(items):
    return [Paragraph(t, S_BUL, bulletText="•") for t in items]


# ----------------------------------------------------------------------------- build
def build(out: Path) -> None:
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=0, bottomMargin=11 * mm, title=f"{TEAM}: Project Brief",
                            author="Manav, Aditya, Nishk, Kavita")
    s = [Table([[header()]], colWidths=[W + 32 * mm], style=[("LEFTPADDING", (0, 0), (-1, -1), 0),
                                                            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                                            ("TOPPADDING", (0, 0), (-1, -1), 0),
                                                            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)],
               hAlign="CENTER"),
         h("1", "In one paragraph"), Paragraph(ONE_PARA, S_BODY),
         h("2", "Architecture"), diagram(),
         h("3", "How it works"), two_col(HOW, 25 * mm),
         h("4", "USP"), cards(USP, cols=3),
         PageBreak(),
         Spacer(1, 9 * mm),
         h("5", "Privacy–utility trade-off (measured on the practice data)"), two_col(RESULTS, 42 * mm),
         Spacer(1, 6), ladder(), Spacer(1, 4), Paragraph(TRADEOFF, S_SMALL),
         KeepTogether([h("6", "Known limitations")] + bullets(LIMITS))]
    doc.build(s)


if __name__ == "__main__":
    build(HERE / "brief.pdf")
    print("wrote", HERE / "brief.pdf")
