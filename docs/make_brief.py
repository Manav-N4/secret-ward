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

S_BODY = ParagraphStyle("body", fontName="Body", fontSize=11.5, leading=15.5, textColor=INK)
S_SMALL = ParagraphStyle("small", parent=S_BODY, fontSize=11, leading=14.5)
S_CELL = ParagraphStyle("cell", parent=S_BODY, fontSize=11, leading=14)
S_CELLB = ParagraphStyle("cellb", parent=S_CELL, fontName="Body-Bold", textColor=GREEN_D)
S_H = ParagraphStyle("h", parent=S_BODY, fontName="Body-Bold", fontSize=14, leading=17, textColor=GREEN,
                     spaceBefore=12, spaceAfter=5)
S_CARD_T = ParagraphStyle("cardt", parent=S_BODY, fontName="Body-Bold", fontSize=12, leading=15, textColor=GREEN_D)
S_TITLE = ParagraphStyle("title", parent=S_BODY, fontName="Body-Bold", fontSize=22, leading=25, textColor=WHITE)
S_PITCH = ParagraphStyle("pitch", parent=S_BODY, fontSize=12, leading=15, textColor=WHITE)
S_META = ParagraphStyle("meta", parent=S_BODY, fontSize=10, leading=12.5, textColor=colors.HexColor("#CFE6DC"))
S_KPI_N = ParagraphStyle("kpin", parent=S_BODY, fontName="Body-Bold", fontSize=17, leading=20, textColor=GREEN_D,
                         alignment=1)
S_KPI_L = ParagraphStyle("kpil", parent=S_BODY, fontSize=10, leading=11.6, textColor=MUTED, alignment=1)
S_BUL = ParagraphStyle("bul", parent=S_SMALL, leftIndent=11, bulletIndent=0, spaceAfter=5)

# ----------------------------------------------------------------------------- TEXT
# Section order follows the kit's brief/PROJECT_BRIEF_TEMPLATE.md; kept short on purpose.
TEAM = "secret-ward"
PITCH = "An offline privacy firewall for Indian hospital records, in English, Hindi and Hinglish."
META = ("<b>Track 3 · Secret Wards</b> &nbsp;·&nbsp; <b>Members:</b> Manav, Aditya, Nishk, Kavita "
        "&nbsp;·&nbsp; <b>Repo:</b> github.com/Manav-N4/secret-ward")

KPIS = [
    ("0 / 3230", "personal data<br/>pieces leaked"),
    ("99.4%", "medical values<br/>kept exact"),
    ("1.00", "patient linking<br/>precision and recall"),
    ("0 / 48", "patients unique<br/>after release"),
    ("98% → 6%", "patients re-identified<br/>by attack"),
]

ONE_PARA = (
    "Hospitals want to share patient records for research without exposing anyone. secret-ward removes every "
    "personal detail, keeps every medical value exact, and gives each patient one stable fake ID across all files. "
    "<b>Our key idea: nothing is memorised.</b> It learns what each column means and who the patients are from the "
    "data itself, so it still works on files, headers and names it has never seen.")

HOW = [
    ("Ingestion", "Reads CSV, TSV, JSON, FHIR and text in four encodings. Files it cannot clean safely are locked "
     "away encrypted, never copied."),
    ("Detection", "Rules, a learned name list, a Hindi–English phonetic key (<font name='Deva'>रमेश</font> = Ramesh) "
     "and <b>a small model we trained ourselves</b> for names with no label. Doctors, doses and diseases are kept."),
    ("Linkage", "Joins records by hospital ID, phone or Aadhaar. Safety rules stop two different people from "
     "ever being merged. Fake IDs are keyed HMACs."),
    ("Privacy layer", "Dates shifted per patient (stay lengths stay exact), ages in 10-year bands, address reduced "
     "to district. Patients who would still stand out get wider bands."),
    ("Security", "Secret key never written anywhere; logs hold counts only; every output is re-checked before "
     "release."),
]

USP = [
    ("Works on unseen data",
     "Renamed columns, new formats and 8 shuffled versions of the data: 0 leaks every time."),
    ("Privacy proven by attack",
     "Two attackers, built separately, try to re-identify patients: success falls from 98% to 6%."),
    ("Never fails silently",
     "Empty files, huge files, crashes: it always finishes, writes an honest report, and leaks nothing."),
]

RESULTS = [
    ("personal data leaked<br/>(overall / Hindi / Hinglish)", "<b>0% / 0% / 0%</b> (0 of 3,230 pieces)"),
    ("medical values kept", "<b>99.4%</b>: the only values changed are districts we hide on purpose"),
    ("linking precision / recall / F0.5", "<b>1.00 / 1.00 / 1.00</b>, no two people ever merged"),
    ("re-identification risk", "<b>0%</b> of patients unique on age band + district (raw data: 96%)"),
    ("run time / peak memory", "<b>2 s / 36 MB</b> for 200 files; 24 s for 8,000 files"),
    ("on data we did not tune on", "<b>0 leaks</b> on renamed headers, new formats, free text only and "
     "40 Hinglish notes"),
]

TRADEOFF = (
    "<b>The trade-off:</b> to make sure no patient stands out, small groups get wider age bands and some lose "
    "their district. We chose each setting by measuring how much it cut the attacker's success against how much "
    "detail it cost. Medicines, doses, lab values and stay lengths are never touched.")

LIMITS = [
    "A targeted attacker who already knows a patient's visit still succeeds about half the time, because stay "
    "lengths must stay exact.",
    "Names with no clue around them are caught 88% of the time, not 100%.",
    "PDFs, images and files over ~43 MB are locked away rather than cleaned. Next step: clean them too.",
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
             ("TOPPADDING", (0, 0), (-1, -1), 6.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 6.5),
             ("LEFTPADDING", (0, 0), (-1, -1), 6)]
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
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 8),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 10), ("LEFTPADDING", (0, 0), (-1, -1), 8),
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


def try_it():
    code = ParagraphStyle("code", parent=S_SMALL, fontName="Courier", fontSize=10, leading=14, textColor=INK)
    rows = [[Paragraph("<b>Try it</b> &nbsp;(Python 3.9+, offline, CPU-only)", S_CARD_T)],
            [Paragraph("python3 -m pip install -r requirements.txt", code)],
            [Paragraph("RAKSHA_SECRET=&lt;secret&gt; python3 main.py --input &lt;in&gt; --output &lt;out&gt;", code)],
            [Paragraph("Writes sanitized/, records.jsonl, report.json and a plain-language report card in "
                       "logs/privacy_report.md.", S_SMALL)]]
    t = Table(rows, colWidths=[W])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), TINT), ("LINEBEFORE", (0, 0), (0, -1), 2.2, GREEN),
                           ("LEFTPADDING", (0, 0), (-1, -1), 9), ("TOPPADDING", (0, 0), (-1, 0), 7),
                           ("BOTTOMPADDING", (0, -1), (-1, -1), 8), ("TOPPADDING", (0, 1), (-1, -1), 1.5),
                           ("BOTTOMPADDING", (0, 0), (-1, -2), 1.5)]))
    return t


def bullets(items):
    return [Paragraph(t, S_BUL, bulletText="•") for t in items]


# ----------------------------------------------------------------------------- build
def build(out: Path) -> None:
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=0, bottomMargin=12 * mm, title=f"{TEAM}: Project Brief",
                            author="Manav, Aditya, Nishk, Kavita")
    s = [Table([[header()]], colWidths=[W + 32 * mm], style=[("LEFTPADDING", (0, 0), (-1, -1), 0),
                                                            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                                                            ("TOPPADDING", (0, 0), (-1, -1), 0),
                                                            ("BOTTOMPADDING", (0, 0), (-1, -1), 0)],
               hAlign="CENTER"),
         Spacer(1, 8), kpis(),
         h("1", "The project in one paragraph"), Paragraph(ONE_PARA, S_BODY),
         h("2", "Architecture"), diagram(),
         h("3", "How it works"), two_col(HOW, 28 * mm),
         PageBreak(),
         Spacer(1, 10 * mm),
         h("4", "What makes it different"), cards(USP, cols=3),
         h("5", "Key outcomes: privacy vs utility (measured on the practice data)"), two_col(RESULTS, 52 * mm),
         Spacer(1, 8), Paragraph(TRADEOFF, S_BODY),
         h("6", "Known limitations"), *bullets(LIMITS),
         Spacer(1, 10), try_it()]
    doc.build(s)


if __name__ == "__main__":
    build(HERE / "brief.pdf")
    print("wrote", HERE / "brief.pdf")
