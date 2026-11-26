"""Meaning-trap tests. Run: python -m pytest tests -q   (or python tests/test_traps.py)

Hindi readers: add a line to CASES for every tricky phrase you find.
  (input text, must_keep: list of substrings that must survive, must_remove: substrings that must go)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("RAKSHA_SECRET", "test")
from secretward.detect import Ctx, sanitize, sanitize_header  # noqa: E402
from secretward.gazetteer import Gazetteer           # noqa: E402

CASES = [
    ("C/O fever for 3 days", ["C/O fever for 3 days"], []),
    ("C/O Ramesh Yadav, H.No. 12", [], ["Ramesh", "Yadav"]),
    ("Dr. Ramesh Srivastava (MD Medicine)", ["Dr. Ramesh Srivastava"], []),
    ("Tab Paracetamol 650mg 1-1-1 x 5 days", ["Paracetamol 650mg 1-1-1 x 5 days"], []),
    ("Dolo 650 BD x 5 days", ["Dolo 650 BD x 5 days"], []),
    ("K/C/O addison's disease", ["K/C/O addison's disease"], []),
    ("Shahid sahab ka BP 117/82", ["BP 117/82"], ["Shahid"]),
    ("Attendant (S/o Zubair) informed", [], ["Zubair"]),
    ("18:40 - Zorawar Qadri (attendant, bed 12), mob 6910522119", ["bed 12"], ["Zorawar", "6910522119"]),
    ("नाम: मोहम्मद शाहिद   आयु: 39 वर्ष", ["30-39 वर्ष"], ["मोहम्मद शाहिद"]),
    ("Mobile: +91 72864 90658", [], ["72864"]),
    ("ASHA worker visited", ["ASHA worker"], []),
    ("Platelets 150000-410000 /cumm", ["150000-410000"], []),
    # a name starting the SECOND line of a note, after a line ending in "." (classifier)
    ("Vitals stable, chart updated.\nSunil Das ko lunch ke baad vomiting hui, nurse ne chart update kiya.",
     ["vomiting hui"], ["Sunil", "Das"]),
    ("Parkinson's disease, on levodopa", ["Parkinson's disease"], []),
    ("14:00 - Parvathi Pandeya - K/C/O urinary tract infection.", ["K/C/O urinary tract infection"], ["Parvathi", "Pandeya"]),
    ("[17/03/26, 9:32 pm] Raju Papa: <attachment: report.pdf>", [], ["Raju"]),
    ("Next morning 06:00 - Patient ne raat theek se neend li.", ["Patient ne raat theek se neend li"], []),
    ("History: No K/C/O DM/HTN.", ["No K/C/O DM/HTN"], []),
    ("Ward/Bed: Ward 4 (Medicine) / Bed 24", ["Ward 4 (Medicine) / Bed 24"], []),
    ("Attendant (W/o Mukesh Pandey) informed about diet.", ["Attendant (W/o", "informed about diet"], ["Mukesh", "Pandey"]),
    ("Relation: S/o-W/o-D/o", ["S/o-W/o-D/o"], []),
    # Kavita (PR #13): lowercase names after strong cues
    ("name: rahul sharma, age 34", ["age"], ["rahul", "sharma"]),
    ("s/o ramesh kumar, village visit", [], ["ramesh"]),
    ("smt. sunita devi admitted", ["admitted"], ["sunita"]),
    # ...but lowercase medical text must survive
    ("Presenting complaints: C/O fever for 8 days", ["Presenting complaints:", "C/O fever"], []),
    ("History: No K/C/O DM/HTN. c/o dysuria x 2 days", ["DM/HTN", "c/o dysuria"], []),
    ("Treated conservatively. patient stable.", ["Treated conservatively", "patient stable"], []),
    # audit fixes: landlines, Md./Mohd prefix, initials
    ("Ph: 0522-2345678, Tel (0522) 2345678, 05222345678", ["Ph:", "Tel"], ["2345678"]),
    ("Platelets 1,50,000 /cumm, TLC 8,400, dose 0-1-0", ["1,50,000", "8,400", "0-1-0"], []),
    ("Md. Arif ko 3 din se bukhar", ["ko 3 din se bukhar"], ["Arif"]),
    ("Dr. Ramesh Srivastava (MD Medicine), Dr. Rao (MD Paediatrics)", ["MD Medicine", "MD Paediatrics"], []),
    ("Name: R. K. Sharma, complains of fever", ["complains of fever"], ["R. K.", "Sharma"]),
    ("मकान नं. 32, जामा मस्जिद के पीछे, तहसील नवाबगंज", [], ["जामा मस्जिद के पीछे", "32"]),
]


def run():
    gaz = Gazetteer()
    gaz.compile()
    bad = 0
    for text, keep, remove in CASES:
        out = sanitize(text, Ctx(gaz=gaz, shift=10))
        for k in keep:
            if k not in out:
                bad += 1
                print("LOST  ", repr(k), "->", repr(out))
        for r in remove:
            if r in out:
                bad += 1
                print("LEAKED", repr(r), "->", repr(out))
    for header in ("S/o-W/o-D/o", "Patient's Name", "Pita/Pati ka Naam", "Gram/Shehar", "DOB (MM/DD/YYYY)"):
        out = sanitize_header(header, Ctx(gaz=gaz))
        if out != header:
            bad += 1
            print("HEADER", repr(header), "->", repr(out))
    # identifiers stored as JSON NUMBERS under unknown keys; medical numbers stay numbers
    from secretward.fields import clean_field
    for value, should_change in ((902115225016, True), (91234567890123, True), (9876543210, True),
                                 (150000, False), (2024, False), (98.6, False), (1700000000, False)):
        out = clean_field("TEXT", value, Ctx(gaz=gaz, shift=10))
        if (out != value) != should_change:
            bad += 1
            print("NUMBER", repr(value), "->", repr(out))
    print(f"{len(CASES)} cases + 5 headers + 7 numbers, {bad} failures")
    return bad


def test_traps():
    assert run() == 0


if __name__ == "__main__":
    sys.exit(1 if run() else 0)
