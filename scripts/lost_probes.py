"""Dev-only helper: which medical 'preserve' values did we destroy? Uses the practice truth."""
import json, sys, collections, unicodedata
from pathlib import Path
kit, out = Path(sys.argv[1]), Path(sys.argv[2])
t = json.load(open(kit / "dev/truth/truth.json"))
rep = json.load(open(out / "report.json"))
by_sha = {f["input_sha256"]: f for f in rep["files"]}
lost = collections.Counter(); ex = collections.defaultdict(list)
for rel, fi in t["files"].items():
    f = by_sha.get(fi["sha256"])
    if not f or not f["output"]:
        continue
    text = unicodedata.normalize("NFKC", (out / f["output"]).read_text(encoding="utf-8")).lower()
    units = fi.get("units", []); units = units if isinstance(units, list) else list(units.values())
    for u in units:
        for p in u.get("preserve", []):
            s = p if isinstance(p, str) else p.get("text") or p.get("surface") or p.get("value")
            kind = "?" if isinstance(p, str) else p.get("kind") or p.get("type") or "?"
            if s and unicodedata.normalize("NFKC", str(s)).lower() not in text:
                lost[kind] += 1
                if len(ex[kind]) < int(sys.argv[3] if len(sys.argv) > 3 else 6):
                    ex[kind].append((rel, s))
print(lost)
for k, v in ex.items():
    for rel, s in v:
        print(k, "|", rel, "|", s)
