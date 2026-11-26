"""Dev-only: where do we miss required links / make wrong ones? Uses practice truth."""
import json, sys, collections
from pathlib import Path
kit, out = Path(sys.argv[1]), Path(sys.argv[2])
t = json.load(open(kit / "dev/truth/truth.json"))
rep = json.load(open(out / "report.json"))
by_sha = {f["input_sha256"]: f["output"] for f in rep["files"]}
ours = {}
for line in open(out / "records.jsonl"):
    r = json.loads(line); ours[(r["file"], r["loc"])] = r["patient"]
miss = collections.Counter(); ex = collections.defaultdict(list)
for rel, fi in t["files"].items():
    o = by_sha.get(fi["sha256"])
    units = fi.get("units", []); units = units if isinstance(units, list) else list(units.values())
    for u in units:
        if u.get("link") != "required":
            continue
        p = ours.get((o, u["loc"])) if o else "QUAR"
        if p is None:
            folder = rel.split("/")[0]; miss[folder] += 1
            if len(ex[folder]) < 3: ex[folder].append((rel, u["loc"], u.get("patient")))
print("missed required links by folder:", miss)
for k, v in ex.items(): print(k, v)
