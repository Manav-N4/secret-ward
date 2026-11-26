#!/usr/bin/env python3
"""Synthetic scale data (dev only): n_files files, each with NEW distinct people. No real data.

Usage: python3 scripts/gen_scale.py 4000 /tmp/scale_4000
       time RAKSHA_SECRET=x python3 main.py --input /tmp/scale_4000 --output /tmp/out_4000
"""
import random, sys, os
from pathlib import Path
n_files, out = int(sys.argv[1]), Path(sys.argv[2])
rnd = random.Random(7)
syl = ["ra","me","sh","ku","ma","ni","ta","pa","de","vi","su","no","ha","ri","la","ga","bi","ya","ka","jo","an","il","ar","un"]
def name():
    return " ".join("".join(rnd.choice(syl) for _ in range(rnd.randint(2,3))).capitalize() for _ in range(2))
(out/"registration").mkdir(parents=True, exist_ok=True); (out/"notes").mkdir(parents=True, exist_ok=True)
for f in range(n_files // 2):
    rows = ["UHID,Patient Name,Gender,Age,Village,District,PIN,Mobile"]
    people = []
    for r in range(10):
        nm = name(); people.append(nm)
        rows.append(f"SC/{f:05d}/{r:03d}{f:04d},{nm},{rnd.choice('MF')},{rnd.randint(1,90)},{name().split()[0]}pur,Sitapur,26{rnd.randint(1000,9999)},9{rnd.randint(100000000,999999999)}")
    (out/"registration"/f"reg_{f:05d}.csv").write_text("\n".join(rows)+"\n")
    note = "\n".join(f"10:00 - {p} - K/C/O fever. Attendant (S/o {name()}) informed. BP 120/80." for p in people)
    (out/"notes"/f"note_{f:05d}.txt").write_text(note+"\n")
