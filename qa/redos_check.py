#!/usr/bin/env python3
"""ReDoS check: time every regex in src/secretward/ against adversarial inputs.

1. Inventory: every re.<fn>(...) call in src/secretward/*.py is found with the AST, with file:line.
   Module-level patterns are timed as the REAL compiled objects imported from the engine (so the
   rule-list alternations from config/rules/ are included); literal inline patterns are compiled
   from their source. Patterns built per input at run time (gazetteer phrase alternation, rare-
   condition alternation) are listed but not timed.
2. Static flags for the classic ReDoS shapes: nested quantifiers, two whitespace quantifiers
   separated only by optional tokens, and a leading unbounded class with no anchor/lookbehind.
3. Screen: each pattern runs (finditer for scan calls, match/fullmatch for anchored ones) on a
   battery of adversarial strings of N characters. Each pattern runs in a forked child; the parent
   kills it if one input takes longer than --timeout seconds, so an exponential case cannot hang.
4. Scaling: any pattern/input over --slow-ms at the screen size is re-timed at 1x, 2x, 4x, 8x and
   the exponent k in t ~ N^k is fitted (1 = linear, 2 = quadratic, 3 = cubic).

Usage (from the repo root; use the same Python the run uses):
  python3 qa/redos_check.py [--repo .] [--n 2000] [--timeout 2] [--json-out qa/logs/redos.json]
Stdlib only, Python 3.9+, Unix (uses fork).
"""
from __future__ import annotations

import argparse
import ast
import importlib
import json
import math
import os
import re
import select
import sys
import time
from pathlib import Path

SCAN_FNS = {"compile", "search", "sub", "subn", "findall", "finditer", "split"}

# Keywords that open a pattern (label / relation / trigger / prefix). A keyword followed by a long
# whitespace run and then something that breaks the match is the trigger shape for "\s*X?\s*".
PREFIXES = ["age", "aged", "age/sex", "umar", "आयु", "pin", "pin code", "s/o", "son of", "relative",
            "attendant", "house no", "h.no", "gram", "village", "near", "district", "distt", "जिला",
            "dob", "date of birth", "जन्म", "diagnosis", "k/c/o", "Dr", "name", "patient name",
            "shri", "mr", "kumar", "Md", "address", "12", "12 Jan", "Jan"]


def battery(n: int):
    """(label, string) adversarial inputs of about n characters."""
    out = [
        ("spaces", " " * n + "\x01"),
        ("newlines", "\n" * n + "\x01"),
        ("word a*N!", "a" * n + "!"),
        ("CAPS A*N/", "A" * n + "/"),
        ("Title Aa*N/", "A" + "a" * n + "/"),
        ("digits 1*N x", "1" * n + "x"),
        ("'1 '*N x", "1 " * (n // 2) + "x"),
        ("'1-'*N x", "1-" * (n // 2) + "x"),
        ("'a-'*N 1", "a-" * (n // 2) + "1"),
        ("'a.'*N @", "a." * (n // 2) + "@"),
        ("email-ish a@a.a.*N", "a@" + "a." * (n // 2) + "-"),
        ("'Aa '*N /", "Aa " * (n // 3) + "/"),
        ("deva word", "क" * n + "x"),
        ("'क '*N", "क " * (n // 2) + "x"),
        ("'kumar '*N x", "kumar " * (n // 6) + "x"),
        ("'X'*N 1", "X" * n + "1"),
        ("b64-ish", "Ab0+" * (n // 4) + "!"),
        ("'1/1/'*N", "1/" * (n // 2) + "x"),
    ]
    for p in PREFIXES:
        out.append((f"'{p}'+spaces", p + " " * n + "\x01"))
        out.append((f"'{p}'+spaces+lower", p + " " * n + "x" * 100))
    return out


def static_flags(src: str) -> list:
    f = []
    if re.search(r"\((?:[^()]|\([^()]*\))*[+*}]\)[+*]", src) or re.search(r"\)\+\)\*|\)\*\)\+", src):
        f.append("nested quantifier")
    ws = r"\\s[*+]"
    if re.search(ws + r"(?:\s*(?:\[[^\]]*\]|\(\?:[^()]*\)|\\?.)\?)+\s*" + ws, src) or re.search(ws + ws, src):
        f.append("adjacent \\s* around optional")
    if re.match(r"\[[^\]]+\][+*]", src):
        f.append("unanchored leading class+")
    return f


def inventory(repo: Path):
    """[(file, line, fn, source, kind, resolver)]; resolver = ('attr', module, name[, idx]) | ('lit', pat, flags) | None."""
    items = []
    for f in sorted((repo / "src" / "secretward").glob("*.py")):
        text = f.read_text(encoding="utf-8")
        tree = ast.parse(text)
        mod = "secretward." + f.stem
        bound = {}  # id(call node) -> resolver for module-level bindings
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name, v = node.targets[0].id, node.value
                if isinstance(v, ast.Call):
                    bound[id(v)] = ("attr", mod, name)
                elif isinstance(v, (ast.List, ast.Tuple)):
                    for i, e in enumerate(v.elts):
                        if isinstance(e, ast.Call):
                            bound[id(e)] = ("attr", mod, name, i)
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                    and n.func.value.id == "re" and n.args) or n.func.attr == "escape":
                continue
            fn, a = n.func.attr, n.args[0]
            src = ast.get_source_segment(text, a) or "?"
            res = bound.get(id(n)) if fn == "compile" else None
            if res is None:
                try:
                    lit = ast.literal_eval(a)
                    flags = 0
                    if fn == "compile" and len(n.args) > 1:
                        flags = eval(compile(ast.Expression(n.args[1]), "<f>", "eval"), {"re": re})  # noqa: S307
                    res = ("lit", lit, flags) if isinstance(lit, str) else None
                except (ValueError, SyntaxError, NameError, AttributeError):
                    res = None
            kind = "anchored" if fn in ("match", "fullmatch") else "scan"
            items.append((f.name, n.lineno, fn, src, kind, res))
    return items


def resolve(res):
    if res is None:
        return None
    if res[0] == "lit":
        return re.compile(res[1], res[2])
    obj = getattr(importlib.import_module(res[1]), res[2])
    obj = obj[res[3]] if len(res) > 3 else obj
    return obj if isinstance(obj, re.Pattern) else None


def run_one(rx, kind, fn, s):
    t0 = time.perf_counter()
    if kind == "anchored":
        (rx.fullmatch if fn == "fullmatch" else rx.match)(s)
    else:
        for _ in rx.finditer(s):
            pass
    return time.perf_counter() - t0


def timed(rx, kind, fn, inputs, timeout):
    """Time each input in a forked child; returns [seconds or None (killed at timeout)]."""
    results, start = [], 0
    while start < len(inputs):
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:  # child
            os.close(r)
            for s in inputs[start:]:
                os.write(w, f"{run_one(rx, kind, fn, s)!r}\n".encode())
            os._exit(0)
        os.close(w)
        buf, got = b"", 0
        while True:
            ready, _, _ = select.select([r], [], [], timeout)
            if not ready:  # current input is stuck
                os.kill(pid, 9)
                results.append(None)
                got += 1
                break
            chunk = os.read(r, 65536)
            if not chunk:
                break
            buf += chunk
            *lines, buf = buf.split(b"\n")
            for ln in lines:
                results.append(float(ln))
                got += 1
        os.close(r)
        os.waitpid(pid, 0)
        start += got
        if got == 0:
            break
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", type=Path, default=Path("."))
    ap.add_argument("--n", type=int, default=2000, help="adversarial string length for the screen")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds before one regex call is killed")
    ap.add_argument("--slow-ms", type=float, default=20.0, help="re-time for scaling above this")
    ap.add_argument("--json-out", type=Path)
    a = ap.parse_args()
    sys.path.insert(0, str((a.repo / "src").resolve()))
    os.chdir(a.repo)  # the engine loads config/ relative to the repo

    items = inventory(Path("."))
    bat = battery(a.n)
    labels, strings = [b[0] for b in bat], [b[1] for b in bat]
    report, untimed = [], []
    print(f"Python {sys.version.split()[0]}; {len(items)} regex call sites; screen N={a.n}, "
          f"{len(bat)} inputs each, kill at {a.timeout}s\n")
    for (fname, line, fn, src, kind, res) in items:
        try:
            rx = resolve(res)
        except Exception as e:  # noqa: BLE001
            rx, res = None, None
            print(f"  could not resolve {fname}:{line}: {e}")
        if rx is None:
            untimed.append({"where": f"{fname}:{line}", "fn": fn, "source": src[:200]})
            continue
        times = timed(rx, kind, fn, strings, a.timeout)
        worst = max(range(len(times)), key=lambda i: math.inf if times[i] is None else times[i])
        entry = {"where": f"{fname}:{line}", "fn": fn, "kind": kind, "source": src[:300],
                 "pattern": rx.pattern[:300], "static_flags": static_flags(rx.pattern),
                 "worst_input": labels[worst], "worst_ms": None if times[worst] is None else times[worst] * 1e3,
                 "scaling": None}
        slow = [i for i, t in enumerate(times) if t is None or t * 1e3 > a.slow_ms]
        if slow:  # fit an exponent on the worst slow input
            i = worst
            sizes, ts = [], []
            for mult in (0.5, 1, 2, 4):
                n = int(a.n * mult)
                t = timed(rx, kind, fn, [battery(n)[i][1]], a.timeout)[0]
                if t is None:
                    break
                sizes.append(n)
                ts.append(t)
            k = None
            if len(ts) >= 2 and ts[0] > 0:
                k = math.log(ts[-1] / ts[0]) / math.log(sizes[-1] / sizes[0])
            entry["scaling"] = {"sizes": sizes, "ms": [t * 1e3 for t in ts], "exponent": k,
                                "slow_inputs": [labels[j] for j in slow]}
        report.append(entry)
        w = "TIMEOUT" if entry["worst_ms"] is None else f"{entry['worst_ms']:9.2f} ms"
        sc = ""
        if entry["scaling"]:
            s = entry["scaling"]
            sc = f"  k={s['exponent']:.2f}" if s["exponent"] is not None else "  k=?"
            sc += " " + "/".join(f"{n}:{m:.0f}ms" for n, m in zip(s["sizes"], s["ms"]))
        fl = (" [" + "; ".join(entry["static_flags"]) + "]") if entry["static_flags"] else ""
        print(f"{entry['where']:<18} {fn:<9} {w}  worst={entry['worst_input']:<28}{sc}{fl}")
    print(f"\nnot timed (built per input at run time): {len(untimed)}")
    for u in untimed:
        print(f"  {u['where']:<18} {u['fn']:<9} {u['source'][:110]}")
    if a.json_out:
        a.json_out.parent.mkdir(parents=True, exist_ok=True)
        a.json_out.write_text(json.dumps({"python": sys.version, "n": a.n, "timed": report, "untimed": untimed},
                                         ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
