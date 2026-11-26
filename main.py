#!/usr/bin/env python3
"""secret-ward entry point: python main.py --input <dir> --output <empty dir>

Offline, CPU-only, LLM-free. Prints only counts. See README.md for the architecture.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))


def _quiet_excepthook(exc_type, exc, tb):  # never print values: messages can contain PII
    sys.stderr.write(f"error: {exc_type.__name__}\n")


sys.excepthook = _quiet_excepthook


def peak_rss_mb() -> float:
    try:
        import resource
        r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(r / 1024 if sys.platform != "darwin" else r / 1048576, 1)
    except Exception:  # noqa: BLE001
        return 0.0


MIN_PY = (3, 9)


def run(inp: Path, out: Path) -> int:
    from secretward.pipeline import Pipeline
    t0 = time.monotonic()
    (out / "sanitized").mkdir(parents=True, exist_ok=True)
    p = Pipeline(inp, out)
    p.load()
    p.build_units()
    files = p.write()
    exported = {d.rel for d in p.docs if d.kind != "quarantine"}
    records = []
    for d in p.docs:
        if d.rel not in exported:
            continue
        for u in d.units:
            records.append({"file": f"sanitized/{d.out_rel}", "loc": u.loc, "patient": u.patient})
    with open(out / "records.jsonl", "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    n_san = sum(e["status"] == "sanitized" for e in files)
    c = p.counts
    ident = sum(v for k, v in c.items() if k not in ("DATE_SHIFTED", "AGE_BANDED"))
    report = {
        "schema": "raksha-report/1",
        "files": files,
        "counts": {
            "files_total": len(files), "files_sanitized": n_san, "files_quarantined": len(files) - n_san,
            "records_processed": len(records), "identifiers_detected": ident,
            "records_linked": sum(r["patient"] is not None for r in records),
            "records_generalized": c.get("AGE_BANDED", 0), "records_suppressed": 0,
            "records_quarantined": 0,
        },
        "entities": {k: c[k] for k in sorted(c)},
        "timing": {"seconds": round(time.monotonic() - t0, 2)},
        "resources": {"peak_rss_mb": peak_rss_mb()},
        # quarantined inputs are kept only as AES-256-GCM ciphertext in quarantine/<sha256>.swv
        "quarantine_vault": {"cipher": "AES-256-GCM, per-file HKDF-SHA256 keys from RAKSHA_SECRET",
                             "files_encrypted": p.vaulted},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"files {len(files)} sanitized {n_san} quarantined {len(files) - n_san} (encrypted {p.vaulted}) records {len(records)}")

    # Fail LOUDLY, never silently: a crash inside our own code quarantines a file (fail-safe),
    # but if that happens to many files the release is broken and must not look successful.
    errors = sum(1 for e in files if str(e.get("reason", "")).startswith("processing_error"))
    if errors:
        sys.stderr.write(f"warning: {errors} file(s) quarantined because of an internal error\n")
    parseable = sum(1 for e in files if not str(e.get("reason", "")).startswith(
        ("unsupported", "empty", "corrupt", "malformed", "nesting", "format_mismatch", "unreadable")))
    if (files and n_san == 0) or (parseable and errors >= max(1, parseable // 2)):
        sys.stderr.write("fatal: most files failed internally; refusing to report success\n")
        return 3
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="secret-ward privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    if sys.version_info < MIN_PY:
        sys.stderr.write("fatal: secret-ward needs Python %d.%d or newer\n" % MIN_PY)
        return 2
    result = {"code": 1}

    def target():
        result["code"] = run(Path(a.input), Path(a.output))

    sys.setrecursionlimit(20000)
    threading.stack_size(512 * 1024 * 1024)   # deep JSON must not crash the process
    t = threading.Thread(target=target)
    t.start()
    t.join()
    return result["code"]


if __name__ == "__main__":
    sys.exit(main())
