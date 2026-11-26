"""Encrypted quarantine vault: files we refuse to sanitize are kept, but only encrypted.

Why: a quarantined file (a scanned PDF, a corrupt export) is the most dangerous thing we
hold, because nothing was removed from it. The spec allows output/quarantine/ (not part of
the release, not scanned); "assume your server will be breached one day" means it must not
sit there in the clear. So it is sealed with AES-256-GCM, or not written at all.

Keys (kept away from the data):
  * master secret = RAKSHA_SECRET, read from the environment, never written anywhere
  * each file gets its OWN key + nonce, derived with HKDF-SHA256 from the master secret and the
    file's SHA-256: one key per file content, so a stolen key opens one file, never the vault
  * GCM authenticates: a tampered vault file fails to open instead of decrypting to garbage
Deterministic by design (same input, same bytes out), like the rest of the pipeline.

File name = the input's SHA-256 (already in report.json), never the original name, which can
itself be PII. Format: b"SWV1" + ciphertext-with-tag.

If the `cryptography` package is missing or anything fails, NOTHING is written: the file is
still quarantined in report.json, it is just not kept. Plaintext is never a fallback.
"""
from __future__ import annotations

import os
from pathlib import Path

MAGIC = b"SWV1"
SALT = b"secret-ward quarantine vault v1"
MAX_BYTES = 64 * 1024 * 1024            # stay far below the 4 GB memory limit

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    AVAILABLE = True
except Exception:  # noqa: BLE001 - optional dependency; the pipeline runs without it
    AVAILABLE = False


def _key_nonce(secret: bytes, sha: str) -> tuple[bytes, bytes]:
    okm = HKDF(algorithm=hashes.SHA256(), length=44, salt=SALT, info=b"file:" + sha.encode()).derive(secret)
    return okm[:32], okm[32:]


def _aad(sha: str) -> bytes:
    return SALT + b"|" + sha.encode()


def seal(raw: bytes, sha: str, secret: bytes) -> bytes:
    key, nonce = _key_nonce(secret, sha)
    return MAGIC + AESGCM(key).encrypt(nonce, raw, _aad(sha))


def open_sealed(blob: bytes, sha: str, secret: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("not a vault file")
    key, nonce = _key_nonce(secret, sha)
    return AESGCM(key).decrypt(nonce, blob[len(MAGIC):], _aad(sha))   # raises if tampered


def store(src: Path, sha: str, out_dir: Path) -> bool:
    """Seal one quarantined input into out_dir/quarantine/<sha>.swv. True if written."""
    secret = os.environ.get("RAKSHA_SECRET", "").encode()
    if not AVAILABLE or not secret:
        return False
    try:
        if src.stat().st_size > MAX_BYTES:
            return False
        blob = seal(src.read_bytes(), sha, secret)
        dest = out_dir / "quarantine" / f"{sha}.swv"
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".part")
        with open(tmp, "wb") as fh:          # ciphertext only ever touches the disk
            fh.write(blob)
        os.replace(tmp, dest)
        return True
    except Exception:  # noqa: BLE001 - never let the vault break the run, never write plaintext
        return False
