#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Standalone smoke test: hit a RUNNING scitt-cose verifier and assert it works.

This is the regression guard for the *standalone offering*. Run against a server
booted from ONLY this package (a fresh venv with just ``scitt-cose[serve]``), it
proves two things at once:

1. **It still stands alone.** The server imports nothing but ``scitt_cose`` — if a
   future change re-coupled the verify/serve path to a host application (or
   anything else not in the package), booting it in a clean venv fails before
   this script runs.
2. **The serve path still verifies.** ``GET /`` returns capabilities and declares
   it is not a Transparency Service; ``POST /verify`` validates a real Signed
   Statement and a digest-only Receipt over the wire.

This script imports only ``scitt_cose`` + ``cryptography`` (for throwaway keys) +
the standard library — never any consuming product. Exit code 0 on success,
non-zero on any failure (suitable for CI).

Usage:
    python scripts/smoke_verify.py --url http://127.0.0.1:8099
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scitt_cose import build_receipt, build_signed_statement


def _keys() -> tuple[bytes, str]:
    sk = ed25519.Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read())


def _post(url: str, obj: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8099")
    args = parser.parse_args(argv)
    base = args.url.rstrip("/")
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731

    failures: list[str] = []

    # 0. Liveness. (/health, not /healthz: Google's frontend intercepts
    # /healthz on run.app domains before the container sees it.)
    if _get(base + "/health") != {"ok": True}:
        failures.append("GET /health did not return {'ok': true}")

    # 1. Capabilities — and it must declare it is NOT a Transparency Service.
    caps = _get(base + "/")
    if "transparency service" not in " ".join(caps.get("does_not", [])).lower():
        failures.append("GET / capabilities do not declare 'not a Transparency Service'")

    priv, pub = _keys()

    # 2. Valid statement verifies.
    stmt = build_signed_statement(
        b'{"smoke":true}', alg="EdDSA", private_key_pem=priv,
        issuer="https://smoke.example", subject="urn:smoke", content_type="application/json",
    )
    r = _post(base + "/verify", {"statement_b64": b64(stmt), "statement_pubkey_pem": pub})
    if r.get("valid") is not True:
        failures.append(f"valid statement not accepted: {r}")

    # 3. Tampered statement is rejected.
    bad = bytearray(stmt)
    bad[-1] ^= 0x01
    r = _post(base + "/verify", {"statement_b64": b64(bytes(bad)), "statement_pubkey_pem": pub})
    if r.get("valid") is not False:
        failures.append("tampered statement was NOT rejected")

    # 4. Digest-only Receipt verifies (no plaintext payload sent).
    entry = hashlib.sha256(stmt).hexdigest()
    tree = [hashlib.sha256(f"e{i}".encode()).hexdigest() for i in range(4)]
    tree.insert(2, entry)
    receipt = build_receipt(
        leaf_entry_hex=entry, leaf_index=2, tree_entries_hex=tree,
        alg="EdDSA", log_private_key_pem=priv,
    )
    r = _post(base + "/verify", {
        "receipt_b64": b64(receipt), "log_pubkey_pem": pub, "leaf_entry_hex": entry,
    })
    if r.get("valid") is not True:
        failures.append(f"valid digest-only receipt not accepted: {r}")

    if failures:
        print("SMOKE FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"SMOKE OK against {base} (statement + tamper-reject + digest-only receipt)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
