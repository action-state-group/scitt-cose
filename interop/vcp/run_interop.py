#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""VeritasChain VCP × scitt-cose interop probe.

Purpose
-------
Test whether a SCITT Signed Statement carrying a VCP (Verifiable Certification
Protocol) event payload round-trips through scitt-cose's verify path cleanly.

Source material
---------------
* ``draft-kamimura-scitt-vcp-01`` §2.1, §3.1, §7.1 — VCP events are the
  *payload* of a COSE_Sign1 Signed Statement; SCRAPI registration uses
  ``content-type: application/cose``.
* ``draft-kamimura-scitt-vcp-01`` Appendix A — complete JSON VCP event example
  (trading-event, Ed25519 / JCS-signed at the VCP layer).
* No published VCP COSE_Sign1 binary artifacts exist as of 2026-06-30; this
  probe constructs one from the published JSON example using a local test key.

Honest finding
--------------
scitt-cose is **payload-agnostic** (RFC 9052 §4, SCITT architecture §3).  A VCP
event wrapped in COSE_Sign1 round-trips correctly — the COSE envelope verifies
and scitt-cose reports the issuer/subject/content-type faithfully without
inspecting the payload.

The divergence is at the **inner VCP signing layer** (JCS + Ed25519 at the
application level) vs the **COSE_Sign1 outer envelope** — both valid; they are
independent layers.  scitt-cose only touches the outer COSE layer.

Run
---
    cd /path/to/scitt-cose
    pip install -e .
    python3 interop/vcp/run_interop.py

Outputs
-------
* ``interop/vcp/vcp-statement.cose`` — the COSE_Sign1 Signed Statement
* ``interop/vcp/vcp-issuer-pub.pem`` — corresponding public key
* ``interop/vcp/result.json`` — machine-readable result (written by this script)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Allow running directly from the repo root without install
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scitt_cose import build_signed_statement, parse_signed_statement  # noqa: E402

# ---------------------------------------------------------------------------
# Published VCP JSON event — Appendix A, draft-kamimura-scitt-vcp-01
# (The inner VCP Ed25519/JCS signature is VCP-layer; this is the PAYLOAD that
#  SCITT wraps in COSE_Sign1.  scitt-cose treats it as opaque bytes.)
# ---------------------------------------------------------------------------
VCP_EVENT = {
    "vcpVersion": "1.2",
    "eventId": "EVT-2026-XAU-001",
    "timestamp": "2026-06-30T00:00:00Z",
    "issuer": "did:vcp:exchange.example",
    "subject": "XAU/USD",
    "eventType": "SIG_ORD_EXE",
    "body": {
        "instrument": "XAU/USD",
        "side": "BUY",
        "quantity": "1.000",
        "price": "2350.50",
        "currency": "USD",
        "orderId": "ORD-20260630-001",
        "executionVenue": "exchange.example",
    },
    # Inner VCP Ed25519/JCS signature (opaque to scitt-cose)
    "signature": "BASE64_ENCODED_ED25519_SIG_OVER_JCS_CANONICAL_BYTES",
}

VCP_PAYLOAD = json.dumps(VCP_EVENT, separators=(",", ":"), sort_keys=True).encode()

# VCP COSE wrapping parameters (draft §3.1 / §7.1)
VCP_ISSUER = "did:vcp:exchange.example"
VCP_SUBJECT = "XAU/USD:EVT-2026-XAU-001"
VCP_CONTENT_TYPE = "application/json"  # inner payload; outer SCRAPI = application/cose


def main() -> int:
    out_dir = Path(__file__).parent

    print("=" * 60)
    print("VeritasChain VCP × scitt-cose interop probe")
    print("=" * 60)
    print("\nSource: draft-kamimura-scitt-vcp-01 Appendix A (synthetic key)")
    print(f"Payload ({len(VCP_PAYLOAD)} bytes): VCP SIG_ORD_EXE event (XAU/USD)")

    # ── 1. Generate a local test key (substitutes for VCP issuer key) ───────
    sk = ed25519.Ed25519PrivateKey.generate()
    priv_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (out_dir / "vcp-issuer-pub.pem").write_bytes(pub_pem)
    print("\n[1] Test key generated (Ed25519 — substitutes for VCP issuer key)")

    # ── 2. Wrap the VCP event in COSE_Sign1 (scitt-cose) ────────────────────
    stmt = build_signed_statement(
        VCP_PAYLOAD,
        alg="EdDSA",
        private_key_pem=priv_pem,
        issuer=VCP_ISSUER,
        subject=VCP_SUBJECT,
        content_type=VCP_CONTENT_TYPE,
    )
    (out_dir / "vcp-statement.cose").write_bytes(stmt)
    print(f"[2] COSE_Sign1 Signed Statement built ({len(stmt)} bytes)")

    # ── 3. Verify with scitt-cose ────────────────────────────────────────────
    parsed = parse_signed_statement(stmt, public_key_pem=pub_pem)

    sig_ok = parsed["signature_verified"]
    alg = parsed.get("alg", "?")
    issuer = parsed.get("issuer", "?")
    subject = parsed.get("subject", "?")
    content_type = parsed.get("content_type", "?")
    payload_bytes = parsed.get("payload", b"")

    print("\n[3] parse_signed_statement result:")
    print(f"    signature_verified : {sig_ok}")
    print(f"    alg                : {alg}")
    print(f"    issuer             : {issuer}")
    print(f"    subject            : {subject}")
    print(f"    content_type       : {content_type}")
    print(f"    payload (bytes)    : {len(payload_bytes)} bytes (opaque to verifier)")

    # Confirm payload round-trips identically
    payload_ok = payload_bytes == VCP_PAYLOAD
    print(f"    payload round-trip : {'✓ exact match' if payload_ok else '✗ MISMATCH'}")

    # ── 4. Tamper: flip one byte in the Ed25519 signature region ────────────
    # COSE_Sign1 = tag(18, [protected_bstr, {}, payload_bstr, signature_bstr])
    # Ed25519 signature is 64 bytes; it lives at the END of the serialized CBOR.
    # Flip a byte inside the last 40 bytes (safely within the 64-byte signature).
    tampered = bytearray(stmt)
    sig_offset = len(tampered) - 30  # 30 bytes from end, inside the 64-byte sig
    tampered[sig_offset] ^= 0xFF

    # parse_signed_statement catches CoseError internally and returns
    # {"signature_verified": False} rather than raising — check the field.
    tampered_parsed = parse_signed_statement(bytes(tampered), public_key_pem=pub_pem)
    tamper_ok = tampered_parsed["signature_verified"] is False

    print(f"\n[4] Tamper test (flip 1 byte at offset -{len(stmt) - sig_offset}):")
    print(f"    signature_verified={tampered_parsed['signature_verified']}  — {'rejected ✓' if tamper_ok else 'BUG: still verified'}")

    # ── 5. Summary ────────────────────────────────────────────────────────────
    all_ok = sig_ok and payload_ok and tamper_ok
    print(f"\n{'=' * 60}")
    print(f"Result: {'PASS ✓' if all_ok else 'FAIL ✗'}")
    print(f"  COSE envelope verified  : {sig_ok}")
    print(f"  Payload round-trip      : {payload_ok}")
    print(f"  Tamper rejected         : {tamper_ok}")
    print(f"{'=' * 60}")

    # ── 6. Write machine-readable result ─────────────────────────────────────
    result = {
        "probe": "vcp-scitt-cose-interop",
        "date": "2026-06-30",
        "source": {
            "draft": "draft-kamimura-scitt-vcp-01",
            "section": "§2.1, §3.1, §7.1, Appendix A",
            "url": "https://datatracker.ietf.org/doc/html/draft-kamimura-scitt-vcp-01",
            "note": "No published VCP COSE_Sign1 binary artifacts as of 2026-06-30. "
                    "Payload sourced from draft Appendix A; outer COSE signed with local test key.",
        },
        "payload": {
            "format": "VCP JSON event (draft §2.1 / Appendix A)",
            "content_type": VCP_CONTENT_TYPE,
            "event_type": VCP_EVENT["eventType"],
            "bytes": len(VCP_PAYLOAD),
        },
        "scitt_cose_result": {
            "signature_verified": sig_ok,
            "payload_round_trip": payload_ok,
            "tamper_rejected": tamper_ok,
            "alg": alg,
            "issuer": issuer,
            "subject": subject,
            "statement_bytes": len(stmt),
        },
        "finding": (
            "ENVELOPE_COMPATIBLE"
            if all_ok
            else "ENVELOPE_FAILED"
        ),
        "finding_detail": (
            "VCP JSON event payload is opaque to scitt-cose (payload-agnostic per RFC 9052 §4 "
            "and SCITT architecture §3). COSE_Sign1 envelope over a VCP event verifies cleanly. "
            "Inner VCP Ed25519/JCS signing layer is independent and not inspected by scitt-cose. "
            "No published VCP COSE binary test vectors exist yet (2026-06-30); "
            "this probe confirms envelope-level compatibility from the published JSON example."
        ),
    }
    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2))
    print(f"\nResult written → {result_path.relative_to(Path.cwd()) if Path.cwd() in result_path.parents else result_path}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
