# SPDX-License-Identifier: Apache-2.0
"""Fifth oracle: the COSE standard's OWN reference-signed COSE_Sign1 vector.

The other oracles either (a) verify bytes *we* emitted (Go, pycose, an independent
external verifier implementation) or (b) check the Merkle layer against published vectors (RFC 6962/9162).
This adds the missing piece for the *signature* layer: a COSE_Sign1 that the COSE
working group's reference implementation signed and published — verified here with
*our* clean-room `verify_sign1`. Agreement means our Sig_structure construction
and ES256 path match the spec's reference output byte-for-byte, independent of our
own emitter.

Vector: RFC 9052 (RFC 8152) Appendix C.2.1 — the canonical single-signer
COSE_Sign1 example, ``alg`` ES256 in the **protected** header, empty external_aad,
payload "This is the content." Source: github.com/cose-wg/Examples
(``RFC8152/Appendix_C_2_1.json``), the COSE WG's published interop corpus.

Why not the SCITT API emulator instead? It was evaluated as a candidate ecosystem
oracle and rejected: it is **archived/unmaintained** (final "pre-archive" tag,
Nov 2024) and emits the *obsolete* pre-standard receipt format
(``draft-birkholz-scitt-receipts``: string header labels ``service_id`` /
``tree_alg``, not a COSE_Sign1 receipt and not the ``vds=395`` / ``vdp=396``
RFC 9162 structure this library verifies). Its statements use ``pycose`` — already
covered by our third-party oracle. Pinning a non-conformant, drift-prone
implementation would be a *misleading* oracle, so we use the COSE WG's own
spec vectors instead.
"""
from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scitt_cose import verify_sign1
from scitt_cose.cose_sign1 import CoseError

# --- RFC 9052 Appendix C.2.1 (COSE WG Examples) -----------------------------
# The signing key (P-256). Only the public coordinates are needed to verify.
_KEY_X = "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"
_KEY_Y = "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"

# The published COSE_Sign1 output (CBOR, tag 18). Protected = {1: -7} (ES256);
# unprotected = {4: '11'}; payload = "This is the content."; 64-byte r||s sig.
_VECTOR_HEX = (
    "D28443A10126A10442313154546869732069732074686520636F6E74656E742E5840"
    "8EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E"
    "2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36"
)


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _public_pem() -> bytes:
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(_b64u(_KEY_X), "big"),
        int.from_bytes(_b64u(_KEY_Y), "big"),
        ec.SECP256R1(),
    )
    return numbers.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_accepts_cose_wg_reference_sign1():
    """Our verifier accepts the COSE WG's own reference-signed COSE_Sign1."""
    s1 = verify_sign1(bytes.fromhex(_VECTOR_HEX), public_key_pem=_public_pem())
    assert s1.payload == b"This is the content."
    assert s1.protected[1] == -7  # ES256, in the protected header


def test_rejects_tampered_cose_wg_vector():
    """One flipped signature byte in the reference vector must be rejected."""
    bad = bytearray(bytes.fromhex(_VECTOR_HEX))
    bad[-1] ^= 0x01
    with pytest.raises(CoseError):
        verify_sign1(bytes(bad), public_key_pem=_public_pem())


def test_rejects_reference_vector_under_wrong_key():
    """The reference vector must not verify under a different (generated) key."""
    other = ec.generate_private_key(ec.SECP256R1())
    other_pem = other.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(CoseError):
        verify_sign1(bytes.fromhex(_VECTOR_HEX), public_key_pem=other_pem)
