# SPDX-License-Identifier: Apache-2.0
"""Generic Signed/Transparent Statement build/parse + attach/extract."""
from __future__ import annotations

import cbor2

from scitt_cose import attach_receipts, extract_receipts
from scitt_cose.statement import (
    CWT_ISS,
    CWT_SUB,
    HDR_CWT_CLAIMS,
    build_signed_statement,
    parse_signed_statement,
)


def _protected_map(msg: bytes) -> dict:
    protected_bstr = cbor2.loads(msg).value[0]
    return cbor2.loads(protected_bstr)


def test_build_parse_arbitrary(alg_keys):
    alg, priv, pub = alg_keys
    msg = build_signed_statement(
        b'{"x":1}',
        alg=alg, private_key_pem=priv,
        issuer="https://acme.example",
        subject="urn:anything:goes",
        content_type="application/widget+json",
        extra_cwt_claims={"profile_thing": "abc", 500: 42},
    )
    parsed = parse_signed_statement(msg, public_key_pem=pub)
    assert parsed["signature_verified"] is True
    assert parsed["issuer"] == "https://acme.example"
    assert parsed["subject"] == "urn:anything:goes"
    assert parsed["content_type"] == "application/widget+json"
    assert parsed["alg"] == alg
    assert parsed["payload"] == b'{"x":1}'
    assert parsed["claims"]["profile_thing"] == "abc"
    assert parsed["claims"][500] == 42


def test_cwt_claims_at_label_15_not_13(eddsa_keys):
    priv, _pub = eddsa_keys
    msg = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    protected = _protected_map(msg)
    assert HDR_CWT_CLAIMS == 15
    assert 15 in protected, "CWT Claims must be at label 15 (RFC 9597)"
    assert 13 not in protected, "must NOT use label 13 (kcwt)"
    claims = protected[15]
    assert claims[CWT_ISS] == "i"
    assert claims[CWT_SUB] == "s"


def test_kid_in_protected(eddsa_keys):
    priv, _pub = eddsa_keys
    msg = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
        kid=b"key-7",
    )
    protected = _protected_map(msg)
    assert protected[4] == b"key-7"


def test_parse_without_key_skips_signature(eddsa_keys):
    priv, _pub = eddsa_keys
    msg = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    parsed = parse_signed_statement(msg)
    assert parsed["signature_verified"] is None
    # No key -> nothing is authenticated: identity fields must NOT be surfaced as
    # if signed. The structurally-decoded values are fenced under `unverified`.
    assert parsed["issuer"] is None
    assert parsed["unverified"]["issuer"] == "i"


def test_parse_wrong_key_reports_false(eddsa_keys, other_eddsa_keys):
    priv, _pub = eddsa_keys
    _o, opub = other_eddsa_keys
    msg = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    parsed = parse_signed_statement(msg, public_key_pem=opub)
    assert parsed["signature_verified"] is False
    # The signature did NOT verify, so the issuer must not be presented as an
    # authenticated value (M3): top-level identity is None; the claimed value is
    # available only under the explicitly-unverified key.
    assert parsed["issuer"] is None
    assert parsed["unverified"]["issuer"] == "i"


def test_attach_extract_round_trip(eddsa_keys):
    priv, _pub = eddsa_keys
    stmt = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    r1, r2 = b"receipt-one", b"receipt-two"
    transparent = attach_receipts(stmt, [r1, r2])
    assert extract_receipts(transparent) == [r1, r2]
    assert extract_receipts(stmt) == []


def test_attach_extends_existing(eddsa_keys):
    priv, _pub = eddsa_keys
    stmt = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    t1 = attach_receipts(stmt, [b"a"])
    t2 = attach_receipts(t1, [b"b"])
    assert extract_receipts(t2) == [b"a", b"b"]


def test_attach_preserves_signature(eddsa_keys):
    priv, pub = eddsa_keys
    stmt = build_signed_statement(
        b"p", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    transparent = attach_receipts(stmt, [b"r"])
    parsed = parse_signed_statement(transparent, public_key_pem=pub)
    assert parsed["signature_verified"] is True
