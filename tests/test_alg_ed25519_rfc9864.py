"""alg -19 (RFC 9864 fully-specified Ed25519) is accepted wherever -8 is.

Covers statements and receipts through the library and the hosted /verify
path (scitt-cose issue 108), with inputs from an independent implementation.
"""
import base64
import json
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from hosted_profiles.hosted import verify_payload
from scitt_cose import (
    CoseError,
    build_receipt,
    parse_signed_statement,
    sign_sign1,
    verify_receipt,
    verify_sign1,
)
from scitt_cose.cose_sign1 import COSE_ALG_ED25519

FIX = Path(__file__).parent / "fixtures" / "rfc9864_peer"


def _pems():
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def _log_pem_from_jwks():
    x = json.loads((FIX / "log-jwks.json").read_text())["keys"][0]["x"]
    raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    return ed25519.Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_code_point():
    assert COSE_ALG_ED25519 == -19


@pytest.mark.parametrize("alg,code", [("Ed25519", -19), ("EdDSA", -8)])
def test_sign_verify_roundtrip(alg, code):
    priv, pub = _pems()
    msg = sign_sign1(b"hi", alg=alg, private_key_pem=priv)
    out = verify_sign1(msg, public_key_pem=pub)
    assert out.protected[1] == code and out.payload == b"hi"


def test_wrong_key_rejected():
    priv, _ = _pems()
    _, other = _pems()
    msg = sign_sign1(b"hi", alg="Ed25519", private_key_pem=priv)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=other)


def test_ed25519_alg_with_non_ed25519_key_rejected():
    from cryptography.hazmat.primitives.asymmetric import ec

    priv, _ = _pems()
    msg = sign_sign1(b"hi", alg="Ed25519", private_key_pem=priv)
    ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(CoseError, match="not Ed25519"):
        verify_sign1(msg, public_key_pem=ec_pub)


def test_signature_not_transferable_between_8_and_19():
    # The alg is in the protected header, so rewriting -19 to -8 breaks the signature.
    priv, pub = _pems()
    msg = sign_sign1(b"hi", alg="Ed25519", private_key_pem=priv)
    tag = cbor2.loads(msg)
    prot = cbor2.loads(tag.value[0])
    prot[1] = -8
    forged = cbor2.CBORTag(18, [cbor2.dumps(prot), *tag.value[1:]])
    with pytest.raises(CoseError):
        verify_sign1(cbor2.dumps(forged), public_key_pem=pub)


def test_statement_reports_alg():
    priv, pub = _pems()
    msg = sign_sign1(b"{}", alg="Ed25519", private_key_pem=priv)
    r = parse_signed_statement(msg, public_key_pem=pub)
    assert r["signature_verified"] is True and r["alg"] == "Ed25519"


def _receipt(alg):
    priv, pub = _pems()
    leaf = b"leaf-bytes".hex()
    rc = build_receipt(
        leaf_entry_hex=leaf, leaf_index=0, tree_entries_hex=[leaf],
        alg=alg, log_private_key_pem=priv,
    )
    return rc, leaf, pub


@pytest.mark.parametrize("alg", ["Ed25519", "EdDSA"])
def test_receipt_roundtrip(alg):
    rc, leaf, pub = _receipt(alg)
    assert verify_receipt(rc, leaf_entry_hex=leaf, log_public_key_pem=pub).ok


def test_receipt_wrong_log_key_rejected():
    rc, leaf, _ = _receipt("Ed25519")
    _, other = _pems()
    assert not verify_receipt(rc, leaf_entry_hex=leaf, log_public_key_pem=other).ok


def test_peer_statement_and_receipt_verify_through_hosted_verify():
    stmt = (FIX / "verdict-record.signed-statement.cose").read_bytes()
    rc = (FIX / "verdict-record.receipt.cbor").read_bytes()
    req = {
        "statement_b64": base64.b64encode(stmt).decode(),
        "statement_pubkey_pem": (FIX / "issuer-ed25519.pub.pem").read_text(),
        "receipt_b64": base64.b64encode(rc).decode(),
        "log_pubkey_pem": _log_pem_from_jwks().decode(),
        "leaf_entry_hex": stmt.hex(),
    }
    r = verify_payload(req)
    assert r["valid"] is True, r["reasons"]
    s = r["statement"]
    assert s["signature_verified"] is True and s["alg"] == "Ed25519"
    assert s["issuer"] == "https://isoluce.net"
    assert s["subject"] == "urn:isoluce:dps:case-18:verdict-record"
    assert s["content_type"] == "application/json"
    assert r["receipt"]["ok"] is True and r["receipt"]["leaf_index"] == 2

    # wrong keys: neither verifies
    _, other = _pems()
    bad = dict(req, statement_pubkey_pem=other.decode(), log_pubkey_pem=other.decode())
    r = verify_payload(bad)
    assert r["valid"] is False
    assert r["statement"]["signature_verified"] is False
    assert r["receipt"]["ok"] is False
