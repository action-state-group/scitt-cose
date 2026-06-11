# SPDX-License-Identifier: Apache-2.0
"""Exhaustive negative conformance: the spec's MUST-REJECT conditions.

A verifier earns trust by rejecting *exactly* what the standard says is invalid.
The obvious four (tampered payload, wrong key, bad vds, malformed CBOR) are
covered in the per-module tests; this file enumerates the *subtle* ones — the
cases that quietly pass a careless verifier and become a credibility disaster
the first time someone in the community finds them.

Each test names the MUST-reject condition and its spec basis. Grouped:

  Statement / COSE_Sign1 (RFC 9052)
    - algorithm confusion (alg vs key type)
    - missing / non-integer alg
    - ES256 signature not 64 raw bytes (r||s)
    - critical-header (crit) marking an unknown header
    - crit listing a header absent from the protected map
    - tampered protected header bstr (signature is bound to exact bytes)
    - wrong CBOR tag / not a COSE_Sign1 / garbage CBOR

  Receipt (RFC 9162 + COSE Receipts draft)
    - vds stripped from the protected (integrity-protected) header
    - vds present only in the UNPROTECTED header (downgrade attempt)
    - missing alg in the receipt protected header
    - inclusion proof for the wrong leaf / different log key

  Merkle (RFC 6962 §2.1)
    - inclusion proof index out of range
    - inclusion proof with a too-long / too-short audit path
    - consistency proof for a SHRUNK tree (n < m)
    - consistency proof with a tampered node
"""
from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from scitt_cose import (
    build_receipt,
    consistency_proof,
    merkle_root,
    verify_consistency,
    verify_receipt,
    verify_sign1,
)
from scitt_cose.cose_sign1 import (
    HDR_ALG,
    HDR_CRIT,
    CoseError,
    sign_sign1,
)
from scitt_cose.merkle import root_from_inclusion_proof
from scitt_cose.receipt import HDR_VDS, VDS_RFC9162_SHA256


def _ed():
    sk = ed25519.Ed25519PrivateKey.generate()
    return (
        sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _ec():
    sk = ec.generate_private_key(ec.SECP256R1())
    return (
        sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        sk.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _parts(msg: bytes):
    """Decode a COSE_Sign1 into (tag_number, mutable 4-element list).

    cbor2>=6 returns ``CBORTag.value`` as an immutable ``tuple`` (and maps as
    ``frozendict``), so tampering must rebuild rather than assign in place.
    """
    tag = cbor2.loads(msg)
    return tag.tag, list(tag.value)


def _rewrap(tag_number: int, value: list) -> bytes:
    return cbor2.dumps(cbor2.CBORTag(tag_number, value))


def _pmap(bstr: bytes) -> dict:
    """Decode a protected-header bstr into a MUTABLE dict (cbor2>=6 -> frozendict)."""
    return dict(cbor2.loads(bstr)) if bstr else {}


# === Statement / COSE_Sign1 MUST-reject =====================================


def test_alg_confusion_eddsa_alg_with_ec_key():
    """alg says EdDSA (-8) but the verifying key is EC — RFC 9052: reject."""
    priv, _ = _ed()
    _epriv, epub = _ec()
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=epub)


def test_alg_confusion_es256_alg_with_ed_key():
    priv, _ = _ec()
    _opriv, opub = _ed()
    msg = sign_sign1(b"x", alg="ES256", private_key_pem=priv)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=opub)


def test_missing_alg_rejected():
    """A protected header with no alg (label 1) must be rejected."""
    priv, pub = _ed()
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv)
    t, v = _parts(msg)
    p = _pmap(v[0])
    p.pop(HDR_ALG)
    v[0] = cbor2.dumps(p)
    with pytest.raises(CoseError):
        verify_sign1(_rewrap(t, v), public_key_pem=pub)


def test_noninteger_alg_rejected():
    priv, pub = _ed()
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv)
    t, v = _parts(msg)
    p = _pmap(v[0])
    p[HDR_ALG] = "EdDSA"  # string, not the integer code point
    v[0] = cbor2.dumps(p)
    with pytest.raises(CoseError):
        verify_sign1(_rewrap(t, v), public_key_pem=pub)


def test_es256_signature_wrong_length_rejected():
    """COSE ES256 signature is raw r||s (64 bytes); DER or any other length out."""
    priv, pub = _ec()
    msg = sign_sign1(b"x", alg="ES256", private_key_pem=priv)
    t, v = _parts(msg)
    v[3] = bytes(v[3]) + b"\x00"  # 65 bytes
    with pytest.raises(CoseError):
        verify_sign1(_rewrap(t, v), public_key_pem=pub)


def test_crit_unknown_header_rejected():
    """RFC 9052 §3.1: a header marked critical but not understood -> reject."""
    priv, pub = _ed()
    # Sign with a critical private header (label 0xBEEF) the verifier can't know.
    msg = sign_sign1(
        b"x", alg="EdDSA", private_key_pem=priv,
        protected={HDR_CRIT: [0xBEEF], 0xBEEF: "must-understand-me"},
    )
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=pub)


def test_crit_understood_header_accepted():
    """crit marking alg (a header we DO understand) verifies fine."""
    priv, pub = _ed()
    msg = sign_sign1(
        b"x", alg="EdDSA", private_key_pem=priv,
        protected={HDR_CRIT: [HDR_ALG]},
    )
    s1 = verify_sign1(msg, public_key_pem=pub, understood_labels=frozenset({HDR_ALG, HDR_CRIT}))
    assert s1.payload == b"x"


def test_crit_lists_absent_header_rejected():
    """crit referencing a label not present in the protected map -> reject."""
    priv, pub = _ed()
    msg = sign_sign1(
        b"x", alg="EdDSA", private_key_pem=priv,
        protected={HDR_CRIT: [99]},  # 99 not in the protected header
    )
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=pub, understood_labels=frozenset({HDR_ALG, HDR_CRIT, 99}))


def test_tampered_protected_bstr_rejected():
    """The signature is bound to the exact protected bytes; flip one -> reject."""
    priv, pub = _ed()
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv, protected={3: "text/plain"})
    t, v = _parts(msg)
    p = bytearray(v[0])
    p[-1] ^= 0x01
    v[0] = bytes(p)
    with pytest.raises(CoseError):
        verify_sign1(_rewrap(t, v), public_key_pem=pub)


def test_wrong_cbor_tag_rejected():
    priv, pub = _ed()
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv)
    tag = cbor2.loads(msg)
    rewrapped = cbor2.dumps(cbor2.CBORTag(17, tag.value))  # 17 = COSE_Mac0, not Sign1
    with pytest.raises(CoseError):
        verify_sign1(rewrapped, public_key_pem=pub)


def test_garbage_cbor_rejected():
    _priv, pub = _ed()
    with pytest.raises(CoseError):
        verify_sign1(b"\xff\xff\xff not cbor", public_key_pem=pub)


def test_valid_signature_over_different_detached_payload_rejected():
    """A signature valid for payload A must not verify for payload B (detached)."""
    priv, pub = _ed()
    msg = sign_sign1(b"payload-A", alg="EdDSA", private_key_pem=priv, detached=True)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=pub, detached_payload=b"payload-B")


# === Receipt MUST-reject =====================================================


def _receipt_and_key():
    priv, pub = _ed()
    entries = [bytes([i]).hex() for i in range(6)]
    receipt = build_receipt(
        leaf_entry_hex=entries[3], leaf_index=3, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv,
    )
    return receipt, pub, entries


def test_receipt_vds_stripped_from_protected_rejected():
    """vds is security-relevant; if absent from the protected header -> reject."""
    receipt, pub, entries = _receipt_and_key()
    t, v = _parts(receipt)
    p = _pmap(v[0])
    p.pop(HDR_VDS)
    v[0] = cbor2.dumps(p)
    res = verify_receipt(_rewrap(t, v), leaf_entry_hex=entries[3], log_public_key_pem=pub)
    assert res.ok is False
    assert any("vds" in e for e in res.errors)


def test_receipt_vds_only_in_unprotected_rejected():
    """A downgrade: vds moved to the UNPROTECTED header must not be honored."""
    receipt, pub, entries = _receipt_and_key()
    t, v = _parts(receipt)
    p = _pmap(v[0])
    p.pop(HDR_VDS, None)
    v[0] = cbor2.dumps(p)
    u = dict(v[1]) if hasattr(v[1], "items") else {}
    u[HDR_VDS] = VDS_RFC9162_SHA256  # attacker puts it where it's unsigned
    v[1] = u
    res = verify_receipt(_rewrap(t, v), leaf_entry_hex=entries[3], log_public_key_pem=pub)
    assert res.ok is False


def test_receipt_missing_alg_rejected():
    receipt, pub, entries = _receipt_and_key()
    t, v = _parts(receipt)
    p = _pmap(v[0])
    p.pop(HDR_ALG, None)
    v[0] = cbor2.dumps(p)
    res = verify_receipt(_rewrap(t, v), leaf_entry_hex=entries[3], log_public_key_pem=pub)
    assert res.ok is False


def test_receipt_wrong_log_key_rejected():
    receipt, _pub, entries = _receipt_and_key()
    _opriv, opub = _ed()
    res = verify_receipt(receipt, leaf_entry_hex=entries[3], log_public_key_pem=opub)
    assert res.ok is False


# === Merkle MUST-reject ======================================================


def test_inclusion_index_out_of_range_rejected():
    entries = [bytes([i]).hex() for i in range(4)]
    root = merkle_root(entries)
    # index >= tree_size cannot reconstruct a root
    assert root_from_inclusion_proof(entries[0], 5, 4, []) is None
    assert root != root_from_inclusion_proof(entries[0], 5, 4, [])  # sanity


def test_inclusion_too_long_path_rejected():
    entries = [bytes([i]).hex() for i in range(4)]
    from scitt_cose import inclusion_proof
    path = inclusion_proof(entries, 1)
    bloated = path + ["00" * 32]
    assert root_from_inclusion_proof(entries[1], 1, 4, bloated) is None


def test_inclusion_too_short_path_rejected():
    entries = [bytes([i]).hex() for i in range(4)]
    from scitt_cose import inclusion_proof
    path = inclusion_proof(entries, 1)
    assert root_from_inclusion_proof(entries[1], 1, 4, path[:-1]) is None


def test_consistency_shrunk_tree_rejected():
    """A consistency proof where n < m is nonsensical and must raise."""
    entries = [bytes([i]).hex() for i in range(4)]
    with pytest.raises(ValueError):
        consistency_proof(entries, 4, 2)  # m=4 > n=2


def test_consistency_tampered_node_rejected():
    entries = [bytes([i]).hex() for i in range(8)]
    old_root = merkle_root(entries[:3])
    new_root = merkle_root(entries)
    proof = consistency_proof(entries, 3, 8)
    tampered = list(proof)
    tampered[0] = ("00" * 32)
    assert verify_consistency(old_root, new_root, 3, 8, tampered) is False
