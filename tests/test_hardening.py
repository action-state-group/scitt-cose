# SPDX-License-Identifier: Apache-2.0
"""Regression suite for the pre-Vienna hardening pass (docs/hardening-review.md).

Every hostile input the differential fuzzer used to surface a finding is pinned
here as an explicit unit test, so a future refactor cannot silently reopen the
class. Each test names the finding id it guards.

The umbrella property — "the two runtimes agree, with zero known divergences" —
is enforced separately by the differential fuzzer (empty baseline). These tests
pin the Python side's specific, intended behaviour per finding.
"""
from __future__ import annotations

import cbor2
import pytest

from scitt_cose import (
    build_receipt,
    build_signed_statement,
    merkle_root,
    parse_signed_statement,
    verify_receipt,
)
from scitt_cose.cose_sign1 import (
    HDR_ALG,
    MAX_MESSAGE_BYTES,
    CoseError,
    strict_decode,
)
from scitt_cose.merkle import (
    MAX_TREE_SIZE,
    _expected_inclusion_path_len,
    root_from_inclusion_proof,
)
from scitt_cose.receipt import HDR_VDP, HDR_VDS, VDP_INCLUSION_PROOFS


@pytest.fixture
def signed_statement(eddsa_keys):
    priv, pub = eddsa_keys
    msg = build_signed_statement(
        b'{"x":1}', alg="EdDSA", private_key_pem=priv,
        issuer="https://issuer.example", subject="urn:s", content_type="application/json",
    )
    return msg, pub


@pytest.fixture
def good_receipt(eddsa_keys):
    priv, pub = eddsa_keys
    entries = [bytes([i]).hex() for i in range(5)]
    receipt = build_receipt(
        leaf_entry_hex=entries[2], leaf_index=2, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv,
    )
    return receipt, entries, pub


def _retag(msg: bytes, mutate):
    tag = cbor2.loads(msg)
    v = list(tag.value)
    mutate(v)
    return cbor2.dumps(cbor2.CBORTag(tag.tag, v))


# --- H4: trailing bytes + indefinite-length (malleability / conformance split) ---


def test_h4_trailing_bytes_rejected(signed_statement):
    msg, pub = signed_statement
    assert parse_signed_statement(msg, public_key_pem=pub)["signature_verified"] is True
    for extra in (b"\x00", b"junk", b"\xff" * 40):
        parsed = parse_signed_statement(msg + extra, public_key_pem=pub)
        assert parsed["signature_verified"] is False, extra
    with pytest.raises(CoseError, match="trailing bytes"):
        strict_decode(msg + b"\x00")


def test_h4_indefinite_payload_rejected(signed_statement):
    msg, pub = signed_statement
    tag = cbor2.loads(msg)
    p, u, payload, sig = list(tag.value)
    indef = b"\x5f" + cbor2.dumps(payload) + b"\xff"
    mutant = b"\xd2\x84" + cbor2.dumps(p) + cbor2.dumps(u) + indef + cbor2.dumps(sig)
    assert parse_signed_statement(mutant, public_key_pem=pub)["signature_verified"] is False
    with pytest.raises(CoseError):
        strict_decode(mutant)


# --- M2: duplicate protected-header keys (algorithm confusion) ---


def test_m2_duplicate_protected_key_rejected(signed_statement):
    msg, pub = signed_statement
    dup_protected = b"\xa2\x01\x27\x01\x26"  # map(2){1:-8, 1:-7}
    mutant = _retag(msg, lambda v: v.__setitem__(0, dup_protected))
    with pytest.raises(CoseError, match="duplicate keys"):
        strict_decode(mutant)
    assert parse_signed_statement(mutant, public_key_pem=pub)["signature_verified"] is False


# --- H1: bytes(int) memory-exhaustion guard ---


def test_h1_giant_int_inclusion_proof_no_alloc(good_receipt, eddsa_keys):
    _r, _entries, pub = good_receipt
    protected = cbor2.dumps({HDR_ALG: -8, HDR_VDS: 1})
    # A tiny receipt declaring an ~8 GB inclusion-proof element. Must be rejected
    # without ever calling bytes() on the integer.
    mutant = cbor2.dumps(cbor2.CBORTag(18, [
        protected, {HDR_VDP: {VDP_INCLUSION_PROOFS: [8_000_000_000]}}, b"x" * 32, b"s",
    ]))
    res = verify_receipt(mutant, leaf_entry_hex="78" * 32, log_public_key_pem=pub)
    assert res.ok is False
    assert any("byte string" in e for e in res.errors)


def test_h1_too_many_inclusion_proofs_rejected(good_receipt, eddsa_keys):
    _r, _entries, pub = good_receipt
    protected = cbor2.dumps({HDR_ALG: -8, HDR_VDS: 1})
    proofs = [cbor2.dumps([8, 2, []])] * 64
    mutant = cbor2.dumps(cbor2.CBORTag(18, [
        protected, {HDR_VDP: {VDP_INCLUSION_PROOFS: proofs}}, b"x" * 32, b"s",
    ]))
    res = verify_receipt(mutant, leaf_entry_hex="78" * 32, log_public_key_pem=pub)
    assert res.ok is False
    assert any("too many inclusion proofs" in e for e in res.errors)


# --- H2 / H3 / M5: Merkle resource bounds + explicit path length ---


def test_h3_huge_tree_size_returns_none_not_recursionerror():
    # tree_size beyond the ceiling: rejected before any fold; never raises.
    assert root_from_inclusion_proof("00" * 32, 0, MAX_TREE_SIZE + 1, []) is None
    # A path whose length matches a huge (but capped) tree would otherwise drive
    # deep recursion — the ceiling check stops it.
    big = (1 << 70)
    assert root_from_inclusion_proof("00" * 32, 0, big, [b"\x00".hex()] * 70) is None


def test_m5_wrong_path_length_rejected():
    # Valid tree, but a path that is too short or too long is rejected outright.
    entries = [bytes([i]).hex() for i in range(8)]
    root = merkle_root(entries)
    from scitt_cose.merkle import inclusion_proof, verify_inclusion
    good_path = inclusion_proof(entries, 3)
    assert verify_inclusion(entries[3], 3, 8, good_path, root)
    assert root_from_inclusion_proof(entries[3], 3, 8, good_path[:-1]) is None  # short
    assert root_from_inclusion_proof(entries[3], 3, 8, good_path + good_path[:1]) is None  # long


def test_h3_huge_tree_size_receipt_returns_cleanly(good_receipt, eddsa_keys):
    _r, _entries, pub = good_receipt
    protected = cbor2.dumps({HDR_ALG: -8, HDR_VDS: 1})
    proof = cbor2.dumps([1 << 100, 0, [b"\x00" * 32]])  # tree_size > ceiling
    mutant = cbor2.dumps(cbor2.CBORTag(18, [
        protected, {HDR_VDP: {VDP_INCLUSION_PROOFS: [proof]}}, b"x" * 32, b"s",
    ]))
    # Must return a ReceiptResult (never raise), ok=False.
    res = verify_receipt(mutant, leaf_entry_hex="00" * 32, log_public_key_pem=pub)
    assert res.ok is False


# --- M6: no public verifier leaks a non-CoseError on malformed input ---


@pytest.mark.parametrize("bad", [b"", b"\x00", b"not cbor", b"\xd2\x84", b"\x9f\x01\xff"])
def test_m6_parse_never_raises(bad, eddsa_keys):
    _priv, pub = eddsa_keys
    # With and without a key, parse_signed_statement returns structured output.
    assert parse_signed_statement(bad, public_key_pem=pub)["signature_verified"] is False
    out = parse_signed_statement(bad)
    assert out["signature_verified"] is None


def test_m6_verify_receipt_never_raises(good_receipt, signed_statement, eddsa_keys):
    _r, _entries, pub = good_receipt
    # Truncations and a spliced inner inclusion proof must not raise.
    for bad in (b"", b"\x00", b"\xd2\x84"):
        assert verify_receipt(bad, leaf_entry_hex="00" * 32, log_public_key_pem=pub).ok is False
    # Inclusion proof that is not valid CBOR inside an otherwise-shaped receipt.
    protected = cbor2.dumps({HDR_ALG: -8, HDR_VDS: 1})
    mutant = cbor2.dumps(cbor2.CBORTag(18, [
        protected, {HDR_VDP: {VDP_INCLUSION_PROOFS: [b"\x9f\x9f"]}}, b"x" * 32, b"s",
    ]))
    assert verify_receipt(mutant, leaf_entry_hex="00" * 32, log_public_key_pem=pub).ok is False


# --- M3: identity never surfaced as authenticated unless the signature verified -


def test_m3_identity_fenced_when_unverified(signed_statement, other_eddsa_keys):
    msg, _pub = signed_statement
    _o, wrong_pub = other_eddsa_keys
    parsed = parse_signed_statement(msg, public_key_pem=wrong_pub)
    assert parsed["signature_verified"] is False
    assert parsed["issuer"] is None and parsed["subject"] is None
    assert parsed["unverified"]["issuer"] == "https://issuer.example"


def test_m3_identity_authenticated_when_verified(signed_statement):
    msg, pub = signed_statement
    parsed = parse_signed_statement(msg, public_key_pem=pub)
    assert parsed["signature_verified"] is True
    assert parsed["issuer"] == "https://issuer.example"
    assert parsed["unverified"] is None


# --- message size cap ---


def test_message_size_cap():
    with pytest.raises(CoseError, match="too large"):
        strict_decode(b"\x00" * (MAX_MESSAGE_BYTES + 1))


# --- review round 2: strict_decode must be order-tolerant (no false reject) ---


def _sign(priv, protected_bstr, payload):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(priv, password=None)
    assert isinstance(key, ed25519.Ed25519PrivateKey)
    from scitt_cose.cose_sign1 import _sig_structure
    return key.sign(_sig_structure(protected_bstr, payload))


def test_multikey_unprotected_noncanonical_order_accepted(eddsa_keys):
    """R1: a validly-signed statement whose unprotected header has multiple keys
    in non-canonical ORDER must still verify — COSE does not require deterministic
    ordering of the (unsigned) unprotected header. Only dup/indefinite/non-minimal
    are malleable, and those change the encoded length; reordering does not."""
    priv, pub = eddsa_keys
    prot = cbor2.dumps({HDR_ALG: -8, 3: "application/json", 15: {1: "iss", 2: "sub"}})
    sig = _sign(priv, prot, b"payload")
    # unprotected map emitted with keys 394 BEFORE 4 (not canonical order)
    msg = b"\xd2\x84" + cbor2.dumps(prot) + cbor2.dumps({394: [b"r"], 4: b"kid"}) \
        + cbor2.dumps(b"payload") + cbor2.dumps(sig)
    strict_decode(msg)  # must not raise
    assert parse_signed_statement(msg, public_key_pem=pub)["signature_verified"] is True


def test_duplicate_unprotected_key_rejected(eddsa_keys):
    priv, _pub = eddsa_keys
    prot = cbor2.dumps({HDR_ALG: -8})
    sig = _sign(priv, prot, b"p")
    dup = b"\xd2\x84" + cbor2.dumps(prot) + b"\xa2\x04\x41a\x04\x41b" + cbor2.dumps(b"p") + cbor2.dumps(sig)
    with pytest.raises(CoseError):
        strict_decode(dup)


def test_nested_duplicate_key_in_protected_rejected():
    """R6: duplicate keys inside a nested map in the protected header (e.g. two
    'iss' in the CWT claims map) are rejected, not silently last-wins."""
    nested_dup_protected = b"\xa1\x0f\xa2\x01aa\x01ab"  # {15: {1:"a", 1:"b"}}
    msg = b"\xd2\x84" + cbor2.dumps(nested_dup_protected) + cbor2.dumps({}) \
        + cbor2.dumps(b"p") + cbor2.dumps(b"s")
    with pytest.raises(CoseError):
        strict_decode(msg)


def test_deeply_nested_protected_no_raise(eddsa_keys):
    """R2: a pathologically nested protected header must be a clean reject
    (signature_verified=False), never a leaked CBORDecodeError/RecursionError."""
    _priv, pub = eddsa_keys
    deep = cbor2.dumps(cbor2.CBORTag(18, [b"\x81" * 450 + b"\x00", {}, b"p", b"s"]))
    assert parse_signed_statement(deep, public_key_pem=pub)["signature_verified"] is False
    assert parse_signed_statement(deep)["signature_verified"] is None


def test_r3_tree_size_ceiling_band_rejected():
    """R3: tree_size in (2^62, 2^63] is rejected — the Python ceiling matches the
    int64-representable Go ceiling exactly, so the two runtimes never disagree on
    a tree_size one accepts and the other cannot represent."""
    assert MAX_TREE_SIZE == 1 << 62
    n = _expected_inclusion_path_len(1 << 62, 0)  # bounded depth
    # A correctly-sized path for 2^63-1 (above the ceiling) must still be rejected.
    assert root_from_inclusion_proof("de" * 32, 0, 2**63 - 1, ["00" * 32] * n) is None
    assert root_from_inclusion_proof("de" * 32, 0, (1 << 62) + 1, ["00" * 32] * n) is None
