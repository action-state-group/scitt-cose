# SPDX-License-Identifier: Apache-2.0
"""The receipt encoding rule (scitt-cose#106): ``verify_receipt`` decides
receipts as agent-action-capsule's interop profile v1 §6.2.2 does, on
checkpointed-local-log's shared receipt vectors and on each clause."""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scitt_cose import _encoding_rule
from scitt_cose.cose_sign1 import CoseError, sign_sign1, verify_sign1
from scitt_cose.receipt import build_receipt, verify_receipt

_VECTORS = json.loads(
    (Path(__file__).resolve().parent.parent / "test-vectors" / "cll-receipt" / "receipt-vectors.json").read_text()
)
_PEM = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_VECTORS["authority_public_key_hex"])).public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)


@pytest.mark.parametrize("case", _VECTORS["cases"], ids=[c["name"] for c in _VECTORS["cases"]])
def test_cll_receipt_vectors(case):
    r = verify_receipt(
        base64.b64decode(case["receipt_b64"]),
        leaf_entry_hex=_VECTORS["entry_hash_hex"],
        log_public_key_pem=_PEM,
    )
    if case["accept"]:
        assert r.ok, r.errors
        assert (r.tree_size, r.leaf_index) == (case["tree_size"], case["leaf_index"])
    else:
        assert not r.ok
        assert r.failed_at is not None


def _nest(depth: int) -> bytes:
    """An item ``depth`` levels below the top: ``depth`` one-element arrays
    around a 0."""
    return b"\x81" * depth + b"\x00"


ACCEPTED = {
    "unsigned 2^64-1": b"\x1b" + b"\xff" * 8,
    "negative -2^63": b"\x3b\x7f" + b"\xff" * 7,
    "false, true, null": b"\x83\xf4\xf5\xf6",
    "integer and text keys out of order": b"\xa2\x61a\x01\x01\x02",
    "valid UTF-8": b"\x62\xc3\xa9",
    "item 16 levels deep": _nest(16),
    "empty array and map": b"\x82\x80\xa0",
}

REFUSED = {
    "an indefinite length": (b"\x9f\x00\xff", "indefinite"),
    "an indefinite byte string": (b"\x5f\x41\x00\xff", "indefinite"),
    "a non-shortest integer": (b"\x18\x17", "shortest"),
    "a non-shortest length": (b"\x59\x00\x01\x00", "shortest"),
    "a non-shortest 8-octet argument": (b"\x1b\x00\x00\x00\x00\xff\xff\xff\xff", "shortest"),
    "an integer below -2^63": (b"\x3b\x80" + b"\x00" * 7, "below -2^63"),
    "a repeated key": (b"\xa2\x01\x00\x01\x00", "repeated"),
    "a byte-string key": (b"\xa1\x41\x00\x00", "map key"),
    "an array key": (b"\xa1\x80\x00", "map key"),
    "a float key": (b"\xa1\xf9\x7e\x00\x00", "map key"),
    "invalid UTF-8": (b"\x61\xff", "UTF-8"),
    "a half float": (b"\xf9\x3c\x00", "float"),
    "a double": (b"\xfb" + b"\x00" * 8, "float"),
    "undefined": (b"\xf7", "simple value"),
    "simple value 0": (b"\xe0", "simple value"),
    "a one-octet simple value": (b"\xf8\x20", "simple value"),
    "a tag": (b"\xc1\x00", "tag"),
    "a bignum": (b"\xc2\x41\x01", "tag"),
    "a reserved additional information": (b"\x1c", "reserved"),
    "an item 17 levels deep": (_nest(17), "16 levels"),
    "trailing octets": (b"\x00\x00", "trailing"),
    "a truncated item": (b"\x82\x00", "truncated"),
    "a length past the end": (b"\x5a\xff\xff\xff\xff", "truncated"),
    "nothing": (b"", "truncated"),
}


@pytest.mark.parametrize("octets", ACCEPTED.values(), ids=ACCEPTED.keys())
def test_rule_accepts(octets):
    _encoding_rule.check(octets, "item")


@pytest.mark.parametrize("octets,needle", REFUSED.values(), ids=REFUSED.keys())
def test_rule_refuses(octets, needle):
    with pytest.raises(CoseError, match=re.escape(needle)):
        _encoding_rule.check(octets, "item")


def test_tag_18_only_on_the_top_item():
    sign1 = b"\xd2\x84\x40\xa0\xf6\x40"
    _encoding_rule.check(sign1, "item", outer_tag=True)
    with pytest.raises(CoseError, match="tag"):
        _encoding_rule.check(sign1, "item")
    with pytest.raises(CoseError, match="tag"):
        _encoding_rule.check(b"\x81" + sign1, "item", outer_tag=True)
    with pytest.raises(CoseError, match="tag"):
        _encoding_rule.check(b"\xd1\x84\x40\xa0\xf6\x40", "item", outer_tag=True)


def _entries(n):
    return [bytes([i, 7, i]).hex() for i in range(n)]


def _with_unprotected(receipt: bytes, extra: dict) -> bytes:
    """The receipt with labels added to its unsigned header, so its
    signature still verifies."""
    outer = cbor2.loads(receipt)
    protected, unprotected, payload, signature = outer.value
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {**unprotected, **extra}, payload, signature]))


@pytest.mark.parametrize(
    "value",
    [1.5, cbor2.CBORTag(1, 0), cbor2.undefined, cbor2.CBORSimpleValue(0), 2**64],
    ids=["float", "tag", "undefined", "simple", "bignum"],
)
def test_signed_receipt_with_a_forbidden_unread_value_fails(eddsa_keys, value):
    priv, pub = eddsa_keys
    es = _entries(3)
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA", log_private_key_pem=priv
    )
    assert verify_receipt(_with_unprotected(receipt, {4: 7}), leaf_entry_hex=es[1], log_public_key_pem=pub).ok
    r = verify_receipt(_with_unprotected(receipt, {-70000: value}), leaf_entry_hex=es[1], log_public_key_pem=pub)
    assert not r.ok
    assert r.failed_at == "structure"
    # strict_decode already refuses a float or tag that cbor2 encodes in a
    # longer form; the rule refuses the rest.
    assert any(e.startswith("receipt rejected:") for e in r.errors), r.errors


def test_crit_label_must_be_an_integer_or_text(eddsa_keys):
    """``crit: [true]`` is not the alg label 1, in a receipt or any COSE_Sign1."""
    priv, pub = eddsa_keys
    for crit, ok in (([1], True), ([True], False)):
        msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv, protected={2: crit})
        if ok:
            verify_sign1(msg, public_key_pem=pub)
        else:
            with pytest.raises(CoseError, match="not an integer or a text string"):
                verify_sign1(msg, public_key_pem=pub)


def _signed(protected: dict, leaf_hex: str, key) -> bytes:
    """A one-leaf EdDSA receipt with exactly ``protected`` as its header, so
    a test can sign labels ``build_receipt`` would not write."""
    import hashlib

    from scitt_cose.cose_sign1 import _sig_structure

    root = hashlib.sha256(b"\x00" + bytes.fromhex(leaf_hex)).digest()
    protected_bstr = cbor2.dumps(protected)
    signature = key.sign(_sig_structure(protected_bstr, root))
    proof = cbor2.dumps([1, 0, []])
    return cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, {396: {-1: [proof]}}, None, signature]))


def _key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return key, pem


def test_a_long_array_under_an_unread_label_is_accepted(eddsa_keys):
    """The rule limits no array or map other than by the octet limit; a CBOR
    library's default cap (fxamacker's 131,072) must not decide it."""
    priv, pub = eddsa_keys
    es = _entries(3)
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA", log_private_key_pem=priv
    )
    long = _with_unprotected(receipt, {-70000: [0] * 131073, -70001: {i: 0 for i in range(131073)}})
    assert verify_receipt(long, leaf_entry_hex=es[1], log_public_key_pem=pub).ok


def test_octet_limit(eddsa_keys):
    from scitt_cose.cose_sign1 import MAX_MESSAGE_BYTES

    priv, pub = eddsa_keys
    es = _entries(3)
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA", log_private_key_pem=priv
    )
    pad = MAX_MESSAGE_BYTES - len(_with_unprotected(receipt, {-70000: b"\x00" * 70000})) + 70000
    at_limit = _with_unprotected(receipt, {-70000: b"\x00" * pad})
    assert len(at_limit) == MAX_MESSAGE_BYTES
    assert verify_receipt(at_limit, leaf_entry_hex=es[1], log_public_key_pem=pub).ok
    over = _with_unprotected(receipt, {-70000: b"\x00" * (pad + 1)})
    r = verify_receipt(over, leaf_entry_hex=es[1], log_public_key_pem=pub)
    assert not r.ok and r.failed_at == "structure"


def test_an_alg_above_int64_is_not_eddsa():
    """2^64-8 must not wrap to -8 (EdDSA) in any verifier."""
    key, pem = _key()
    leaf = "aa"
    assert verify_receipt(_signed({1: -8, 395: 1}, leaf, key), leaf_entry_hex=leaf, log_public_key_pem=pem).ok
    r = verify_receipt(_signed({1: 2**64 - 8, 395: 1}, leaf, key), leaf_entry_hex=leaf, log_public_key_pem=pem)
    assert not r.ok


def test_a_bad_crit_fails_before_any_proof_is_read():
    """As in the Rust and Go verifiers: failed_at is structure, no root."""
    key, pem = _key()
    leaf = "aa"
    r = verify_receipt(_signed({1: -8, 2: [99], 99: 0, 395: 1}, leaf, key), leaf_entry_hex=leaf, log_public_key_pem=pem)
    assert not r.ok
    assert r.failed_at == "structure"
    assert (r.root, r.tree_size, r.leaf_index) == (None, None, None)
    assert any("does not understand" in e for e in r.errors), r.errors


def test_a_boolean_protected_label_is_not_the_alg_label(eddsa_keys):
    """A CBOR true key equals 1 in a Python dict; it must not pose as alg."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    from scitt_cose.cose_sign1 import _sig_structure

    priv, pub = eddsa_keys
    key = load_pem_private_key(priv, None)
    protected_bstr = cbor2.dumps({True: -8})
    signature = key.sign(_sig_structure(protected_bstr, b"x"))
    msg = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, {}, b"x", signature]))
    with pytest.raises(CoseError, match="not an integer or a text string"):
        verify_sign1(msg, public_key_pem=pub)
