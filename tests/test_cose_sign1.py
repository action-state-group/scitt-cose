# SPDX-License-Identifier: Apache-2.0
"""COSE_Sign1 sign/verify round-trip + tamper/wrong-key negatives."""
from __future__ import annotations

import cbor2
import pytest

from scitt_cose.cose_sign1 import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    COSE_SIGN1_TAG,
    CoseError,
    sign_sign1,
    verify_sign1,
)


def test_round_trip_both_algs(alg_keys):
    alg, priv, pub = alg_keys
    payload = b"the quick brown fox"
    msg = sign_sign1(payload, alg=alg, private_key_pem=priv)
    sign1 = verify_sign1(msg, public_key_pem=pub)
    assert sign1.payload == payload
    expected_code = COSE_ALG_EDDSA if alg == "EdDSA" else COSE_ALG_ES256
    assert sign1.protected[1] == expected_code


def test_outer_is_tag_18(eddsa_keys):
    priv, pub = eddsa_keys
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv)
    outer = cbor2.loads(msg)
    assert isinstance(outer, cbor2.CBORTag)
    assert outer.tag == COSE_SIGN1_TAG
    assert len(outer.value) == 4


def test_es256_signature_is_64_raw_bytes(es256_keys):
    priv, pub = es256_keys
    msg = sign_sign1(b"x", alg="ES256", private_key_pem=priv)
    _p, _u, _payload, sig = cbor2.loads(msg).value
    assert isinstance(sig, bytes) and len(sig) == 64


def test_protected_and_unprotected_passthrough(eddsa_keys):
    priv, pub = eddsa_keys
    msg = sign_sign1(
        b"x", alg="EdDSA", private_key_pem=priv,
        protected={3: "application/json"}, unprotected={99: "hi"},
    )
    sign1 = verify_sign1(msg, public_key_pem=pub)
    assert sign1.protected[3] == "application/json"
    assert sign1.unprotected[99] == "hi"


def test_tamper_payload_fails(eddsa_keys):
    priv, pub = eddsa_keys
    msg = sign_sign1(b"original", alg="EdDSA", private_key_pem=priv)
    outer = cbor2.loads(msg)
    p, u, _payload, sig = outer.value
    tampered = cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [p, u, b"tampered", sig]))
    with pytest.raises(CoseError):
        verify_sign1(tampered, public_key_pem=pub)


def test_wrong_key_fails(eddsa_keys, other_eddsa_keys):
    priv, _pub = eddsa_keys
    _opriv, opub = other_eddsa_keys
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=opub)


def test_detached_payload_round_trip(alg_keys):
    alg, priv, pub = alg_keys
    payload = b"detached body"
    msg = sign_sign1(payload, alg=alg, private_key_pem=priv, detached=True)
    # payload slot must be nil
    assert cbor2.loads(msg).value[2] is None
    sign1 = verify_sign1(msg, public_key_pem=pub, detached_payload=payload)
    assert sign1.payload == payload


def test_detached_requires_payload(eddsa_keys):
    priv, pub = eddsa_keys
    msg = sign_sign1(b"x", alg="EdDSA", private_key_pem=priv, detached=True)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=pub)


def test_detached_wrong_payload_fails(eddsa_keys):
    priv, pub = eddsa_keys
    msg = sign_sign1(b"real", alg="EdDSA", private_key_pem=priv, detached=True)
    with pytest.raises(CoseError):
        verify_sign1(msg, public_key_pem=pub, detached_payload=b"fake")


def test_unsupported_alg_rejected(eddsa_keys):
    priv, _pub = eddsa_keys
    with pytest.raises(CoseError):
        sign_sign1(b"x", alg="RS256", private_key_pem=priv)


def test_not_cbor_tag_rejected(eddsa_keys):
    _priv, pub = eddsa_keys
    with pytest.raises(CoseError):
        verify_sign1(cbor2.dumps([1, 2, 3, 4]), public_key_pem=pub)
