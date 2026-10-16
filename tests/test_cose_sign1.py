# SPDX-License-Identifier: Apache-2.0
"""COSE_Sign1 sign/verify round-trip + tamper/wrong-key negatives."""
from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from scitt_cose.cose_sign1 import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    COSE_ALG_ES384,
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


def _pem(key, private=False):
    if private:
        return key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_es384_round_trip():
    key = ec.generate_private_key(ec.SECP384R1())
    msg = sign_sign1(b"x", alg="ES384", private_key_pem=_pem(key, private=True))
    assert len(cbor2.loads(msg).value[3]) == 96
    assert verify_sign1(msg, public_key_pem=_pem(key)).payload == b"x"


@pytest.mark.parametrize(
    "alg,curve",
    [("ES256", ec.SECP256K1), ("ES256", ec.SECP384R1), ("ES384", ec.SECP256R1), ("EdDSA", ec.SECP256R1)],
)
def test_sign_refuses_a_key_the_alg_does_not_name(alg, curve):
    key = ec.generate_private_key(curve())
    with pytest.raises(CoseError, match="requires"):
        sign_sign1(b"x", alg=alg, private_key_pem=_pem(key, private=True))


@pytest.mark.parametrize(
    "alg,curve,digest,width,message",
    [
        (COSE_ALG_ES256, ec.SECP256K1, hashes.SHA256, 32, "ES256 (-7) but the public key is not P-256"),
        (COSE_ALG_ES384, ec.SECP256R1, hashes.SHA384, 48, "ES384 (-35) but the public key is not P-384"),
        (COSE_ALG_EDDSA, ec.SECP256R1, hashes.SHA256, 32, "EdDSA (-8) but the public key is not Ed25519"),
    ],
)
def test_verify_refuses_a_key_the_alg_does_not_name(alg, curve, digest, width, message):
    """A genuine signature under a key on the wrong curve still fails: RFC 9053
    §2.1 binds ES256 to P-256 and ES384 to P-384 (#87)."""
    key = ec.generate_private_key(curve())
    protected = cbor2.dumps({1: alg})
    tbs = cbor2.dumps(["Signature1", protected, b"", b"x"])
    r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(digest())))
    msg = cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [protected, {}, b"x", r.to_bytes(width, "big") + s.to_bytes(width, "big")]))
    with pytest.raises(CoseError, match=message.replace("(", r"\(").replace(")", r"\)")):
        verify_sign1(msg, public_key_pem=_pem(key))
