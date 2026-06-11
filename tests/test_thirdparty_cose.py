# SPDX-License-Identifier: Apache-2.0
"""Third-party COSE conformance: agree with an implementation that is NOT ours.

Python<->Go (both ours) cures *self-consistency*. This file adds the other half
the reviewer asked for: agreement with a genuinely third-party COSE library —
``pycose`` — which shares no code with this package and is maintained by the
wider ecosystem. We deliberately do NOT use ``python-cwt`` here: it is the
library whose ``CWT_CLAIMS`` enum carries the label-13 bug this project exists to
guard against, so it is not an independent oracle for *this* class of error.

Two directions, because a round-trip through one stack proves little:

1. **We emit -> pycose verifies.** Our COSE_Sign1 bytes are accepted by a foreign
   verifier (and tampered bytes rejected).
2. **pycose emits -> we verify.** Our clean-room verifier accepts a statement a
   foreign library produced — so our reader is not merely the inverse of our
   writer.

SKIPS cleanly if pycose is not installed; CI installs it (``[dev]`` extra).
"""
from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from scitt_cose import build_signed_statement, verify_sign1
from scitt_cose.cose_sign1 import CoseError

pycose = pytest.importorskip("pycose")

# pycose 1.1 parses COSE via cbor2's loads and is incompatible with cbor2>=6,
# which returns immutable frozendict/tuple ("Bytes cannot be decoded as COSE
# message"). The scitt-cose LIBRARY is cbor2>=6-clean (normalized via _plain);
# this is purely the third-party oracle's limitation, so skip it on cbor2>=6.
# The Go, RFC-vector, and Authority oracles still run there.
from importlib.metadata import version as _pkg_version  # noqa: E402

if tuple(int(p) for p in _pkg_version("cbor2").split(".")[:1]) >= (6,):
    pytest.skip(
        "pycose 1.1 is incompatible with cbor2>=6 (third-party oracle only)",
        allow_module_level=True,
    )

from pycose.algorithms import EdDSA as PyEdDSA  # noqa: E402
from pycose.headers import Algorithm, ContentType  # noqa: E402
from pycose.keys import EC2Key, OKPKey  # noqa: E402
from pycose.keys.curves import P256 as PyP256  # noqa: E402
from pycose.keys.curves import Ed25519 as PyEd25519  # noqa: E402
from pycose.messages import Sign1Message  # noqa: E402

# --- Direction 1: we emit, the third party verifies -------------------------


def test_eddsa_statement_verified_by_pycose():
    sk = ed25519.Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    stmt = build_signed_statement(
        b'{"opaque":1}', alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    msg = Sign1Message.decode(stmt)
    msg.key = OKPKey(crv=PyEd25519, x=raw_pub)
    assert msg.verify_signature() is True


def test_es256_statement_verified_by_pycose():
    sk = ec.generate_private_key(ec.SECP256R1())
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    nums = sk.public_key().public_numbers()
    stmt = build_signed_statement(
        b'{"opaque":1}', alg="ES256", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    msg = Sign1Message.decode(stmt)
    msg.key = EC2Key(crv=PyP256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))
    assert msg.verify_signature() is True


def test_tampered_statement_rejected_by_pycose():
    sk = ed25519.Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    stmt = build_signed_statement(
        b"original", alg="EdDSA", private_key_pem=priv,
        issuer="i", subject="s", content_type="text/plain",
    )
    tag = cbor2.loads(stmt)
    body = bytearray(tag.value[2])
    body[0] ^= 0x01
    tag.value[2] = bytes(body)
    msg = Sign1Message.decode(cbor2.dumps(tag))
    msg.key = OKPKey(crv=PyEd25519, x=raw_pub)
    assert msg.verify_signature() is False


# --- Direction 2: the third party emits, we verify --------------------------


def test_our_verifier_accepts_pycose_emitted():
    sk = ed25519.Ed25519PrivateKey.generate()
    raw_priv = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    pub_pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    m = Sign1Message(
        phdr={Algorithm: PyEdDSA, ContentType: "application/foreign"},
        payload=b"foreign-emitted",
    )
    m.key = OKPKey(crv=PyEd25519, x=raw_pub, d=raw_priv)
    encoded = m.encode()

    s1 = verify_sign1(encoded, public_key_pem=pub_pem)
    assert s1.payload == b"foreign-emitted"
    assert s1.protected[1] == -8  # EdDSA


def test_our_verifier_rejects_pycose_emitted_under_wrong_key():
    sk = ed25519.Ed25519PrivateKey.generate()
    raw_priv = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    other = ed25519.Ed25519PrivateKey.generate()
    other_pem = other.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    m = Sign1Message(phdr={Algorithm: PyEdDSA}, payload=b"x")
    m.key = OKPKey(crv=PyEd25519, x=raw_pub, d=raw_priv)
    encoded = m.encode()
    with pytest.raises(CoseError):
        verify_sign1(encoded, public_key_pem=other_pem)
