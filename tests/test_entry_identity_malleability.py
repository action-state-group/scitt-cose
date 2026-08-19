# SPDX-License-Identifier: Apache-2.0
"""Regression test for docs/hardening-review.md finding L2 (corrected).

L2's closing sentence used to claim the leaf digest — SHA-256 over the full
statement bytes — is "unaffected in practice" by ES256 s-malleability. That
was wrong: the full statement bytes include the signature, so a malleated
twin ``(r, n-s)`` (SEC1 v2.0 SS4.1.3) produces a DIFFERENT full-envelope
digest for the SAME signing act. This test makes that measurement concrete
and pins the corrected understanding as a regression:

* full-envelope digest (what a leaf commitment may legitimately use) DOES
  change across the malleated twin — proving the old L2 sentence wrong;
* Sig_structure digest (what an entry identifier MUST use) does NOT change
  across the malleated twin — proving the fix direction is sound;
* a negative control (payload changes) proves neither check is a constant
  function.
"""
from __future__ import annotations

import hashlib

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from scitt_cose.cose_sign1 import _sig_structure, sign_sign1, verify_sign1

# NIST P-256 (secp256r1) group order (SEC2 SS2.4.2).
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _ec_key_pem() -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def _malleate(statement: bytes) -> bytes:
    """Flip s -> n-s in an ES256 COSE_Sign1 message, keeping everything else."""
    tag = cbor2.loads(statement)
    protected_bstr, unprotected, payload, signature = tag.value
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    s_twin = _P256_N - s
    assert s != s_twin
    sig_twin = r.to_bytes(32, "big") + s_twin.to_bytes(32, "big")
    return cbor2.dumps(cbor2.CBORTag(tag.tag, [protected_bstr, unprotected, payload, sig_twin]))


def test_full_envelope_digest_changes_for_malleated_twin():
    """The corrected L2 claim: leaf-commitment digest (full statement bytes)
    IS affected by s-malleability — it must NOT be relied on as an identity."""
    priv_pem, pub_pem = _ec_key_pem()
    payload = b"a-signed-act"

    statement = sign_sign1(payload, alg="ES256", private_key_pem=priv_pem)
    twin = _malleate(statement)
    assert statement != twin

    # Both are valid signatures over the same act.
    verify_sign1(statement, public_key_pem=pub_pem)
    verify_sign1(twin, public_key_pem=pub_pem)

    leaf_digest = hashlib.sha256(statement).hexdigest()
    leaf_digest_twin = hashlib.sha256(twin).hexdigest()
    assert leaf_digest != leaf_digest_twin, (
        "if this ever passes, the full-envelope digest has become "
        "malleability-immune and L2's original (wrong) claim would be true again"
    )


def test_sig_structure_digest_is_immune_to_malleation():
    """The entry-identifier direction: Sig_structure digest is stable per act."""
    priv_pem, pub_pem = _ec_key_pem()
    payload = b"a-signed-act"

    statement = sign_sign1(payload, alg="ES256", private_key_pem=priv_pem)
    twin = _malleate(statement)

    tag = cbor2.loads(statement)
    protected_bstr = tag.value[0]
    entry_digest = hashlib.sha256(_sig_structure(protected_bstr, payload)).hexdigest()

    tag_twin = cbor2.loads(twin)
    protected_bstr_twin = tag_twin.value[0]
    entry_digest_twin = hashlib.sha256(_sig_structure(protected_bstr_twin, payload)).hexdigest()

    assert entry_digest == entry_digest_twin


def test_negative_control_payload_change_still_differs():
    """A genuinely different act (1-bit payload change) MUST differ under both
    digest schemes — without this, the assertions above would also pass for a
    constant function and prove nothing."""
    priv_pem, _pub_pem = _ec_key_pem()

    statement_a = sign_sign1(b"payload-a", alg="ES256", private_key_pem=priv_pem)
    statement_b = sign_sign1(b"payload-b", alg="ES256", private_key_pem=priv_pem)

    assert hashlib.sha256(statement_a).hexdigest() != hashlib.sha256(statement_b).hexdigest()

    tag_a = cbor2.loads(statement_a)
    tag_b = cbor2.loads(statement_b)
    entry_a = hashlib.sha256(_sig_structure(tag_a.value[0], b"payload-a")).hexdigest()
    entry_b = hashlib.sha256(_sig_structure(tag_b.value[0], b"payload-b")).hexdigest()
    assert entry_a != entry_b
