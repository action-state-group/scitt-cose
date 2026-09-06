# SPDX-License-Identifier: Apache-2.0
"""Checkpoint drop-zone verification — the ``json-ed25519`` wire form.

This checks ONLY the checkpoint's own Ed25519 signature over its 9-field
signing body. The algorithm (sorted-key/compact-separator JSON, sha256 hex
digest, sign over the hex STRING's ascii bytes) must match capsule-anchor's
``checkpoint_json.py`` / ``service._checkpoint_digest`` exactly, or every
real checkpoint fails to verify here. Test vectors are self-generated
(we don't hold any real witness's private key) — that's fine, since the
point is pinning OUR reimplementation of the shared algorithm, not
round-tripping a specific partner's bytes.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hosted_profiles.hosted import verify_checkpoint_json, verify_payload


def _sign_checkpoint(priv: Ed25519PrivateKey, cp: dict) -> dict:
    import hashlib

    signing_body = json.dumps(cp, sort_keys=True, separators=(",", ":")).encode()
    digest_hex = hashlib.sha256(signing_body).hexdigest()
    sig = priv.sign(digest_hex.encode("ascii"))
    out = dict(cp)
    out["signature"] = sig.hex()
    return out


@pytest.fixture()
def keypair():
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


@pytest.fixture()
def checkpoint_fields():
    return {
        "v": 1,
        "kind": "mmr_checkpoint",
        "log_id": "test-witness/v1",
        "mmr_size": 4,
        "root": "a" * 64,
        "prev_size": 0,
        "prev_root": "",
        "key_id": "test-key-1",
        "timestamp": "2026-09-06T00:00:00Z",
    }


def test_real_checkpoint_verifies(keypair, checkpoint_fields):
    priv, pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    result = verify_checkpoint_json(json.dumps(signed), pub_hex)
    assert result["signature_verified"] is True
    assert result["covers"]["log_id"] == "test-witness/v1"
    assert result["covers"]["mmr_size"] == 4


def test_mutant_tampered_signature_fails(keypair, checkpoint_fields):
    priv, pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    signed["signature"] = ("00" if signed["signature"][:2] != "00" else "ff") + signed["signature"][2:]
    result = verify_checkpoint_json(json.dumps(signed), pub_hex)
    assert result["signature_verified"] is False


def test_mutant_tampered_signed_field_fails(keypair, checkpoint_fields):
    """Changing a signed field WITHOUT re-signing must fail — the classic
    equality-inference bug this whole class of check exists to prevent."""
    priv, pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    signed["root"] = "b" + signed["root"][1:]
    result = verify_checkpoint_json(json.dumps(signed), pub_hex)
    assert result["signature_verified"] is False


def test_mutant_wrong_pubkey_fails(keypair, checkpoint_fields):
    priv, _pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    result = verify_checkpoint_json(json.dumps(signed), "00" * 32)
    assert result["signature_verified"] is False


def test_no_pubkey_never_reports_success(keypair, checkpoint_fields):
    """A missing key must report 'not checked' (None), never True — a
    checker that defaults to pass on missing input is the exact false-
    assurance bug class QUEUE_PROTOCOL 7a exists to catch."""
    priv, _pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    result = verify_checkpoint_json(json.dumps(signed), None)
    assert result["signature_verified"] is None
    assert result["signature_verified"] is not True


def test_malformed_json_fails_closed():
    result = verify_checkpoint_json("not json", "aa" * 32)
    assert result["signature_verified"] is False


def test_missing_fields_fails_closed():
    result = verify_checkpoint_json(json.dumps({"v": 1}), "aa" * 32)
    assert result["signature_verified"] is False


def test_wrong_kind_rejected(keypair, checkpoint_fields):
    priv, pub_hex = keypair
    checkpoint_fields = dict(checkpoint_fields, kind="not_a_checkpoint")
    signed = _sign_checkpoint(priv, checkpoint_fields)
    result = verify_checkpoint_json(json.dumps(signed), pub_hex)
    assert result["signature_verified"] is False


def test_verify_payload_integration_valid(keypair, checkpoint_fields):
    priv, pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    resp = verify_payload({"checkpoint_json": json.dumps(signed), "checkpoint_pubkey_hex": pub_hex})
    assert resp["valid"] is True
    assert resp["checkpoint"]["signature_verified"] is True


def test_verify_payload_integration_tampered_is_invalid(keypair, checkpoint_fields):
    priv, pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    signed["mmr_size"] = signed["mmr_size"] + 1  # tamper without re-signing
    resp = verify_payload({"checkpoint_json": json.dumps(signed), "checkpoint_pubkey_hex": pub_hex})
    assert resp["valid"] is False


def test_verify_payload_no_fields_is_bad_request():
    resp = verify_payload({})
    assert resp["bad_request"] is True


def test_verified_checkpoint_never_claims_witness_countersign(keypair, checkpoint_fields):
    """The honesty boundary: this tool checks the checkpoint's OWN
    signature only. It must never phrase a pass as witness confirmation."""
    priv, pub_hex = keypair
    signed = _sign_checkpoint(priv, checkpoint_fields)
    result = verify_checkpoint_json(json.dumps(signed), pub_hex)
    joined = " ".join(result["reasons"]).lower()
    assert "does not confirm" in joined or "does not" in joined
    assert "countersign" in joined or "witness" in joined
