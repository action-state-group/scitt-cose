# SPDX-License-Identifier: Apache-2.0
"""Checkpoint drop-zone verification — the ``json-ed25519`` wire form.

This checks ONLY the checkpoint's own Ed25519 signature over its 9-field
signing body (sorted-key/compact-separator JSON, sha256 hex digest, signed
over the hex STRING's ascii bytes).

Two kinds of vectors:

* ``test_upstream_vector_*`` use the CLL checkpoint conformance vectors,
  vendored byte-verbatim in ``tests/fixtures/cll-checkpoint/`` (provenance
  and digest in that directory's README). The CLL reference emitter produced
  every digest and signature there; nothing in them came from this repo, so
  these tests are what show this verifier agrees with that emitter.
* Every other test signs with a fresh key generated here. Those vectors are
  self-generated, so they exercise the verifier's failure paths (tampering,
  wrong key, missing key, malformed input) but prove nothing about agreement
  with any other implementation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hosted_profiles.hosted import (
    checkpoint_json_digest_hex,
    verify_checkpoint_json,
    verify_payload,
)

_UPSTREAM_VECTORS = Path(__file__).parent / "fixtures" / "cll-checkpoint" / "vectors.json"
#: Raw SHA-256 of the vendored file, as recorded in its README.
_UPSTREAM_VECTORS_SHA256 = "e7d2813e8eca011e7d6016ac89ac0f20fb4f74772eb7fa436cc7482290a7a2a2"
_WIRE_FIELDS = (
    "v", "kind", "log_id", "mmr_size", "root",
    "prev_size", "prev_root", "key_id", "timestamp", "signature",
)


def _load_upstream() -> dict:
    raw = _UPSTREAM_VECTORS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _UPSTREAM_VECTORS_SHA256, (
        "vendored CLL checkpoint vectors changed; re-vendor from upstream and "
        "update the digest in the README and here together"
    )
    return json.loads(raw)


_UPSTREAM = _load_upstream()
_UPSTREAM_CASES = _UPSTREAM["cases"]


def _wire(case: dict) -> dict:
    """The checkpoint as it travels: the 9 signed fields + ``signature``,
    without the vector file's expected-value and description keys."""
    return {k: case[k] for k in _WIRE_FIELDS}


def _sign_checkpoint(priv: Ed25519PrivateKey, cp: dict) -> dict:
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


def test_self_signed_checkpoint_verifies(keypair, checkpoint_fields):
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
    checker that defaults to pass on missing input is the false-assurance
    bug class this check exists to catch."""
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
    assert result["signature_verified"] is True
    joined = " ".join(result["reasons"]).lower()
    assert "does not confirm any witness" in joined


def test_upstream_vectors_present():
    """Guard against the parametrized tests below collecting zero cases."""
    assert len(_UPSTREAM_CASES) == _UPSTREAM["count"] == 2


@pytest.mark.parametrize("case", _UPSTREAM_CASES, ids=[c["name"] for c in _UPSTREAM_CASES])
def test_upstream_vector_digest_matches(case):
    assert checkpoint_json_digest_hex(_wire(case)) == case["digest_hex"]


@pytest.mark.parametrize("case", _UPSTREAM_CASES, ids=[c["name"] for c in _UPSTREAM_CASES])
def test_upstream_vector_signature_verifies(case):
    result = verify_checkpoint_json(json.dumps(_wire(case)), _UPSTREAM["key_id"])
    assert result["signature_verified"] is True, result["reasons"]


@pytest.mark.parametrize("case", _UPSTREAM_CASES, ids=[c["name"] for c in _UPSTREAM_CASES])
def test_upstream_vector_tampered_field_fails(case):
    wire = _wire(case)
    wire["mmr_size"] += 1
    result = verify_checkpoint_json(json.dumps(wire), _UPSTREAM["key_id"])
    assert result["signature_verified"] is False
