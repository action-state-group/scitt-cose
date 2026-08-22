# SPDX-License-Identifier: Apache-2.0
"""Authenticity is three-valued in both the Python and browser (CAPSULE_JS)
verify surfaces — a verifying signature over a self-asserted key must render
as a qualified "skip", never a green "pass" (the [viewer-authenticity-tiering]
decision). This exercises the *real* CAPSULE_JS ``checkAuthenticity`` in Node
(real ``crypto.subtle`` Ed25519 verification, not a reimplementation) against
genuine COSE_Sign1 statements built with this repo's own signer, and checks
it against ``hosted_profiles.aac._check_authenticity`` for parity.

Mutant check: a bit-flipped signature must flip the JS verdict from "skip" to
"fail" — never to "skip" (which would mean a tampered statement silently hid
in the self-asserted tier instead of being caught).
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from hosted_profiles import aac
from hosted_profiles.hosted import CAPSULE_JS
from scitt_cose.statement import build_signed_statement

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_capsule_ritual.mjs"

pytestmark_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


@pytest.fixture(scope="module")
def capsule_js_path():
    f = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
    f.write(CAPSULE_JS)
    f.close()
    yield Path(f.name)
    Path(f.name).unlink(missing_ok=True)


def _run_js(capsule_js_path, op: dict):
    result = subprocess.run(
        ["node", str(HARNESS), str(capsule_js_path)],
        input=json.dumps(op),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _signed_capsule() -> tuple[dict, bytes]:
    """A capsule carrying a genuine, self-asserted-key COSE_Sign1 statement."""
    key = ed25519.Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    capsule_id = "a1" * 32
    capsule = {"capsule_id": capsule_id, "action_type": "decide"}
    payload = json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode()
    stmt = build_signed_statement(
        payload, alg="EdDSA", private_key_pem=priv_pem, issuer="acme",
        subject=capsule_id, content_type="application/json",
    )
    capsule["signed_statement"] = {
        "statement_b64": base64.b64encode(stmt).decode(),
        "pubkey_pem": pub_pem.decode(),
    }
    return capsule, stmt


@pytestmark_node
def test_js_no_statement_is_skip(capsule_js_path):
    r = _run_js(capsule_js_path, {"fn": "checkAuthenticity", "capsules": [{"capsule_id": "a1" * 32}]})
    assert r["status"] == "skip"
    assert "no signed statement" in r["detail"]


@pytestmark_node
def test_js_self_asserted_verifying_signature_is_skip_not_pass(capsule_js_path):
    """The decision this task implements, verified against REAL browser
    crypto.subtle Ed25519 verification, not a stub: a verifying signature
    over a self-asserted key must skip, with the exact required wording, and
    must never render pass."""
    capsule, _ = _signed_capsule()
    r = _run_js(capsule_js_path, {"fn": "checkAuthenticity", "capsules": [capsule]})
    assert r["status"] == "skip"
    assert r["status"] != "pass"
    assert r["detail"] == (
        "signature verifies against a key supplied with the record — this shows "
        "the bytes are unaltered since signing, not who signed them"
    )


@pytestmark_node
def test_js_tampered_signature_fails_not_skips(capsule_js_path):
    """Mutant check: flipping a byte in the signed statement must flip the
    real crypto.subtle verdict to fail — a tampered statement must not be
    able to hide in the self-asserted skip tier."""
    capsule, stmt = _signed_capsule()
    tampered = bytearray(stmt)
    tampered[-1] ^= 0xFF  # corrupt the COSE signature
    capsule["signed_statement"]["statement_b64"] = base64.b64encode(bytes(tampered)).decode()
    r = _run_js(capsule_js_path, {"fn": "checkAuthenticity", "capsules": [capsule]})
    assert r["status"] == "fail", "tampered signature must fail, not skip"
    assert r["status"] != "skip"


@pytestmark_node
@pytest.mark.parametrize("case", ["no_statement", "self_asserted", "tampered"])
def test_js_and_python_agree(capsule_js_path, case):
    """Both verify surfaces must agree on the same input -- the whole point
    of porting the same tiering to both."""
    if case == "no_statement":
        capsules = [{"capsule_id": "a1" * 32}]
    elif case == "self_asserted":
        capsule, _ = _signed_capsule()
        capsules = [capsule]
    else:
        capsule, stmt = _signed_capsule()
        tampered = bytearray(stmt)
        tampered[-1] ^= 0xFF
        capsule["signed_statement"]["statement_b64"] = base64.b64encode(bytes(tampered)).decode()
        capsules = [capsule]

    py_stage = aac._check_authenticity(capsules)
    js_result = _run_js(capsule_js_path, {"fn": "checkAuthenticity", "capsules": capsules})

    assert js_result["status"] == py_stage.status, (case, js_result, py_stage)
    assert js_result["detail"] == py_stage.detail, (case, js_result, py_stage)


@pytestmark_node
def test_js_evaluate_ritual_authenticity_stage_matches_check(capsule_js_path):
    """evaluateRitual's Authenticity stage must be exactly checkAuthenticity's
    output -- not a second, drifted code path."""
    capsule, _ = _signed_capsule()
    direct = _run_js(capsule_js_path, {"fn": "checkAuthenticity", "capsules": [capsule]})
    ritual = _run_js(
        capsule_js_path,
        {"fn": "evaluateRitual", "capsules": [capsule], "witness": None, "integrity": None},
    )
    auth_stage = next(s for s in ritual["stages"] if s["name"] == "Authenticity")
    assert auth_stage["status"] == direct["status"]
    assert auth_stage["detail"] == direct["detail"]
