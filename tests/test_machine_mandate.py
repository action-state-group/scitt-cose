# SPDX-License-Identifier: Apache-2.0
"""Tests for the MachineMandate profile parser, renderer, and detection.

Acceptance cases:
1. Detection: byte-verbatim pinned fixtures detected correctly; greedy shapes render OPAQUE.
2. AEP fixture renders first-class (profile_label, field groups).
3. EAR fixtures render first-class (ear.status, trustworthiness-vector).
4. Mint record renders first-class (vct, action_hash, scope, gates).
5. Client-side JS detectProfile: exercises the REAL JS path via Node subprocess.
6. Negative (greedy-claim reproductions): generic AEP shape, generic EAR shape,
   generic sha256: action_hash — each MUST render OPAQUE (detect_profile → "unknown").
7. Fixture honesty: SHA-256 of each pinned file verified against the pinned commit.
8. PROFILE_PARSERS['machine-mandate'] is registered and callable.
9. No endorsement language in the JS renderer.
10. AAC rendering unchanged.

Source fixtures (byte-verbatim):
  tests/fixtures/mm/demo.aep.json             (tyche-institute/machine-mandate@524e6a3 fixtures/demo.aep.json)
  tests/fixtures/mm/ear-A_good_fresh.json     (tyche-institute/machine-mandate@524e6a3 fixtures/ear-A_good_fresh.json)
  tests/fixtures/mm/ear-B_outcome_swapped.json (tyche-institute/machine-mandate@524e6a3 fixtures/ear-B_outcome_swapped.json)
  tests/fixtures/mm/run-credential-mint-record.json (tyche-institute/machine-mandate@524e6a3 interop/run-credential-mint-record.json)
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from hosted_profiles import aac as _aac
from hosted_profiles import machine_mandate as mm
from scitt_cose.hosted import CAPSULE_JS

# ---------------------------------------------------------------------------
# Fixture loading — byte-verbatim from pinned commit
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "mm"

# Raw-file SHA-256 values from tyche-institute/machine-mandate@524e6a3
_PINNED_RAW_SHA256 = {
    "demo.aep.json":                 "2ed1661abb839010b23617b19ee01c5a3549e2d2ca71a4fd37c01f0c2080155d",
    "ear-A_good_fresh.json":         "eaf3d03efd9f8896e8ffb4087c1f9ba384229afb0fc09e41ee2afcfb67100cfa",
    "ear-B_outcome_swapped.json":    "030ec18513962ae2ebbd02ac657266484abbbc070244fc178528f78ea041f650",
    "run-credential-mint-record.json": "82e93433582a2992524499d66b10eec7a9e340a69e5cd91c73cfb3a5fd450935",
}

# Canonical-JSON SHA-256 (used by Python and JS detection)
_PINNED_CANONICAL_SHA256 = {
    "demo.aep.json":                 "63bc7577d7929da79db0d6b045dd1cbdd2e9fb0a708618e3a5093869b8c2bdce",
    "ear-A_good_fresh.json":         "8cd9e0588b83416891ff1c4480767daeeaa2d82324dc01bda4114f6c2e98c2b3",
    "ear-B_outcome_swapped.json":    "4ac69f7b8524a7084be503196d3b0a3aaedac99b42422ae6fe5be198ffb3b2a2",
    "run-credential-mint-record.json": "be779f307e5357ccce504dd0bf920ec1f39b8f4652726eb912ee99e30c195de1",
}


def _load_fixture(name: str) -> dict:
    path = _FIXTURES_DIR / name
    with open(path, "rb") as f:
        raw = f.read()
    return json.loads(raw)


def _canonical_digest(data: dict) -> str:
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(blob).hexdigest()


DEMO_AEP = _load_fixture("demo.aep.json")
EAR_A_GOOD_FRESH = _load_fixture("ear-A_good_fresh.json")
EAR_B_OUTCOME_SWAPPED = _load_fixture("ear-B_outcome_swapped.json")
MINT_RECORD = _load_fixture("run-credential-mint-record.json")


# ---------------------------------------------------------------------------
# Acceptance 7 (fixture honesty) — must come before detection tests
# ---------------------------------------------------------------------------

def test_fixture_raw_sha256_demo_aep():
    raw = (_FIXTURES_DIR / "demo.aep.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _PINNED_RAW_SHA256["demo.aep.json"]


def test_fixture_raw_sha256_ear_a():
    raw = (_FIXTURES_DIR / "ear-A_good_fresh.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _PINNED_RAW_SHA256["ear-A_good_fresh.json"]


def test_fixture_raw_sha256_ear_b():
    raw = (_FIXTURES_DIR / "ear-B_outcome_swapped.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _PINNED_RAW_SHA256["ear-B_outcome_swapped.json"]


def test_fixture_raw_sha256_mint_record():
    raw = (_FIXTURES_DIR / "run-credential-mint-record.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _PINNED_RAW_SHA256["run-credential-mint-record.json"]


def test_fixture_canonical_digests_match_detection_set():
    """Canonical digests of AEP/EAR fixtures match _MM_PINNED_CANONICAL_DIGESTS."""
    for name in ("demo.aep.json", "ear-A_good_fresh.json", "ear-B_outcome_swapped.json"):
        data = _load_fixture(name)
        got = _canonical_digest(data)
        assert got == _PINNED_CANONICAL_SHA256[name], f"{name}: canonical digest mismatch"
        assert got in mm._MM_PINNED_CANONICAL_DIGESTS, f"{name}: not in detection set"


def test_mint_record_canonical_digest():
    """Mint record canonical digest is stable (sanity check; not in pinned-AEP/EAR set)."""
    got = _canonical_digest(MINT_RECORD)
    assert got == _PINNED_CANONICAL_SHA256["run-credential-mint-record.json"]
    # Mint record detected via credential_claims.vct, NOT digest — not in AEP/EAR set
    assert got not in mm._MM_PINNED_CANONICAL_DIGESTS


# ---------------------------------------------------------------------------
# Acceptance 1: Detection — positive cases
# ---------------------------------------------------------------------------

def test_aep_detection():
    assert mm.is_machine_mandate(DEMO_AEP)
    assert _aac.detect_profile(DEMO_AEP) == "machine-mandate"


def test_ear_a_detection():
    assert mm.is_machine_mandate(EAR_A_GOOD_FRESH)
    assert _aac.detect_profile(EAR_A_GOOD_FRESH) == "machine-mandate"


def test_ear_b_detection():
    assert mm.is_machine_mandate(EAR_B_OUTCOME_SWAPPED)
    assert _aac.detect_profile(EAR_B_OUTCOME_SWAPPED) == "machine-mandate"


def test_mint_record_detection():
    assert mm.is_machine_mandate(MINT_RECORD)
    assert _aac.detect_profile(MINT_RECORD) == "machine-mandate"


def test_vct_run_credential_detection():
    data = {"vct": mm.MM_VCT, "jti": "test-001", "scope": {}}
    assert mm.is_machine_mandate(data)
    assert _aac.detect_profile(data) == "machine-mandate"


# ---------------------------------------------------------------------------
# Acceptance 6: Negative (greedy-claim reproductions) — MUST render OPAQUE
# ---------------------------------------------------------------------------

def test_negative_generic_action_hash():
    """Generic sha256: action_hash must NOT be claimed as MachineMandate."""
    generic = {"action_hash": "sha256:deadbeef" + "0" * 56, "some_field": "value"}
    assert not mm.is_machine_mandate(generic)
    assert _aac.detect_profile(generic) == "unknown"


def test_negative_generic_aep_profile():
    """Generic eatf.eu/aep eat_profile must NOT be claimed as MachineMandate."""
    generic = {
        "eat_profile": "https://eatf.eu/aep/v2",
        "iss": "some-other-system",
        "action_id": "do-something",
    }
    assert not mm.is_machine_mandate(generic)
    assert _aac.detect_profile(generic) == "unknown"


def test_negative_generic_veraison_ear():
    """Generic Veraison EAR eat_profile must NOT be claimed as MachineMandate."""
    generic = {
        "eat_profile": "tag:github.com,2023:veraison/ear",
        "iat": 1700000000,
        "submods": {"SOME_DEVICE": {"ear.status": "affirming"}},
    }
    assert not mm.is_machine_mandate(generic)
    assert _aac.detect_profile(generic) == "unknown"


def test_negative_modified_aep_nonce():
    """AEP with changed nonce is not detected (fixture-scoped by digest)."""
    mutated = dict(DEMO_AEP)
    mutated["nonce"] = "different_nonce"
    assert not mm.is_machine_mandate(mutated)
    assert _aac.detect_profile(mutated) == "unknown"


def test_negative_modified_ear_nonce():
    """EAR with changed eat_nonce is not detected."""
    mutated = dict(EAR_A_GOOD_FRESH)
    mutated["eat_nonce"] = "different_nonce="
    assert not mm.is_machine_mandate(mutated)
    assert _aac.detect_profile(mutated) == "unknown"


# ---------------------------------------------------------------------------
# Acceptance 5: Client-side JS detectProfile via Node subprocess
# ---------------------------------------------------------------------------

def _run_detect_js(json_obj: dict) -> str:
    """Run detectProfile JS function against json_obj via Node.js. Returns the profile string."""
    # Extract _mmIsPinnedAepOrEar + detectProfile from CAPSULE_JS
    js_src = CAPSULE_JS
    # Find _mmIsPinnedAepOrEar start
    helper_start = js_src.find("function _mmIsPinnedAepOrEar(")
    detect_start = js_src.find("function detectProfile(")
    # Find end of detectProfile: next line starting with 'function ' or '/* '
    detect_end_candidates = [
        js_src.find("\nfunction isH64(", detect_start),
        js_src.find("\n/* ", detect_start),
        js_src.find("\nvar ", detect_start),
    ]
    detect_end = min(c for c in detect_end_candidates if c > detect_start)

    functions_js = js_src[helper_start:detect_end].strip()
    harness = (
        functions_js
        + "\nvar result = detectProfile("
        + json.dumps(json_obj)
        + ");\nprocess.stdout.write(result);\n"
    )
    result = subprocess.check_output(
        [sys.executable, "-c",
         f"import subprocess,sys; r=subprocess.check_output(['node','-e',"
         f"{repr(harness)}]); print(r.decode().strip())"],
        timeout=10,
    )
    return result.decode().strip()


def _node_available() -> bool:
    try:
        subprocess.check_output(["node", "--version"], timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_NODE = _node_available()


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_aep_pinned():
    assert _run_detect_js(DEMO_AEP) == "machine-mandate"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_ear_a_pinned():
    assert _run_detect_js(EAR_A_GOOD_FRESH) == "machine-mandate"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_ear_b_pinned():
    assert _run_detect_js(EAR_B_OUTCOME_SWAPPED) == "machine-mandate"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_mint_record():
    assert _run_detect_js(MINT_RECORD) == "machine-mandate"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_negative_generic_action_hash():
    """JS: generic sha256: action_hash → unknown (greedy-claim reproduction 1)."""
    generic = {"action_hash": "sha256:deadbeef" + "0" * 56, "some_field": "value"}
    assert _run_detect_js(generic) == "unknown"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_negative_generic_aep_profile():
    """JS: generic eatf.eu/aep eat_profile → unknown (greedy-claim reproduction 2)."""
    generic = {"eat_profile": "https://eatf.eu/aep/v2", "iss": "other-system", "action_id": "do-x"}
    assert _run_detect_js(generic) == "unknown"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_negative_generic_ear():
    """JS: generic Veraison EAR → unknown (greedy-claim reproduction 3)."""
    generic = {
        "eat_profile": "tag:github.com,2023:veraison/ear",
        "iat": 1700000000,
        "submods": {"DEV": {"ear.status": "affirming"}},
    }
    assert _run_detect_js(generic) == "unknown"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_aac_capsule():
    """JS: AAC capsule_id → aac (unaffected by MM changes)."""
    assert _run_detect_js({"capsule_id": "a" * 64, "action_type": "decide"}) == "aac"


@pytest.mark.skipif(not _NODE, reason="node not available")
def test_js_detect_unknown_json():
    """JS: unknown JSON → unknown."""
    assert _run_detect_js({"completely": "random", "data": 42}) == "unknown"


# ---------------------------------------------------------------------------
# Acceptance 2: AEP fixture renders first-class
# ---------------------------------------------------------------------------

def test_aep_parse_fields():
    result = mm.parse_machine_mandate(DEMO_AEP)
    assert result.profile_label == "MachineMandate AEP"
    labels = [g.label for g in result.field_groups]
    assert "Token identity" in labels
    assert "Action" in labels
    assert "Binding" in labels
    tok = next(g for g in result.field_groups if g.label == "Token identity")
    tok_dict = dict(tok.fields)
    assert tok_dict["eat_profile"] == "https://eatf.eu/aep/v1"
    assert tok_dict["iss"] == "aep-demo/veraison-presentation"
    assert tok_dict["sub"] == "policy-compliance-reviewer"
    act = next(g for g in result.field_groups if g.label == "Action")
    act_dict = dict(act.fields)
    assert act_dict["action_id"] == "review-clause-4.3-gdpr-art22"
    assert act_dict["status"] == "ok"
    bind = next(g for g in result.field_groups if g.label == "Binding")
    bind_dict = dict(bind.fields)
    assert bind_dict["receipt_hash"] == "d37b2efe9529c720ebe0ed60831aa9f6fac9f7167335c082040dd60d2b3067d8"


def test_aep_graph_view():
    view = mm.parse_as_graph_view(DEMO_AEP)
    assert view.profile == "machine-mandate"
    assert len(view.nodes) == 1
    node = view.nodes[0]
    assert node.node_type == "machine-mandate"
    assert node.is_known_type is True
    assert node.is_withheld is False
    assert node.revealed_payload.profile_label == "MachineMandate AEP"


def test_aep_profile_parser_entry():
    parser = _aac.PROFILE_PARSERS["machine-mandate"]
    assert parser is not None
    view = parser(DEMO_AEP)
    assert view.profile == "machine-mandate"
    assert not view.parse_error


# ---------------------------------------------------------------------------
# Acceptance 3: EAR fixtures render first-class
# ---------------------------------------------------------------------------

def test_ear_a_parse_fields():
    result = mm.parse_machine_mandate(EAR_A_GOOD_FRESH)
    assert result.profile_label == "MachineMandate EAR (Veraison)"
    labels = [g.label for g in result.field_groups]
    assert "EAR header" in labels
    assert any("Submodule" in lbl for lbl in labels)
    submod = next(g for g in result.field_groups if "Submodule" in g.label)
    submod_dict = dict(submod.fields)
    assert submod_dict["ear.status"] == "affirming"
    assert submod_dict["ear.appraisal-policy-id"] == "policy:TPM_ENACTTRUST"
    assert isinstance(submod_dict["ear.trustworthiness-vector"], dict)
    assert submod_dict["ear.trustworthiness-vector"]["executables"] == 2


def test_ear_b_contraindicated():
    result = mm.parse_machine_mandate(EAR_B_OUTCOME_SWAPPED)
    submod = next(g for g in result.field_groups if "Submodule" in g.label)
    submod_dict = dict(submod.fields)
    assert submod_dict["ear.status"] == "contraindicated"
    assert submod_dict["ear.trustworthiness-vector"]["executables"] == 33


# ---------------------------------------------------------------------------
# Acceptance 4: Mint record renders first-class (real file, all fields)
# ---------------------------------------------------------------------------

def test_mint_record_parse():
    result = mm.parse_machine_mandate(MINT_RECORD)
    assert result.profile_label == "MachineMandate Mint Record"
    labels = [g.label for g in result.field_groups]
    assert "Record identity" in labels
    assert "Credential claims" in labels
    assert "Scope" in labels
    assert "Preimage commitment" in labels
    assert "Self-check" in labels
    gate_labels = [lbl for lbl in labels if lbl.startswith("Gate case")]
    assert len(gate_labels) == 2
    cred = next(g for g in result.field_groups if g.label == "Credential claims")
    cred_dict = dict(cred.fields)
    assert cred_dict["vct"] == mm.MM_VCT
    assert cred_dict["jti"] == "mm-vienna-interop-2026-001"
    assert cred_dict["sub_agent_id"] == "agent:vienna-interop:001"
    assert cred_dict["action_hash"] == "sha256:a89fbd2bd6f95cdb1ec27b6c7253770ff2a22220937cf065f6e45ef67b37e299"
    scope = next(g for g in result.field_groups if g.label == "Scope")
    scope_dict = dict(scope.fields)
    assert scope_dict["allowed_actions"] == ["pay-invoice/acme-corp"]
    assert scope_dict["max_spend"] == 50000
    pre = next(g for g in result.field_groups if g.label == "Preimage commitment")
    pre_dict = dict(pre.fields)
    assert pre_dict["digest"] == "5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2"
    pos = next(g for g in result.field_groups if g.label == "Gate case: positive")
    assert dict(pos.fields)["verdict"] == "ACCEPT"
    ol = next(g for g in result.field_groups if g.label == "Gate case: mandate-over-limit")
    assert dict(ol.fields)["verdict"] == "DENY"
    assert dict(ol.fields)["L4_in_scope"] is False


# ---------------------------------------------------------------------------
# Acceptance 8 & 9: CAPSULE_JS renderer and endorsement boundary
# ---------------------------------------------------------------------------

def test_capsule_js_has_machine_mandate_renderer():
    assert "renderMachineMandate" in CAPSULE_JS
    assert "detectProfile" in CAPSULE_JS
    assert "PROFILE_RENDERERS" in CAPSULE_JS
    assert "_mmIsPinnedAepOrEar" in CAPSULE_JS
    assert "eat_profile" in CAPSULE_JS
    assert "ear.status" in CAPSULE_JS
    assert "credential_claims" in CAPSULE_JS


def test_capsule_js_detect_uses_vct_not_generic_shapes():
    """detectProfile must NOT use generic eatf.eu/aep or action_hash indexOf patterns."""
    detect_start = CAPSULE_JS.find("function detectProfile(")
    detect_end = CAPSULE_JS.find("\nfunction isH64(", detect_start)
    detect_fn = CAPSULE_JS[detect_start:detect_end]
    # These greedy patterns must not appear in detectProfile
    assert 'indexOf("eatf.eu/aep")' not in detect_fn
    assert 'indexOf("veraison/ear")' not in detect_fn
    assert 'indexOf("sha256:")' not in detect_fn
    # The owner-controlled VCT URI must be there
    assert "https://vocab.tyche.institute/vct/machine-mandate" in detect_fn
    # The mint record check must be there
    assert "credential_claims" in detect_fn


def test_capsule_js_no_endorsement_language():
    js_lower = CAPSULE_JS.lower()
    assert "not an endorsement" in js_lower or "not an endorse" in js_lower
    assert "endorsed" not in js_lower
    assert "production ready" not in js_lower


def test_machine_mandate_source_pinned():
    assert mm.parse_machine_mandate(DEMO_AEP).source_commit == "524e6a3129b7f1ab850dd9471967458d3cb6f4cd"
    assert "524e6a3" in CAPSULE_JS


# ---------------------------------------------------------------------------
# Acceptance 10: AAC rendering unchanged
# ---------------------------------------------------------------------------

def test_aac_profile_still_detected():
    aac_single = {"capsule_id": "a" * 64, "action_type": "decide", "disposition": {}}
    assert _aac.detect_profile(aac_single) == "aac"
    bilateral = {"buyer_capsule": {}, "seller_capsule": {}}
    assert _aac.detect_profile(bilateral) == "aac"


def test_aac_parser_still_works():
    aac_data = {
        "capsule_id": "b" * 64,
        "action_type": "decide",
        "operator": "test-org",
        "model_attestation": {"compute_attestation": {"subject_digest": "c" * 64}},
        "disposition": {"decision": "accept"},
    }
    view = _aac.PROFILE_PARSERS["aac"](aac_data)
    assert view.profile == "aac"
    assert not view.parse_error
    assert any(n.node_type == "capsule" for n in view.nodes)


# ---------------------------------------------------------------------------
# Acceptance 8: PROFILE_PARSERS registration
# ---------------------------------------------------------------------------

def test_profile_parsers_has_both_entries():
    assert "aac" in _aac.PROFILE_PARSERS
    assert "machine-mandate" in _aac.PROFILE_PARSERS
    assert _aac.PROFILE_PARSERS["machine-mandate"] is not None


def test_unknown_profile_still_opaque():
    unknown = {"completely": "random", "data": 42, "no_mm_fields": True}
    assert not mm.is_machine_mandate(unknown)
    assert _aac.detect_profile(unknown) == "unknown"
    assert "OPAQUE" in CAPSULE_JS
