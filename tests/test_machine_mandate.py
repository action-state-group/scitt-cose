# SPDX-License-Identifier: Apache-2.0
"""Tests for the MachineMandate profile parser and renderer on the P1 verification surface.

Acceptance cases:
1. MachineMandate AEP fixture renders first-class (profile_label, field groups).
2. MachineMandate EAR fixture renders first-class (ear.status, trustworthiness-vector).
3. MachineMandate run-credential / mint-record renders first-class (vct, action_hash, scope, gates).
4. Cryptographic verification path is identical — detect_profile routes to machine-mandate.
5. An unrelated unknown JSON still renders verified-but-opaque (profile=unknown).
6. No changes to AAC rendering (aac profile still detected and parsed correctly).
7. PROFILE_PARSERS['machine-mandate'] is registered and callable.
8. CAPSULE_JS carries renderMachineMandate renderer and detectProfile branch.
9. No endorsement language appears adjacent to MachineMandate in the JS renderer.

Source fixtures from tyche-institute/machine-mandate@524e6a3:
  fixtures/demo.aep.json
  fixtures/ear-A_good_fresh.json
  interop/run-credential-mint-record.json
"""
from __future__ import annotations

from scitt_cose import aac as _aac
from scitt_cose import machine_mandate as mm
from scitt_cose.hosted import CAPSULE_JS

# ---------------------------------------------------------------------------
# Fixtures — verbatim from tyche-institute/machine-mandate@524e6a3
# ---------------------------------------------------------------------------

DEMO_AEP = {
    "_comment": "DEMO AEP for Veraison community presentation 2026-06-24. Neutral domain: policy compliance review.",
    "eat_profile": "https://eatf.eu/aep/v1",
    "iss": "aep-demo/veraison-presentation",
    "sub": "policy-compliance-reviewer",
    "iat": 1782878400,
    "iat_iso": "2026-06-24T14:00:00Z",
    "nonce": "a9f3c21e88b04d17",
    "action_id": "review-clause-4.3-gdpr-art22",
    "swname": "compliance-assistant/demo-model-v1",
    "oemid": "demo-deployment",
    "status": "ok",
    "receipt_hash": "d37b2efe9529c720ebe0ed60831aa9f6fac9f7167335c082040dd60d2b3067d8",
    "_output_binding_note": "<<ccr:7071daf94353,string,320B>>",
}

EAR_A_GOOD_FRESH = {
    "ear.verifier-id": {"build": "N/A", "developer": "Veraison Project"},
    "eat_nonce": "jcw5yPcdEW_JM_QrRekL18i5FFjBFr2o-_txjW_AGO0=",
    "eat_profile": "tag:github.com,2023:veraison/ear",
    "iat": 1782598790,
    "submods": {
        "TPM_ENACTTRUST": {
            "ear.appraisal-policy-id": "policy:TPM_ENACTTRUST",
            "ear.status": "affirming",
            "ear.trustworthiness-vector": {
                "configuration": 0, "executables": 2, "file-system": 0,
                "hardware": 0, "instance-identity": 0, "runtime-opaque": 0,
                "sourced-data": 0, "storage-opaque": 0,
            },
            "ear.veraison.annotated-evidence": {
                "firmware-version": 2312897626142815700,
                "hash-algorithm": 11,
                "node-id": "345ccd98-a30b-4baf-9aa9-9b0861d2c042",
                "pcr-digest": "er5PQ51V3LpX2I6D3li4pZqG1CiGdQqAUJpeqzMWIiE=",
                "pcr-selection": [1, 2, 3, 4],
            },
        }
    },
}

EAR_B_OUTCOME_SWAPPED = {
    "ear.verifier-id": {"build": "N/A", "developer": "Veraison Project"},
    "eat_nonce": "aiWKHMeQ4uPUMkXwzlQjR5k6syZwgsWpwZEBQcPTsgo=",
    "eat_profile": "tag:github.com,2023:veraison/ear",
    "iat": 1782598790,
    "submods": {
        "TPM_ENACTTRUST": {
            "ear.appraisal-policy-id": "policy:TPM_ENACTTRUST",
            "ear.status": "contraindicated",
            "ear.trustworthiness-vector": {
                "configuration": 0, "executables": 33, "file-system": 0,
                "hardware": 0, "instance-identity": 0, "runtime-opaque": 0,
                "sourced-data": 0, "storage-opaque": 0,
            },
            "ear.veraison.annotated-evidence": {
                "firmware-version": 2312897626142815700,
                "hash-algorithm": 11,
                "node-id": "345ccd98-a30b-4baf-9aa9-9b0861d2c042",
                "pcr-digest": "cQhf0UzaSuKcvrRBmQVMqs0O/WLQAvvIC2+FXupbM10=",
                "pcr-selection": [1, 2, 3, 4],
            },
        }
    },
}

MINT_RECORD_CREDENTIAL_CLAIMS = {
    "action_hash": "sha256:a89fbd2bd6f95cdb1ec27b6c7253770ff2a22220937cf065f6e45ef67b37e299",
    "exp_utc": "2026-07-24T23:59:59Z",
    "iat_utc": "2026-07-18T13:37:15Z",
    "issuer_jwk_thumbprint": "jkt:VSvnWZ5tSnuQthtG45KsbFxO0rfkZzzJ5iy5PJGatsc",
    "jti": "mm-vienna-interop-2026-001",
    "scope": {
        "action_commitments": ["sha256:a89fbd2bd6f95cdb1ec27b6c7253770ff2a22220937cf065f6e45ef67b37e299"],
        "allowed_actions": ["pay-invoice/acme-corp"],
        "max_spend": 50000,
    },
    "sub_agent_id": "agent:vienna-interop:001",
    "vct": "https://vocab.tyche.institute/vct/machine-mandate",
}

MINT_RECORD = {
    "artifact": "MachineMandate run credential — IETF 126 deliverable B",
    "boundary": "Synthetic sandbox credential for a pre-registered composition run. No live payment, no real payment data.",
    "credential_claims": MINT_RECORD_CREDENTIAL_CLAIMS,
    "credential_preimage": {
        "digest": "5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2",
        "digest_alg": "SHA-256",
        "invariant_across_presentations": True,
        "preimage_length_bytes": 1190,
        "rule": "option (a): the exact issuer-signed JWT component bytes of the SD-JWT",
    },
    "minted_at_utc": "2026-07-18T13:37:15Z",
    "self_check": {
        "all_verdicts_as_expected": True,
        "cases": [
            {
                "L1_crypto": True, "L2_attested": True, "L3_endorser_role": True, "L4_in_scope": True,
                "case_id": "positive", "expected_verdict": "ACCEPT", "match": True,
                "gates": {"action_in_allowed_set": True, "amount_within_limit": True,
                          "hash_matches_bound_mandate": True, "instance_pre_authorised": True},
                "preimage_digest_from_presentation": "5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2",
                "preimage_length_from_presentation": 1190,
                "reasons": [], "requested_amount": 25000, "verdict": "ACCEPT",
            },
            {
                "L1_crypto": True, "L2_attested": True, "L3_endorser_role": True, "L4_in_scope": False,
                "case_id": "mandate-over-limit", "expected_verdict": "DENY", "match": True,
                "gates": {"action_in_allowed_set": True, "amount_within_limit": False,
                          "hash_matches_bound_mandate": True, "instance_pre_authorised": True},
                "preimage_digest_from_presentation": "5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2",
                "preimage_length_from_presentation": 1190,
                "reasons": ["L4: amount 75000 exceeds mandate spend-limit 50000"],
                "requested_amount": 75000, "verdict": "DENY",
            },
        ],
    },
    "status": "FROZEN PRE-EXECUTION INPUT — NOT A RESULT",
}


# ---------------------------------------------------------------------------
# Acceptance 1: AEP fixture renders first-class
# ---------------------------------------------------------------------------

def test_aep_detection():
    """AEP fixture is detected as machine-mandate, not aac or unknown."""
    assert mm.is_machine_mandate(DEMO_AEP)
    assert _aac.detect_profile(DEMO_AEP) == "machine-mandate"


def test_aep_parse_fields():
    """AEP parser extracts MachineMandate vocabulary fields correctly."""
    result = mm.parse_machine_mandate(DEMO_AEP)
    assert result.profile_label == "MachineMandate AEP"
    labels = [g.label for g in result.field_groups]
    assert "Token identity" in labels
    assert "Action" in labels
    assert "Binding" in labels
    # Token identity fields use MachineMandate vocabulary (not AAC vocabulary)
    tok = next(g for g in result.field_groups if g.label == "Token identity")
    tok_dict = dict(tok.fields)
    assert tok_dict["eat_profile"] == "https://eatf.eu/aep/v1"
    assert tok_dict["iss"] == "aep-demo/veraison-presentation"
    assert tok_dict["sub"] == "policy-compliance-reviewer"
    # Action fields
    act = next(g for g in result.field_groups if g.label == "Action")
    act_dict = dict(act.fields)
    assert act_dict["action_id"] == "review-clause-4.3-gdpr-art22"
    assert act_dict["status"] == "ok"
    # Binding fields
    bind = next(g for g in result.field_groups if g.label == "Binding")
    bind_dict = dict(bind.fields)
    assert bind_dict["receipt_hash"] == "d37b2efe9529c720ebe0ed60831aa9f6fac9f7167335c082040dd60d2b3067d8"


def test_aep_graph_view():
    """AEP parse_as_graph_view returns GraphView with profile=machine-mandate."""
    view = mm.parse_as_graph_view(DEMO_AEP)
    assert view.profile == "machine-mandate"
    assert len(view.nodes) == 1
    node = view.nodes[0]
    assert node.node_type == "machine-mandate"
    assert node.is_known_type is True
    assert node.is_withheld is False
    assert node.revealed_payload is not None
    assert node.revealed_payload.profile_label == "MachineMandate AEP"


def test_aep_profile_parser_entry():
    """PROFILE_PARSERS['machine-mandate'] routes AEP to MachineMandate renderer."""
    parser = _aac.PROFILE_PARSERS["machine-mandate"]
    assert parser is not None, "machine-mandate slot must be populated"
    view = parser(DEMO_AEP)
    assert view.profile == "machine-mandate"
    assert not view.parse_error


# ---------------------------------------------------------------------------
# Acceptance 2: EAR fixtures render first-class
# ---------------------------------------------------------------------------

def test_ear_a_detection():
    """EAR-A (affirming) fixture is detected as machine-mandate."""
    assert mm.is_machine_mandate(EAR_A_GOOD_FRESH)
    assert _aac.detect_profile(EAR_A_GOOD_FRESH) == "machine-mandate"


def test_ear_a_parse_fields():
    """EAR-A parser extracts ear.status and trustworthiness-vector in MM vocabulary."""
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
    """EAR-B (contraindicated) fixture renders ear.status=contraindicated."""
    result = mm.parse_machine_mandate(EAR_B_OUTCOME_SWAPPED)
    submod = next(g for g in result.field_groups if "Submodule" in g.label)
    submod_dict = dict(submod.fields)
    assert submod_dict["ear.status"] == "contraindicated"
    assert submod_dict["ear.trustworthiness-vector"]["executables"] == 33


# ---------------------------------------------------------------------------
# Acceptance 3: Run credential / mint-record renders first-class
# ---------------------------------------------------------------------------

def test_vct_detection():
    """Run credential (vct field) is detected as machine-mandate."""
    data = {"vct": mm.MM_VCT, "action_hash": "sha256:abc", "scope": {}}
    assert mm.is_machine_mandate(data)
    assert _aac.detect_profile(data) == "machine-mandate"


def test_mint_record_detection():
    """Mint record (credential_claims + credential_preimage) is detected as machine-mandate."""
    assert mm.is_machine_mandate(MINT_RECORD)
    assert _aac.detect_profile(MINT_RECORD) == "machine-mandate"


def test_mint_record_parse():
    """Mint record parser renders vct, action_hash, scope, gate verdicts correctly."""
    result = mm.parse_machine_mandate(MINT_RECORD)
    assert result.profile_label == "MachineMandate Mint Record"
    labels = [g.label for g in result.field_groups]
    assert "Record identity" in labels
    assert "Credential claims" in labels
    assert "Scope" in labels
    assert "Preimage commitment" in labels
    assert "Self-check" in labels
    # Gate cases
    gate_labels = [lbl for lbl in labels if lbl.startswith("Gate case")]
    assert len(gate_labels) == 2
    # Credential claims
    cred = next(g for g in result.field_groups if g.label == "Credential claims")
    cred_dict = dict(cred.fields)
    assert cred_dict["vct"] == mm.MM_VCT
    assert cred_dict["jti"] == "mm-vienna-interop-2026-001"
    assert cred_dict["sub_agent_id"] == "agent:vienna-interop:001"
    assert cred_dict["action_hash"] == "sha256:a89fbd2bd6f95cdb1ec27b6c7253770ff2a22220937cf065f6e45ef67b37e299"
    # Scope
    scope = next(g for g in result.field_groups if g.label == "Scope")
    scope_dict = dict(scope.fields)
    assert scope_dict["allowed_actions"] == ["pay-invoice/acme-corp"]
    assert scope_dict["max_spend"] == 50000
    # Preimage commitment
    pre = next(g for g in result.field_groups if g.label == "Preimage commitment")
    pre_dict = dict(pre.fields)
    assert pre_dict["digest"] == "5df4d32df57650f27b6a65df041b708de80d69c0ca82a1044334f5e2edef5ce2"
    # Gate case: positive
    pos = next(g for g in result.field_groups if g.label == "Gate case: positive")
    pos_dict = dict(pos.fields)
    assert pos_dict["verdict"] == "ACCEPT"
    assert pos_dict["L1_crypto"] is True
    assert pos_dict["L4_in_scope"] is True
    # Gate case: mandate-over-limit
    ol = next(g for g in result.field_groups if g.label == "Gate case: mandate-over-limit")
    ol_dict = dict(ol.fields)
    assert ol_dict["verdict"] == "DENY"
    assert ol_dict["L4_in_scope"] is False


def test_run_credential_claims_parse():
    """Direct run-credential claims dict (vct + action_hash + scope) renders correctly."""
    result = mm.parse_machine_mandate(MINT_RECORD_CREDENTIAL_CLAIMS)
    assert result.profile_label == "MachineMandate Run Credential"
    scope_g = next(g for g in result.field_groups if g.label == "Scope")
    scope_dict = dict(scope_g.fields)
    assert scope_dict["max_spend"] == 50000
    assert scope_dict["allowed_actions"] == ["pay-invoice/acme-corp"]


# ---------------------------------------------------------------------------
# Acceptance 4: Verification path is identical
# ---------------------------------------------------------------------------

def test_detect_profile_routes_to_machine_mandate():
    """detect_profile selects machine-mandate for all three MM payload shapes."""
    assert _aac.detect_profile(DEMO_AEP) == "machine-mandate"
    assert _aac.detect_profile(EAR_A_GOOD_FRESH) == "machine-mandate"
    assert _aac.detect_profile(MINT_RECORD) == "machine-mandate"
    assert _aac.detect_profile(MINT_RECORD_CREDENTIAL_CLAIMS) == "machine-mandate"


def test_profile_parsers_machine_mandate_callable():
    """PROFILE_PARSERS['machine-mandate'] is a callable returning GraphView."""
    parser = _aac.PROFILE_PARSERS.get("machine-mandate")
    assert callable(parser), "machine-mandate entry must be callable"
    view = parser(DEMO_AEP)
    assert view.profile == "machine-mandate"
    assert not view.parse_error


# ---------------------------------------------------------------------------
# Acceptance 5: Unknown type still renders verified-but-opaque
# ---------------------------------------------------------------------------

def test_unknown_profile_still_opaque():
    """Unrelated JSON that is not machine-mandate and not AAC stays 'unknown'."""
    unknown = {"completely": "random", "data": 42, "no_mm_fields": True}
    assert not mm.is_machine_mandate(unknown)
    assert _aac.detect_profile(unknown) == "unknown"
    # The aac module's GraphView machinery still treats it as opaque
    # (opaque rendering is handled by the JS CAPSULE_JS; no server-side parse)
    assert "OPAQUE" in CAPSULE_JS
    assert "Unknown type" in CAPSULE_JS


# ---------------------------------------------------------------------------
# Acceptance 6: AAC rendering is unchanged
# ---------------------------------------------------------------------------

def test_aac_profile_still_detected():
    """AAC capsule_id / buyer_capsule detection is unaffected by MachineMandate addition."""
    aac_single = {"capsule_id": "a" * 64, "action_type": "decide", "disposition": {}}
    assert _aac.detect_profile(aac_single) == "aac"
    bilateral = {"buyer_capsule": {}, "seller_capsule": {}}
    assert _aac.detect_profile(bilateral) == "aac"


def test_aac_parser_still_works():
    """parse_capsule via PROFILE_PARSERS['aac'] still returns aac-profile GraphView."""
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
# Acceptance 7: PROFILE_PARSERS registration
# ---------------------------------------------------------------------------

def test_profile_parsers_has_both_entries():
    """PROFILE_PARSERS has both 'aac' and 'machine-mandate'."""
    assert "aac" in _aac.PROFILE_PARSERS
    assert "machine-mandate" in _aac.PROFILE_PARSERS
    assert _aac.PROFILE_PARSERS["machine-mandate"] is not None


# ---------------------------------------------------------------------------
# Acceptance 8 & 9: CAPSULE_JS renderer and endorsement boundary
# ---------------------------------------------------------------------------

def test_capsule_js_has_machine_mandate_renderer():
    """CAPSULE_JS includes renderMachineMandate and detectProfile branch."""
    assert "renderMachineMandate" in CAPSULE_JS
    assert "machine-mandate" in CAPSULE_JS
    assert "detectProfile" in CAPSULE_JS
    assert "PROFILE_RENDERERS" in CAPSULE_JS
    # Verify MachineMandate vocabulary appears in JS (not AAC vocabulary)
    assert "eat_profile" in CAPSULE_JS
    assert "ear.status" in CAPSULE_JS
    assert "action_hash" in CAPSULE_JS
    assert "vct" in CAPSULE_JS
    assert "sub_agent_id" in CAPSULE_JS


def test_capsule_js_no_endorsement_language():
    """The JS renderer contains no endorsement language adjacent to MachineMandate."""
    # Anton's condition: no endorsement language anywhere near the rendering
    js_lower = CAPSULE_JS.lower()
    # The renderer must contain the not-an-endorsement disclaimer
    assert "not an endorsement" in js_lower or "not an endorse" in js_lower
    # There must be no claims of endorsement, production readiness, or equivalence
    assert "endorsed" not in js_lower
    assert "production ready" not in js_lower
    assert "equivalent" not in js_lower


def test_machine_mandate_source_pinned():
    """MachineMandate module carries the pinned commit reference."""
    assert mm.parse_machine_mandate(DEMO_AEP).source_commit == "524e6a3129b7f1ab850dd9471967458d3cb6f4cd"
    assert "524e6a3" in CAPSULE_JS  # commit SHA in JS renderer too
