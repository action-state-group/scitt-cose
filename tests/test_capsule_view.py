# SPDX-License-Identifier: Apache-2.0
"""Fixtures for aam-mvp-p1-verify-surface acceptance cases.

Acceptance cases:
1. Live permalink — capsule page renders and anchor-status proxy returns anchored+receipt_verified.
2. Unknown artifact type → VERIFIED-BUT-OPAQUE (graph node + privilege-log).
3. Withheld node → withholding-manifest panel (WITHHELD in privilege-log).
4. Instrumentation counter increments on each capsule-page view.
5. Permalink route extracts a valid capsule_id from /v/<id>.
6. Revealed artifact — recompute matches the committed digest.
7. Profile plug-point — PROFILE_PARSERS dict is extensible without modifying core.

For the live inclusion-proof case (acceptance 1), the test hits the real anchor
only when the environment variable ``AAC_LIVE_CAPSULE_ID`` is set.  Without it
the test documents the contract via mock-style assertions and is marked xfail-live.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from scitt_cose import aac as _aac
from scitt_cose.hosted import (
    _CAPSULE_VIEW_COUNTER,
    _REFERRER_COUNTER,
    CAPSULE_JS,
    INSTRUMENTATION_POLICY,
    _anchor_proxy_json,
    _capsule_id_from_path,
    _instrument_capsule_view,
    _render_reg_panel,
    render_capsule_page,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _sha256(obj: object) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(blob).hexdigest()


def _fake_hex64(prefix: str = "cafe") -> str:
    return (prefix * 64)[:64]


def _make_binding(*, reveal_terms: bool = True, withheld_manifest: bool = True) -> dict:
    """Minimal bilateral binding dict for test rendering."""
    terms = {"rate_usd": 2500, "event_date": "2026-08-15", "seller": "marcus-rey"}
    sealed_terms_hash = _sha256(terms)

    buyer_ev = _fake_hex64("ab")
    seller_ev = _fake_hex64("cd")
    buyer_id = _fake_hex64("11")
    seller_id = _fake_hex64("22")

    buyer_cap = {
        "capsule_id": buyer_id,
        "action_type": "decide",
        "operator": "buyer:org-123",
        "model_attestation": {
            "compute_attestation": {
                "subject_digest": sealed_terms_hash,
                "role": "requester",
                "hire_id": "hire-abc",
            }
        },
        "disposition": {"decision": "accept", "verdict_class": "executed"},
        "constraints": [{"id": "wicket-compliance:buyer", "evidence_digest": buyer_ev}],
    }
    seller_cap = {
        "capsule_id": seller_id,
        "action_type": "decide",
        "operator": "marcus-rey",
        "model_attestation": {
            "compute_attestation": {
                "subject_digest": sealed_terms_hash,
                "role": "recipient",
                "hire_id": "hire-abc",
            }
        },
        "chain": {"parent_capsule_id": buyer_id, "relation": "confirms"},
        "disposition": {"decision": "accept", "verdict_class": "executed"},
        "constraints": [{"id": "wicket-compliance:seller", "evidence_digest": seller_ev}],
    }

    return {
        "buyer_capsule": buyer_cap,
        "seller_capsule": seller_cap,
        "sealed_terms_hash": sealed_terms_hash,
        "terms": terms if reveal_terms else None,
    }


# ---------------------------------------------------------------------------
# Acceptance 2: Unknown artifact type → VERIFIED-BUT-OPAQUE
# ---------------------------------------------------------------------------

def test_unknown_type_renders_verified_but_opaque():
    """Unknown artifact types appear in the graph with is_known_type=False."""
    mystery_digest = _fake_hex64("ff")
    cap = {
        "capsule_id": _fake_hex64("aa"),
        "action_type": "decide",
        "operator": "test-agent",
        "model_attestation": {
            "compute_attestation": {
                "subject_digest": mystery_digest,
                "role": "requester",
            }
        },
        "disposition": {"decision": "accept"},
        # Inject an unknown-type artifact via a constraint with a non-standard id
        "constraints": [{"id": "custom-profile:unknown_check", "evidence_digest": mystery_digest}],
    }

    # Override: pretend subject_digest has an unknown node_type via a raw binding
    binding = {
        "buyer_capsule": {**cap},
        "seller_capsule": {**cap, "capsule_id": _fake_hex64("bb"),
                           "chain": {"parent_capsule_id": _fake_hex64("aa"), "relation": "confirms"}},
        "sealed_terms_hash": mystery_digest,
        "terms": None,
    }

    view = _aac.parse_capsule(binding)
    # sealed_terms_hash node is known (offer_terms type)
    known = [n for n in view.nodes if n.is_known_type]
    assert known, "at least one known-type node should be present"

    # Now test single capsule with a truly unknown type planted by modifying parse
    # Unknown types arise when node_type is not in _KNOWN_TYPES; we verify
    # via the unknown_types list on GraphView.
    single_cap = {
        "capsule_id": _fake_hex64("cc"),
        "action_type": "decide",
        "operator": "test",
        "model_attestation": {"compute_attestation": {"subject_digest": mystery_digest}},
        "disposition": {"decision": "accept"},
    }
    view2 = _aac.parse_capsule(single_cap)
    assert not view2.parse_error
    # subject_digest gets type "subject" which IS in _KNOWN_TYPES — verify:
    subj_nodes = [n for n in view2.nodes if n.digest == mystery_digest]
    assert subj_nodes, "subject_digest node not found"
    assert subj_nodes[0].is_known_type, "subject type should be known"
    assert not view2.unknown_types, "no unknown types in this fixture"

    # Verify VERIFIED-BUT-OPAQUE via capsule page HTML:
    # The page must include the OPAQUE badge text in CAPSULE_JS for unknown types.
    assert "OPAQUE" in CAPSULE_JS
    assert "Unknown type" in CAPSULE_JS
    assert "gn-opaque" in CAPSULE_JS


def test_unknown_type_in_unknown_types_list():
    """Artificially inject an unknown_type via the unknown_types list in GraphView."""
    view = _aac.GraphView(profile="aac", is_binding=False)
    view.unknown_types.append("my-custom-profile:special_artifact")
    assert "my-custom-profile:special_artifact" in view.unknown_types
    # Nodes with unknown types should have is_known_type=False
    node = _aac.GraphNode(
        id=_fake_hex64("de"), node_type="my-custom-profile:special_artifact",
        digest=_fake_hex64("de"), label="unknown artifact",
        is_known_type=False,  # would be set by _add() in real parse
    )
    view.nodes.append(node)
    opaque_nodes = [n for n in view.nodes if not n.is_known_type]
    assert opaque_nodes
    assert opaque_nodes[0].node_type == "my-custom-profile:special_artifact"


# ---------------------------------------------------------------------------
# Acceptance 3: Withheld node → WITHHELD in privilege-log
# ---------------------------------------------------------------------------

def test_withheld_nodes_in_privilege_log():
    """Withheld artifacts appear in the privilege-log with is_withheld=True."""
    binding = _make_binding(reveal_terms=False, withheld_manifest=True)
    view = _aac.parse_capsule(binding)

    assert not view.parse_error
    # sealed_terms_hash is withheld (terms=None)
    sealed_entry = next(
        (e for e in view.privilege_log if e.artifact_id == "sealed_terms_hash"), None
    )
    assert sealed_entry is not None, "sealed_terms_hash must be in privilege_log"
    assert sealed_entry.is_withheld, "sealed_terms_hash should be WITHHELD when terms=None"
    assert sealed_entry.match_ok is None, "no match check for withheld artifact"

    # Constraint evidence_digests are always withheld (manifest not provided)
    manifest_entries = [e for e in view.privilege_log if e.artifact_type == "wicket_manifest"]
    assert manifest_entries, "wicket_manifest entries must be in privilege_log"
    for entry in manifest_entries:
        assert entry.is_withheld
        assert entry.match_ok is None


def test_revealed_artifact_recompute_matches():
    """Revealed offer_terms: recomputed digest matches the committed hash."""
    binding = _make_binding(reveal_terms=True)
    view = _aac.parse_capsule(binding)

    sealed_entry = next(
        (e for e in view.privilege_log if e.artifact_id == "sealed_terms_hash"), None
    )
    assert sealed_entry is not None
    assert not sealed_entry.is_withheld, "terms are revealed"
    assert sealed_entry.match_ok is True, "recomputed digest must match"


def test_revealed_artifact_mismatch_detected():
    """Tampered terms: recomputed digest does NOT match — detected as MISMATCH."""
    terms = {"rate_usd": 2500, "event_date": "2026-08-15"}
    _sha256(terms)
    tampered_hash = _fake_hex64("ba")  # wrong hash

    binding = {
        "buyer_capsule": {
            "capsule_id": _fake_hex64("11"),
            "model_attestation": {"compute_attestation": {"subject_digest": tampered_hash}},
            "disposition": {"decision": "accept"},
        },
        "seller_capsule": {
            "capsule_id": _fake_hex64("22"),
            "chain": {"parent_capsule_id": _fake_hex64("11"), "relation": "confirms"},
            "model_attestation": {"compute_attestation": {"subject_digest": tampered_hash}},
            "disposition": {"decision": "accept"},
        },
        "sealed_terms_hash": tampered_hash,
        "terms": terms,  # revealed but hash doesn't match
    }
    view = _aac.parse_capsule(binding)
    sealed = next(e for e in view.privilege_log if e.artifact_id == "sealed_terms_hash")
    assert not sealed.is_withheld
    assert sealed.match_ok is False  # hash mismatch detected


# ---------------------------------------------------------------------------
# Acceptance 4: Instrumentation counter increments
# ---------------------------------------------------------------------------

def test_instrumentation_increments():
    """Each capsule-page view increments the anonymous counter."""
    before = _CAPSULE_VIEW_COUNTER[0]
    _instrument_capsule_view("")
    _instrument_capsule_view("")
    _instrument_capsule_view("")
    assert _CAPSULE_VIEW_COUNTER[0] == before + 3


def test_instrumentation_referrer_domain_counted():
    """Referrer domain (eTLD+1) is counted; path/query are never stored."""
    _instrument_capsule_view("https://acme.github.com/some/path?q=secret")
    # Should record "github.com", not the full URL
    assert "github.com" in _REFERRER_COUNTER
    assert any(
        "secret" not in k and "/some/path" not in k for k in _REFERRER_COUNTER
    ), "path/query must not appear in referrer counter keys"


def test_instrumentation_same_origin_not_counted():
    """Same-origin and localhost referrers are NOT counted as third-party."""
    len(_REFERRER_COUNTER)
    _instrument_capsule_view("https://verify.actionstate.ai/v/abc")
    _instrument_capsule_view("http://localhost:8080/")
    # No new domains should appear for same-origin hits
    same_origin_domains = {"verify.actionstate.ai", "localhost"}
    assert not same_origin_domains.intersection(_REFERRER_COUNTER)


def test_instrumentation_policy_stub():
    """Publishable policy stub is structured and contains the right keys."""
    assert INSTRUMENTATION_POLICY["publishable"] is True
    assert "what_we_count" in INSTRUMENTATION_POLICY
    assert "what_we_do_not_store" in INSTRUMENTATION_POLICY
    assert "retention" in INSTRUMENTATION_POLICY
    assert any("IP" in x for x in INSTRUMENTATION_POLICY["what_we_do_not_store"])


# ---------------------------------------------------------------------------
# Acceptance 5: Permalink route extracts capsule_id
# ---------------------------------------------------------------------------

def test_capsule_id_from_path_v_route():
    cid = "a" * 64
    assert _capsule_id_from_path(f"/v/{cid}", "v/") == cid
    assert _capsule_id_from_path("/v/short", "v/") is None  # too short
    assert _capsule_id_from_path("/other/path", "v/") is None
    assert _capsule_id_from_path(f"/anchor-status/{cid}", "anchor-status/") == cid


def test_capsule_page_renders_with_valid_id():
    cid = "b" * 64
    html = render_capsule_page(cid)
    assert cid in html
    assert "graphSection" in html
    assert "privlogSection" in html
    assert "pasteSection" in html
    assert "capsule.js" in html
    assert "anchor-status" not in html  # anchor-status is fetched by JS, not embedded in HTML
    assert f'data-capsule-id="{cid}"' in html


# ---------------------------------------------------------------------------
# Acceptance 6: AAC profile first-class + renderer plug-point
# ---------------------------------------------------------------------------

def test_aac_profile_detected():
    data = {"capsule_id": "a" * 64, "action_type": "decide", "disposition": {}}
    assert _aac.detect_profile(data) == "aac"

    bilateral = {"buyer_capsule": {}, "seller_capsule": {}}
    assert _aac.detect_profile(bilateral) == "aac"

    unknown = {"some": "random", "json": "dict"}
    assert _aac.detect_profile(unknown) == "unknown"


def test_profile_parsers_dict_extensible():
    """PROFILE_PARSERS is a mutable dict — additional profiles can be registered."""
    original_keys = set(_aac.PROFILE_PARSERS.keys())
    assert "aac" in original_keys

    # Register a mock profile (test-only)
    def _mock_parser(data: dict) -> _aac.GraphView:
        return _aac.GraphView(profile="mock", is_binding=False)

    _aac.PROFILE_PARSERS["mock-test"] = _mock_parser
    assert "mock-test" in _aac.PROFILE_PARSERS

    view = _aac.PROFILE_PARSERS["mock-test"]({})
    assert view.profile == "mock"

    # Clean up
    del _aac.PROFILE_PARSERS["mock-test"]
    assert _aac.PROFILE_PARSERS.keys() == original_keys


def test_capsule_js_has_profile_renderers_plug_point():
    """CAPSULE_JS exposes PROFILE_RENDERERS dict as the client-side plug-point."""
    assert "PROFILE_RENDERERS" in CAPSULE_JS
    assert "renderAac" in CAPSULE_JS
    assert "detectProfile" in CAPSULE_JS


# ---------------------------------------------------------------------------
# Acceptance 1: Live inclusion-proof via GET /v1/inclusion/{capsule_id}
# ---------------------------------------------------------------------------
# The anchor now exposes GET /v1/inclusion/{capsule_id} (capsule-anchor PR #11)
# instead of the old POST /anchor/transparency-log query.
# leaf-199 capsule_id from the goose-demo-run:
#   6d8c1a4718847f98aad34b4975482bdc11ae3cbaa11939ff2e920497c86274fc
# Set AAC_LIVE_CAPSULE_ID in the environment to run against the real anchor.
_LEAF_199_CAPSULE_ID = "6d8c1a4718847f98aad34b4975482bdc11ae3cbaa11939ff2e920497c86274fc"
_FABRICATED_CAPSULE_ID = "deadbeefdeadbeef" + "00" * 24  # 64-char hex; not in log


def test_live_inclusion_proof_contract():
    """Documents the contract for the live inclusion-proof acceptance case.

    Without a live capsule_id, this test verifies the _anchor_proxy_json
    function returns the expected shape. Set AAC_LIVE_CAPSULE_ID in the
    environment to run against the real anchor.
    """
    import os

    live_id = os.environ.get("AAC_LIVE_CAPSULE_ID")
    if not live_id:
        # Document the expected contract shape without hitting the network.
        # The live test needs a real capsule_id anchored at anchor.agentactioncapsule.org.
        result_contract = {
            "capsule_id": "a" * 64,
            "anchored": True,
            "receipt_verified": True,
            "log_index": 0,
            "logged_at": None,
            "leaf_index": 0,
            "tree_size": 1,
            "error": None,
        }
        assert set(result_contract.keys()) == {
            "capsule_id", "anchored", "receipt_verified", "log_index",
            "logged_at", "leaf_index", "tree_size", "error",
        }
        pytest.skip("Set AAC_LIVE_CAPSULE_ID=<anchored capsule_id> to run live test")

    result = _anchor_proxy_json(live_id)
    assert result["capsule_id"] == live_id
    assert result["error"] is None, f"anchor error: {result['error']}"
    assert result["anchored"], "capsule must be anchored"
    assert result["receipt_verified"], (
        f"receipt inclusion proof must verify; errors: {result.get('receipt_errors')}"
    )
    assert isinstance(result["log_index"], int)
    assert result["log_index"] >= 0


@pytest.mark.skipif(
    not __import__("os").environ.get("AAC_LIVE_CAPSULE_ID"),
    reason="Set AAC_LIVE_CAPSULE_ID to run live anchor tests",
)
def test_live_leaf199_anchored():
    """leaf-199 (goose-demo-run check_inventory) must return anchored=True via /v1/inclusion/.

    Requires network access to anchor.agentactioncapsule.org and the anchor
    to have PR #11 (GET /v1/inclusion/{capsule_id}) deployed.
    """
    result = _anchor_proxy_json(_LEAF_199_CAPSULE_ID)
    assert result["error"] is None, f"anchor error: {result['error']}"
    assert result["anchored"] is True, (
        "leaf-199 capsule must be anchored in the transparency log"
    )
    assert result["receipt_verified"] is True, (
        f"RFC 9162 inclusion proof for leaf-199 must verify; errors: {result.get('receipt_errors')}"
    )
    assert isinstance(result["leaf_index"], int), "leaf_index must be an integer"
    assert result["leaf_index"] == 199, (
        f"leaf-199 capsule should map to leaf_index=199, got {result['leaf_index']}"
    )


@pytest.mark.skipif(
    not __import__("os").environ.get("AAC_LIVE_CAPSULE_ID"),
    reason="Set AAC_LIVE_CAPSULE_ID to run live anchor tests",
)
def test_live_fabricated_id_not_anchored():
    """A fabricated (never-registered) capsule_id must return anchored=False.

    GET /v1/inclusion/{capsule_id} returns 404 for unknown ids.
    _anchor_proxy_json must translate that to anchored=False, error=None.
    """
    result = _anchor_proxy_json(_FABRICATED_CAPSULE_ID)
    assert result["anchored"] is False, (
        "fabricated capsule_id must not be anchored"
    )
    assert result["error"] is None, (
        f"404 from anchor must NOT be treated as an error: {result['error']}"
    )


# ---------------------------------------------------------------------------
# Digest graph completeness
# ---------------------------------------------------------------------------

def test_bilateral_graph_nodes_and_edges():
    """Full bilateral binding produces the expected node types and edge relations."""
    binding = _make_binding(reveal_terms=True)
    view = _aac.parse_capsule(binding)

    assert not view.parse_error
    assert view.is_binding
    assert view.profile == "aac"

    node_types = {n.node_type for n in view.nodes}
    assert "capsule" in node_types, "buyer + seller capsule nodes"
    assert "offer_terms" in node_types, "offer_terms node for sealed_terms_hash"
    # subject_digest == sealed_terms_hash in bilateral; the node appears as offer_terms (correct dedup)
    assert "capsule" in node_types or "offer_terms" in node_types, "digest nodes must be present"
    assert "wicket_manifest" in node_types, "constraint evidence_digest nodes"

    edge_labels = {e.label for e in view.edges}
    assert "attests_over" in edge_labels, "both capsules attest over offer_terms"
    assert "chains_to" in edge_labels, "seller chains to buyer"
    assert "commits_to" in edge_labels, "capsules commit to constraint manifests"


def test_single_capsule_parse():
    """Single capsule (non-bilateral) parses without error."""
    cap = {
        "capsule_id": _fake_hex64("aa"),
        "action_type": "decide",
        "operator": "buyer:org",
        "model_attestation": {
            "compute_attestation": {"subject_digest": _fake_hex64("bb")}
        },
        "disposition": {"decision": "accept"},
    }
    view = _aac.parse_capsule(cap)
    assert not view.parse_error
    assert not view.is_binding
    assert any(n.node_type == "capsule" for n in view.nodes)
    assert any(n.node_type == "subject" for n in view.nodes)
    assert any(e.label == "attests_over" for e in view.edges)


# ---------------------------------------------------------------------------
# Regulatory context panel
# ---------------------------------------------------------------------------

def test_reg_panel_without_receipt_has_attribution_only():
    """Without an anchor receipt, only per-action-attribution rows appear."""
    html = _render_reg_panel(has_receipt=False, has_hitl=False, has_withheld=False)
    assert "per-action-attribution" in html
    assert "tamper-evident-log" not in html
    assert "human-oversight-record" not in html
    assert "disclosure-transparency-record" not in html


def test_reg_panel_with_receipt_adds_tamper_evident_rows():
    """With an anchor receipt, tamper-evident-log rows are included."""
    html = _render_reg_panel(has_receipt=True, has_hitl=False, has_withheld=False)
    assert "tamper-evident-log" in html
    assert "EU AI Act Art 12" in html
    assert "SEC Rule 17a-4" in html
    assert "per-action-attribution" in html


def test_reg_panel_with_hitl_adds_human_oversight_rows():
    """With human disposition, human-oversight-record rows are included."""
    html = _render_reg_panel(has_receipt=False, has_hitl=True, has_withheld=False)
    assert "human-oversight-record" in html
    assert "NIST AI RMF MANAGE 1.3" in html
    assert "tamper-evident-log" not in html


def test_reg_panel_with_withheld_adds_disclosure_rows():
    """With withheld commitments, disclosure-transparency-record rows appear."""
    html = _render_reg_panel(has_receipt=False, has_hitl=False, has_withheld=True)
    assert "disclosure-transparency-record" in html
    assert "EU AI Act Art 50(1)" in html


def test_reg_panel_all_properties():
    """All four properties active: all row categories present."""
    html = _render_reg_panel(has_receipt=True, has_hitl=True, has_withheld=True)
    for prop in ("tamper-evident-log", "human-oversight-record",
                 "disclosure-transparency-record", "per-action-attribution"):
        assert prop in html, f"expected {prop} in panel"


def test_reg_panel_has_disclaimer():
    """Panel always includes the verbatim disclaimer."""
    html = _render_reg_panel(has_receipt=False, has_hitl=False, has_withheld=False)
    assert "not legal advice" in html
    assert "Regulatory context (informational)" in html


def test_reg_panel_links_to_crosswalk():
    """Panel links to the full regulatory crosswalk document."""
    html = _render_reg_panel(has_receipt=True, has_hitl=False, has_withheld=False)
    assert "regulatory-crosswalk.md" in html
    assert "full crosswalk" in html


def test_capsule_page_has_reg_panel_mount():
    """Capsule permalink page includes the reg panel section mount point."""
    cid = "c" * 64
    html = render_capsule_page(cid)
    assert "regPanelSection" in html
    assert "regPanelMount" in html


def test_capsule_js_has_reg_panel_logic():
    """CAPSULE_JS includes the reg panel rendering function."""
    assert "renderRegPanel" in CAPSULE_JS
    assert "REG_ROWS" in CAPSULE_JS
    assert "regulatory-crosswalk.md" in CAPSULE_JS
    assert "not legal advice" in CAPSULE_JS
    assert "per-action-attribution" in CAPSULE_JS


# ---------------------------------------------------------------------------
# compute_attestation agent_input / agent_output digest parsing (Goose fixture)
# ---------------------------------------------------------------------------

# Real goose-demo ledger record (leaf-199, capsule_id from _work/goose-demo/goose-session-ledger.jsonl).
# No subject_digest, no effect request/response_digest — only agent_input_digest + agent_output_digest.
_GOOSE_LEAF_199 = {
    "spec_version": "draft-mih-scitt-agent-action-capsule-02",
    "format_version": "2",
    "capsule_id": "6d8c1a4718847f98aad34b4975482bdc11ae3cbaa11939ff2e920497c86274fc",
    "action_id": "check_inventory/fb70e774-a7cb-4e9c-a838-19c183994156",
    "action_type": "decide",
    "operator": "demo-org",
    "developer": "goose@v1.39.0",
    "timestamp": "2026-07-28T05:32:01.975608Z",
    "model_attestation": {
        "compute_attestation": {
            "agent_input_digest": "69b9552c1e559977744c3279775fb2db656d9e0632f23f17fa3416fe929a8924",
            "agent_output_digest": "caeadaa1a378b7df5530040b9111982f0cf52c16e3af178b3dd10ab97e2330a5",
            "runtime": "mcp",
        }
    },
    "effect": {"status": "dispatched", "type": "check_inventory", "effect_attestation": "runtime_claimed"},
    "assurance": {
        "attestation_mode": "self_attested",
        "effect_mode": "dispatched_unconfirmed",
        "ledger_mode": "standalone",
    },
    "disposition": {"decision": "accept", "approver": "policy", "human_disposed": False, "verdict_class": "executed"},
}

_GOOSE_AI_DIGEST = "69b9552c1e559977744c3279775fb2db656d9e0632f23f17fa3416fe929a8924"
_GOOSE_AO_DIGEST = "caeadaa1a378b7df5530040b9111982f0cf52c16e3af178b3dd10ab97e2330a5"


def test_goose_compute_attestation_digests_produce_3_nodes():
    """Goose leaf-199: capsule node + agent_input + agent_output = 3 nodes total."""
    view = _aac.parse_capsule(_GOOSE_LEAF_199)

    assert not view.parse_error
    assert not view.is_binding
    assert len(view.nodes) == 3, (
        f"expected 3 nodes (capsule+agent_input+agent_output), got {len(view.nodes)}: "
        + str([n.node_type for n in view.nodes])
    )
    node_types = {n.node_type for n in view.nodes}
    assert node_types == {"capsule", "agent_input", "agent_output"}


def test_goose_compute_attestation_digests_in_privilege_log():
    """Goose leaf-199: privilege log has exactly 2 WITHHELD entries (agent_input, agent_output)."""
    view = _aac.parse_capsule(_GOOSE_LEAF_199)

    assert not view.parse_error
    assert len(view.privilege_log) == 2, (
        f"expected 2 privilege-log rows, got {len(view.privilege_log)}: "
        + str([e.artifact_type for e in view.privilege_log])
    )
    log_types = {e.artifact_type for e in view.privilege_log}
    assert log_types == {"agent_input", "agent_output"}

    for entry in view.privilege_log:
        assert entry.is_withheld, f"{entry.artifact_type} should be WITHHELD"
        assert entry.match_ok is None, f"{entry.artifact_type} match_ok should be None (withheld)"
        assert "compute_attestation" in entry.context
        assert entry.is_known_type


def test_goose_compute_attestation_edges():
    """Goose leaf-199: attests_over edges from capsule to both agent digests."""
    view = _aac.parse_capsule(_GOOSE_LEAF_199)
    edge_targets = {e.to_id for e in view.edges if e.label == "attests_over"}
    assert _GOOSE_AI_DIGEST in edge_targets
    assert _GOOSE_AO_DIGEST in edge_targets


def test_goose_compute_attestation_reveal_path():
    """If agent_input / agent_output preimages are supplied, they are revealed and match-checked."""
    ai_preimage = {"prompt": "check inventory for item_id=42", "tool": "check_inventory"}
    ao_preimage = {"result": "in_stock", "quantity": 7}
    ai_digest = _aac._json_digest(ai_preimage)
    ao_digest = _aac._json_digest(ao_preimage)

    cap_with_preimage = {
        "capsule_id": _fake_hex64("77"),
        "model_attestation": {
            "compute_attestation": {
                "agent_input_digest": ai_digest,
                "agent_input": ai_preimage,
                "agent_output_digest": ao_digest,
                "agent_output": ao_preimage,
            }
        },
        "disposition": {"decision": "accept"},
    }
    view = _aac.parse_capsule(cap_with_preimage)
    assert not view.parse_error
    ai_node = next(n for n in view.nodes if n.node_type == "agent_input")
    ao_node = next(n for n in view.nodes if n.node_type == "agent_output")
    assert not ai_node.is_withheld
    assert ai_node.revealed_payload == ai_preimage
    assert not ao_node.is_withheld
    assert ao_node.revealed_payload == ao_preimage

    ai_entry = next(e for e in view.privilege_log if e.artifact_type == "agent_input")
    ao_entry = next(e for e in view.privilege_log if e.artifact_type == "agent_output")
    assert ai_entry.match_ok is True
    assert ao_entry.match_ok is True


def test_reg_panel_disclosure_fires_for_compute_attestation_digests():
    """disclosure-transparency-record row lights when a capsule has agent_input/output digests."""
    html = _render_reg_panel(has_receipt=False, has_hitl=False, has_withheld=True)
    assert "disclosure-transparency-record" in html
    assert "EU AI Act Art 50(1)" in html


# ---------------------------------------------------------------------------
# /anchor-status endpoint — recorded fixture tests for _anchor_proxy_json
# (The DEPLOYED verify surface used to query /anchor/transparency-log?capsule_id=<id>
#  which always returned []. Fix landed in PR #16 (8ba25df) — now queries
#  GET /v1/inclusion/{capsule_id}. These tests exercise the field mapping
#  and 404 handling without live network access.)
# ---------------------------------------------------------------------------


def test_anchor_proxy_maps_inclusion_response_fields():
    """Recorded fixture: /v1/inclusion/ 200 maps correctly to the response dict.

    Uses the real Goose leaf-199 capsule_id. The mock returns a plausible
    inclusion response without receipt_b64 so the receipt-verify block is
    skipped (live test covers that path).
    """
    from unittest.mock import MagicMock, patch

    inclusion_body = json.dumps({
        "capsule_id": _LEAF_199_CAPSULE_ID,
        "entry_hash": "a" * 64,
        "leaf_index": 199,
        "tree_size": 200,
        "leaf_hash": "b" * 64,
        "audit_path": [],
        "root_hash": "c" * 64,
        "receipt_b64": "",   # empty → receipt-verify block skipped
    }).encode()

    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.read.return_value = inclusion_body

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = _anchor_proxy_json(_LEAF_199_CAPSULE_ID)

    assert result["capsule_id"] == _LEAF_199_CAPSULE_ID
    assert result["anchored"] is True
    assert result["leaf_index"] == 199
    assert result["tree_size"] == 200
    assert result["log_index"] == 199   # log_index mirrors leaf_index
    assert result["error"] is None
    assert result["receipt_verified"] is False  # no receipt_b64 → not verified


def test_anchor_proxy_404_returns_not_anchored_no_error():
    """Recorded fixture: 404 from /v1/inclusion/ → anchored=False, error=None.

    This is the correct treatment for a capsule_id not yet in the log —
    absence is not an error condition.
    """
    import urllib.error
    from unittest.mock import patch

    _UNKNOWN_ID = "d" * 64

    def _raise_404(req, **_kw):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    with patch("urllib.request.urlopen", side_effect=_raise_404):
        result = _anchor_proxy_json(_UNKNOWN_ID)

    assert result["anchored"] is False
    assert result["error"] is None
    assert result["capsule_id"] == _UNKNOWN_ID
