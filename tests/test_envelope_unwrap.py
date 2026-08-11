# SPDX-License-Identifier: Apache-2.0
"""[verify-envelope-unwrap-fix] — Disclosure-Envelope unwrap gaps in the verify viewer.

Both bugs shared one root cause: hosted.py's viewer code read fields directly
off the raw top-level fragment; for a Disclosure-Envelope fragment
(``{"capsule": {...}, "disclosures": {...}}``) those fields live at
``data.capsule.*``, not the top level.

Fix 1 (reg-panel undercount): ``renderRegPanel``'s ``checkHitl``/``checkSd``
(mirrored in Python by ``_capsule_has_hitl``/``_capsule_has_sd``) now unwrap
before reading ``disposition``/``model_attestation``.

Fix 2 (bundle ritual vacuous pass — the serious one): the array-fragment
bundle path (``evaluateRitual``/``renderChainTable``/``_capSummary``/
``findChainGaps``/``annotateRecords`` in ``CAPSULE_JS``; ``findChainGaps``/
``annotateRecords``/``verifyCapsuleId``/``computeCapsuleId`` also in
``BUNDLE_JS``, byte-pinned identical to ``CAPSULE_JS``'s copy by
``test_bundle_js_shared_helpers_match_capsule_js``) silently SKIPPED records
whose ``capsule_id`` was nested in an envelope, then reported a vacuous
"Integrity check✓ — every record matches" pass. Fixed by unwrapping each
bundle item before the ``isH64(capsule_id)`` gate. ``hosted_profiles.aac``'s
Python mirror (``find_chain_gaps``/``evaluate_ritual``/``annotate_records``)
gets the identical fix.

The ``findChainGaps``/``annotateRecords``/``verifyCapsuleId``/
``computeCapsuleId`` cases below run the REAL ``BUNDLE_JS`` via Node
(``tests/js_harness_bundle.mjs``) — not a reimplementation — exactly like
``tests/test_capsule_id_recompute.py``. ``CAPSULE_JS`` is IIFE-scoped (its
internals aren't reachable the way ``BUNDLE_JS``'s flat top-level functions
are), but it carries a byte-identical copy of these functions (pinned by
``test_bundle_js_shared_helpers_match_capsule_js`` in
``tests/test_bundle_page.py``), so proving ``BUNDLE_JS``'s copy correct
proves both.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from hosted_profiles import aac
from hosted_profiles.hosted import (
    BUNDLE_JS,
    CAPSULE_JS,
    MMR_JS,
    _capsule_has_hitl,
    _capsule_has_sd,
    _unwrap_envelope,
)

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_bundle.mjs"


def _fake_hex64(prefix: str) -> str:
    return (prefix * 64)[:64]


CAP_A = _fake_hex64("aa")
CAP_B = _fake_hex64("bb")
CAP_C = _fake_hex64("cc")


def _cap(cid: str, parent: str | None = None, **overrides) -> dict:
    cap = {
        "capsule_id": cid,
        "action_type": "decide",
        "operator": "acme-co",
        "timestamp": "2026-08-11T00:00:00Z",
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }
    if parent:
        cap["chain"] = {"parent_capsule_id": parent, "relation": "sequence"}
    cap.update(overrides)
    return cap


def _envelope(cap: dict, disclosures: dict | None = None) -> dict:
    return {"capsule": cap, "disclosures": disclosures or {}}


# ---------------------------------------------------------------------------
# Fix 1 — reg-panel property detectors (_capsule_has_hitl/_capsule_has_sd,
# the Python mirrors of CAPSULE_JS's checkHitl/checkSd) must detect the same
# properties on an envelope-wrapped capsule as on the bare capsule inside it.
# ---------------------------------------------------------------------------


def test_unwrap_envelope_passes_bare_capsule_through():
    bare = _cap(CAP_A)
    assert _unwrap_envelope(bare) is bare


def test_unwrap_envelope_unwraps_disclosure_envelope():
    bare = _cap(CAP_A)
    assert _unwrap_envelope(_envelope(bare)) == bare


def test_capsule_has_hitl_parity_bare_vs_disclosed():
    cap = _cap(CAP_A, disposition={"decision": "reject", "approver": "human", "human_disposed": True})
    assert _capsule_has_hitl(cap) is True
    assert _capsule_has_hitl(_envelope(cap)) is True, (
        "disclosed (envelope-wrapped) fragment must detect human-oversight-record "
        "exactly like the bare capsule it wraps"
    )


def test_capsule_has_hitl_mutant_without_unwrap_undercounts():
    """Mutant: read disposition directly off the envelope (the pre-fix
    behaviour) — must NOT see human_disposed, proving the parity test above
    is discriminating."""
    cap = _cap(CAP_A, disposition={"decision": "reject", "approver": "human", "human_disposed": True})
    env = _envelope(cap)
    disposition = env.get("disposition")  # pre-fix: no unwrap
    assert not disposition


def test_capsule_has_sd_parity_bare_vs_disclosed():
    cap = _cap(
        CAP_A,
        model_attestation={"compute_attestation": {"agent_input_digest": _fake_hex64("11")}},
    )
    assert _capsule_has_sd(cap) is True
    assert _capsule_has_sd(_envelope(cap)) is True


def test_capsule_has_sd_mutant_without_unwrap_undercounts():
    cap = _cap(
        CAP_A,
        model_attestation={"compute_attestation": {"agent_input_digest": _fake_hex64("11")}},
    )
    env = _envelope(cap)
    ca = (env.get("model_attestation") or {}).get("compute_attestation") or {}  # pre-fix: no unwrap
    assert not ca.get("agent_input_digest")


def test_capsule_js_reg_panel_unwraps_before_property_checks():
    """Structural pin: renderRegPanel must unwrap before calling checkHitl/checkSd."""
    marker = "var envCap=unwrapEnvelope(data);"
    assert marker in CAPSULE_JS
    reg_panel = CAPSULE_JS[CAPSULE_JS.index("function renderRegPanel("):]
    reg_panel = reg_panel[: reg_panel.index("\nfunction ", 1)]
    assert marker in reg_panel
    assert "checkHitl(envCap)" in reg_panel
    assert "checkSd(envCap)" in reg_panel


# ---------------------------------------------------------------------------
# Fix 2 — Python mirror (hosted_profiles.aac): find_chain_gaps/annotate_records
# no longer silently skip envelope-wrapped bundle items.
# ---------------------------------------------------------------------------


def test_find_chain_gaps_recognises_envelope_wrapped_item():
    """A -> [B, enveloped] -> C is a complete chain once B is unwrapped; the
    pre-fix code (reading capsule_id off the raw envelope) reports a spurious
    gap here because B's capsule_id/chain were invisible."""
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    assert aac.find_chain_gaps(bundle) == []


def test_find_chain_gaps_mutant_without_unwrap_reports_spurious_gap():
    """Mutant: reproduce the pre-fix code path (no unwrap) directly and
    confirm it DOES report the spurious gap this fix removes."""
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    ids = {c.get("capsule_id") for c in bundle if aac._is_hex64(c.get("capsule_id", ""))}
    gaps = []
    for i, cap in enumerate(bundle):
        if i == 0:
            continue
        parent = (cap.get("chain") or {}).get("parent_capsule_id", "")
        if aac._is_hex64(parent) and parent not in ids:
            gaps.append((i - 1, i, parent))
    assert gaps, "pre-fix logic must reproduce the spurious gap the fix removes"


def _mismatched_views(bundle):
    views = [aac.parse_capsule(c) for c in bundle]
    views[1].privilege_log.append(
        aac.PrivilegeLogEntry(
            artifact_id="agent_input", artifact_type="agent_input", digest=_fake_hex64("11"),
            is_withheld=False, is_known_type=True, match_ok=False, context="test",
        )
    )
    return views


def test_annotate_records_flags_altered_envelope_item_not_silent_skip():
    """The middle record is enveloped AND carries a real digest mismatch
    (simulated on its view's privilege_log) — annotate_records must mark it
    digest_mismatch, not silently drop it, and downstream record 2 (which
    chains to it) must be flagged as citing an altered record."""
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    views = _mismatched_views(bundle)
    notes = aac.annotate_records(bundle, views)
    assert notes[1].note == "digest_mismatch"
    assert notes[1].is_altered is True
    assert notes[2].note == "cites an altered record"
    assert notes[2].cites_altered is True


def test_annotate_records_mutant_without_unwrap_silently_drops_altered_record():
    """Mutant: the pre-fix altered_ids computation (guarded on the RAW,
    un-unwrapped capsule_id) silently drops the enveloped altered record —
    this is the vacuous-pass bug itself, reproduced directly."""
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    views = _mismatched_views(bundle)
    altered_ids = {
        bundle[i].get("capsule_id", "")
        for i, v in enumerate(views)
        if any(e.match_ok is False for e in v.privilege_log) and aac._is_hex64(bundle[i].get("capsule_id", ""))
    }
    assert altered_ids == set(), "pre-fix logic must drop the enveloped altered record entirely"


def test_evaluate_ritual_sequence_clean_for_envelope_mixed_bundle():
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    views = [aac.parse_capsule(c) for c in bundle]
    summary = aac.evaluate_ritual(bundle, views, witness=None)
    seq = next(s for s in summary.stages if s.name == "Sequence")
    assert seq.status == "pass"


# ---------------------------------------------------------------------------
# Fix 2 — real JS execution (Node) against BUNDLE_JS's byte-identical copy of
# findChainGaps/annotateRecords/verifyCapsuleId/computeCapsuleId.
# ---------------------------------------------------------------------------

pytestmark_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


@pytest.fixture(scope="module")
def js_paths():
    mmr_fh = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
    mmr_fh.write(MMR_JS)
    mmr_fh.close()
    bundle_fh = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
    bundle_fh.write(BUNDLE_JS)
    bundle_fh.close()
    yield Path(mmr_fh.name), Path(bundle_fh.name)
    Path(mmr_fh.name).unlink(missing_ok=True)
    Path(bundle_fh.name).unlink(missing_ok=True)


def _run_js(js_paths, op: dict):
    mmr_path, bundle_path = js_paths
    result = subprocess.run(
        ["node", str(HARNESS), str(mmr_path), str(bundle_path)],
        input=json.dumps(op),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytestmark_node
def test_js_find_chain_gaps_unwraps_envelope_items(js_paths):
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    gaps = _run_js(js_paths, {"fn": "findChainGaps", "capsules": bundle})
    assert gaps == []


@pytestmark_node
def test_js_annotate_records_flags_altered_envelope_item(js_paths):
    bundle = [_cap(CAP_A), _envelope(_cap(CAP_B, parent=CAP_A)), _cap(CAP_C, parent=CAP_B)]
    integrity = [{"ok": True}, {"ok": False}, {"ok": True}]
    notes = _run_js(js_paths, {"fn": "annotateRecords", "capsules": bundle, "integrity": integrity})
    assert notes[1]["note"] == "digest_mismatch"
    assert notes[1]["isAltered"] is True
    assert notes[2]["note"] == "cites an altered record"


@pytestmark_node
def test_js_verify_capsule_id_unwraps_envelope(js_paths):
    """A Disclosure-Envelope-wrapped capsule must verify identically to its
    bare form — before the fix, verifyCapsuleId(envelope) always returned
    ok:null (envelope.capsule_id is undefined) regardless of the wrapped
    capsule's actual integrity."""
    cap = _cap(CAP_A)
    cap["capsule_id"] = _run_js(js_paths, {"fn": "computeCapsuleId", "capsule": cap})
    bare_result = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": cap})
    env_result = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": _envelope(cap)})
    assert bare_result["ok"] is True
    assert env_result == bare_result


@pytestmark_node
def test_js_verify_capsule_id_envelope_mutant_fails_closed(js_paths):
    """A tampered capsule wrapped in an envelope must NOT verify — proves the
    envelope unwrap recomputes over the real (tampered) body, not a pass
    manufactured by the wrapper shape."""
    cap = _cap(CAP_A)
    cap["capsule_id"] = _run_js(js_paths, {"fn": "computeCapsuleId", "capsule": cap})
    tampered = dict(cap)
    tampered["disposition"] = {"decision": "reject", "verdict_class": "blocked"}
    result = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": _envelope(tampered)})
    assert result["ok"] is False
    assert result["recomputed"] != result["stated"]
