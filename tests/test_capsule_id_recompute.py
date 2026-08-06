# SPDX-License-Identifier: Apache-2.0
"""[aac-viewer-recompute-capsule-id] — the viewer must recompute capsule_id
from the fragment body (RFC 8785 JCS + SHA-256, agent-action-capsule's
canonical.compute_capsule_id) and refuse to show a pass for a body that does
not hash to its own stated capsule_id.

Before this fix, ``CAPSULE_JS``/``BUNDLE_JS`` read ``data.capsule_id``
straight off the fragment and never checked it against the body — a capsule
whose content was altered after signing/anchoring would still render the
green "Anchored" banner and a "verifies" ritual, because the id being logged
in the transparency log says nothing about whether THIS body is what was
logged. See ``test-vectors/capsule-id/PROVENANCE.md`` for the fixtures' real,
live-anchored source (capsule-2 is the exact denial capsule from the finding,
leaf 243) and the one documented scope note (no revealed-agent_input variant
was recoverable locally; the disposition-flip mutation alone is used, which
exercises the identical mechanism).

Every test here runs the REAL ``computeCapsuleId``/``verifyCapsuleId`` /
``annotateRecords`` / ``evaluateBundleRitual`` JS via Node
(``tests/js_harness_bundle.mjs``) against ``hosted_profiles.hosted``'s actual
``BUNDLE_JS`` — not a reimplementation of it in Python — exactly like
``tests/test_mmr_js_parity.py``. ``CAPSULE_JS`` carries a byte-identical copy
of the capsule_id functions (pinned by
``test_bundle_js_shared_helpers_match_capsule_js`` in
``tests/test_bundle_page.py``), so proving BUNDLE_JS's copy correct proves
both.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from hosted_profiles.hosted import BUNDLE_JS, MMR_JS

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_bundle.mjs"
VECTORS = HERE.parent / "test-vectors" / "capsule-id"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


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


def _load_capsule(name: str) -> dict:
    return json.loads((VECTORS / f"{name}.json").read_text())


@pytest.fixture(scope="module")
def expected():
    return json.loads((VECTORS / "expected.json").read_text())


FIXTURES = ("capsule-1", "capsule-2", "capsule-3", "capsule-2-tampered")


# ---------------------------------------------------------------------------
# JS/Python parity: computeCapsuleId / verifyCapsuleId against real,
# live-anchored capsules and the one hand-tampered negative fixture.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", FIXTURES)
def test_compute_capsule_id_matches_python_oracle(js_paths, expected, name):
    capsule = _load_capsule(name)
    got = _run_js(js_paths, {"fn": "computeCapsuleId", "capsule": capsule})
    assert got == expected[name]["recomputed"]


@pytest.mark.parametrize("name", FIXTURES)
def test_verify_capsule_id_matches_expected_ok(js_paths, expected, name):
    capsule = _load_capsule(name)
    got = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": capsule})
    exp = expected[name]
    assert got["stated"] == exp["stated"]
    assert got["recomputed"] == exp["recomputed"]
    assert got["ok"] == exp["ok"]


def test_clean_capsules_verify_true(js_paths):
    """The three real, untampered, live-anchored capsules must all pass."""
    for name in ("capsule-1", "capsule-2", "capsule-3"):
        got = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": _load_capsule(name)})
        assert got["ok"] is True, name


def test_tampered_capsule_fails_closed(js_paths):
    """The disposition-flipped denial-capsule (reject/blocked -> accept/executed,
    capsule_id left byte-identical) must NOT verify — this is the exact
    finding: a denial silently reading as an approval."""
    got = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": _load_capsule("capsule-2-tampered")})
    assert got["ok"] is False
    assert got["stated"] == "08bec0383378c13cc8046964b3d4ffb8ebca2c573f3b26305f026bed0aa8b4cd"
    assert got["recomputed"] != got["stated"]


# ---------------------------------------------------------------------------
# Mutant check: the check must actually FAIL its mutants -- flipping any
# single field must change the recomputed digest. A check that can't reject
# anything isn't a check.
# ---------------------------------------------------------------------------


def test_mutant_single_field_flip_changes_digest(js_paths):
    clean = _load_capsule("capsule-2")
    mutated = json.loads(json.dumps(clean))
    mutated["operator"] = "not-acme-co"
    clean_id = _run_js(js_paths, {"fn": "computeCapsuleId", "capsule": clean})
    mutated_id = _run_js(js_paths, {"fn": "computeCapsuleId", "capsule": mutated})
    assert clean_id != mutated_id
    assert clean_id == clean["capsule_id"]


def test_mutant_untampering_flips_back_to_ok(js_paths):
    """Un-tamper capsule-2-tampered back to its real disposition and the
    check must flip back to ok:true — proving it isn't hardcoded to fail."""
    tampered = _load_capsule("capsule-2-tampered")
    fixed = json.loads(json.dumps(tampered))
    fixed["disposition"] = {
        "decision": "reject", "approver": "human",
        "human_disposed": True, "verdict_class": "blocked",
    }
    got = _run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": fixed})
    assert got["ok"] is True
    assert got["recomputed"] == fixed["capsule_id"]


# ---------------------------------------------------------------------------
# Full bundle flow: evaluateBundleRitual + annotateRecords over a 3-capsule
# bundle with capsule-2 tampered -- proves the fix applies to every capsule
# in a bundle/array fragment, not just the one rendered, and that the
# downstream chain member (capsule-3, which cites capsule-2 via
# chain.parent_capsule_id) is flagged as "cites an altered record", never
# itself failed.
# ---------------------------------------------------------------------------


def _integrity_for(js_paths, records):
    return [_run_js(js_paths, {"fn": "verifyCapsuleId", "capsule": c}) for c in records]


def test_bundle_with_one_tampered_member_flags_only_that_member(js_paths):
    records = [_load_capsule("capsule-1"), _load_capsule("capsule-2-tampered"), _load_capsule("capsule-3")]
    integrity = _integrity_for(js_paths, records)
    assert [i["ok"] for i in integrity] == [True, False, True]

    notes = _run_js(js_paths, {"fn": "annotateRecords", "capsules": records, "integrity": integrity})
    assert notes[0]["note"] == "verifies"
    assert notes[0]["isAltered"] is False
    assert notes[1]["note"] == "digest_mismatch"
    assert notes[1]["isAltered"] is True
    assert notes[2]["note"] == "cites an altered record"
    assert notes[2]["isAltered"] is False
    assert notes[2]["citesAltered"] is True


def test_bundle_ritual_integrity_fails_with_stated_vs_recomputed_in_the_finding(js_paths):
    records = [_load_capsule("capsule-1"), _load_capsule("capsule-2-tampered"), _load_capsule("capsule-3")]
    integrity = _integrity_for(js_paths, records)
    completeness = {"status": "skip", "detail": "no completeness certificate in this bundle"}
    cross_check = {"status": "pass", "detail": "no producer self-report present"}
    summary = _run_js(js_paths, {
        "fn": "evaluateBundleRitual", "records": records,
        "completeness": completeness, "crossCheck": cross_check, "integrity": integrity,
    })
    integrity_stage = next(s for s in summary["stages"] if s["name"] == "Integrity")
    assert integrity_stage["status"] == "fail"
    assert summary["finding"] is not None
    stated = "08bec0383378c13cc8046964b3d4ffb8ebca2c573f3b26305f026bed0aa8b4cd"
    assert stated in summary["finding"]["meta"]
    assert stated not in summary["finding"]["meta"].split("recomputed")[-1]  # recomputed id differs
    # Sequence must still pass -- chain.parent_capsule_id is unchanged by the tamper
    sequence_stage = next(s for s in summary["stages"] if s["name"] == "Sequence")
    assert sequence_stage["status"] == "pass"


def test_bundle_ritual_mutant_check_all_clean_passes(js_paths):
    """Mutant guardrail: the same 3-capsule bundle with the REAL (untampered)
    capsule-2 must show Integrity pass and no finding -- the check isn't
    hardcoded to fail, it responds to the actual body content."""
    records = [_load_capsule("capsule-1"), _load_capsule("capsule-2"), _load_capsule("capsule-3")]
    integrity = _integrity_for(js_paths, records)
    assert all(i["ok"] for i in integrity)
    completeness = {"status": "skip", "detail": "no completeness certificate in this bundle"}
    cross_check = {"status": "pass", "detail": "no producer self-report present"}
    summary = _run_js(js_paths, {
        "fn": "evaluateBundleRitual", "records": records,
        "completeness": completeness, "crossCheck": cross_check, "integrity": integrity,
    })
    integrity_stage = next(s for s in summary["stages"] if s["name"] == "Integrity")
    assert integrity_stage["status"] == "pass"
    assert summary["finding"] is None

    notes = _run_js(js_paths, {"fn": "annotateRecords", "capsules": records, "integrity": integrity})
    assert [n["note"] for n in notes] == ["verifies", "verifies", "verifies"]
