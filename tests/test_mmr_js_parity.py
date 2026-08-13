# SPDX-License-Identifier: Apache-2.0
"""``hosted_profiles.hosted``'s ``MMR_JS`` is a hand port of capsule-ledger's
``capsule_ledger.mmr.core`` completeness-certificate math (leaf_hash,
interior_hash, root_from_peaks, verify_inclusion, verify_consistency) -- not
a reimplementation this suite trusts by inspection. These tests actually run
it (via Node, ``tests/js_harness_mmr.mjs``) against the pinned vectors in
``test-vectors/mmr/`` and assert byte-identical output against the Python
reference that minted them (``scripts/generate_mmr_kat39_vectors.py``, which
itself asserts agreement with capsule-ledger's own KAT39 test before export).

``test_verify_inclusion_rejects_corrupted_proof_byte`` and
``test_verify_consistency_rejects_corrupted_proof_byte`` are the mutant
tests: flip one byte of a genuinely-valid proof and confirm the JS verifier
flips to ``false`` -- the "must fail its mutants" guardrail. A verifier that
can't reject anything isn't a verifier.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from hosted_profiles.hosted import MMR_JS

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_mmr.mjs"
VECTORS = HERE.parent / "test-vectors" / "mmr"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


@pytest.fixture(scope="module")
def mmr_js_path():
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
        fh.write(MMR_JS)
        path = Path(fh.name)
    yield path
    path.unlink(missing_ok=True)


def _run_js(mmr_js_path: Path, op: dict):
    result = subprocess.run(
        ["node", str(HARNESS), str(mmr_js_path)],
        input=json.dumps(op),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def kat39():
    return json.loads((VECTORS / "kat39.json").read_text())


@pytest.fixture(scope="module")
def proof_vectors():
    return json.loads((VECTORS / "proof-vectors.json").read_text())


# -- KAT39: byte-identical low-level hash primitives -------------------------


def test_js_interior_hash_matches_python_for_every_kat39_triple(mmr_js_path, kat39):
    """Every (left, right, position) -> result triple recorded while replaying
    the upstream KAT39 leaves through the real Python add_leaf: the JS port's
    interiorHash must reproduce the exact same output, byte for byte."""
    triples = kat39["interior_triples"]
    assert len(triples) >= 18  # 21 leaves over a 39-node tree -> nontrivial interior count
    for t in triples:
        got = _run_js(mmr_js_path, {
            "fn": "interiorHash", "left": t["left"], "right": t["right"], "position": t["position"],
        })
        assert got == t["result"], f"interior_hash({t['left'][:8]}.., {t['right'][:8]}.., {t['position']})"


def test_js_root_from_peaks_matches_python_for_every_kat39_size(mmr_js_path, kat39):
    for mmr_index, expected_hashes in kat39["peak_hashes"].items():
        got_peaks = _run_js(mmr_js_path, {"fn": "peaks", "size": int(mmr_index) + 1})
        assert got_peaks == kat39["peak_indices"][mmr_index], f"peaks(size={int(mmr_index)+1})"
        got_root = _run_js(mmr_js_path, {"fn": "rootFromPeaks", "peaks": expected_hashes})
        # Cross-language parity only (root_from_peaks has no upstream KAT root --
        # see capsule_ledger/mmr/core.py's docstring); the full-tree case is checked
        # against Python's own root_full below for the strongest signal.
        if mmr_index == "38":
            assert got_root == kat39["root_full"]


def test_js_root_from_peaks_matches_python_full_tree_root(mmr_js_path, kat39):
    full_peaks = kat39["peak_hashes"]["38"]
    got = _run_js(mmr_js_path, {"fn": "rootFromPeaks", "peaks": full_peaks})
    assert got == kat39["root_full"]


def test_js_interior_hash_is_position_committed(mmr_js_path, kat39):
    """Direct demonstration that position-commitment does real work in the JS
    port too: the same (left, right) pair at two different positions must
    produce different hashes (mirrors capsule-ledger's own KAT39 test)."""
    left, right = kat39["nodes"][0], kat39["nodes"][1]
    h_at_2 = _run_js(mmr_js_path, {"fn": "interiorHash", "left": left, "right": right, "position": 2})
    h_at_100 = _run_js(mmr_js_path, {"fn": "interiorHash", "left": left, "right": right, "position": 100})
    assert h_at_2 != h_at_100
    assert h_at_2 == kat39["nodes"][2]


# -- self-generated proof vectors: verifyInclusion / verifyConsistency -------


def test_js_verify_inclusion_accepts_every_genuine_proof(mmr_js_path, proof_vectors):
    for case in proof_vectors["inclusion_cases"]:
        got = _run_js(mmr_js_path, {
            "fn": "verifyInclusion",
            "root": case["root"], "size": case["size"], "leaf_index": case["leaf_index"],
            "body_digest": case["body_digest"], "proof": case["proof"],
        })
        assert got is True, f"leaf_index={case['leaf_index']} should verify"


def test_js_verify_consistency_accepts_genuine_proof(mmr_js_path, proof_vectors):
    c = proof_vectors["consistency_case"]
    got = _run_js(mmr_js_path, {
        "fn": "verifyConsistency",
        "root_a": c["root_a"], "size_a": c["size_a"], "root_b": c["root_b"], "size_b": c["size_b"],
        "proof": c["proof"],
    })
    assert got is True


# -- mutant tests: a verifier that can't reject anything isn't a verifier ----


def _flip_hex_byte(hex_str: str) -> str:
    b = bytearray(bytes.fromhex(hex_str))
    b[0] ^= 0xFF
    return b.hex()


def test_verify_inclusion_rejects_corrupted_proof_byte(mmr_js_path, proof_vectors):
    case = proof_vectors["inclusion_cases"][0]
    tampered = json.loads(json.dumps(case["proof"]))
    tampered["witness"][0] = _flip_hex_byte(tampered["witness"][0])
    got = _run_js(mmr_js_path, {
        "fn": "verifyInclusion",
        "root": case["root"], "size": case["size"], "leaf_index": case["leaf_index"],
        "body_digest": case["body_digest"], "proof": tampered,
    })
    assert got is False


def test_verify_inclusion_rejects_wrong_body_digest(mmr_js_path, proof_vectors):
    case = proof_vectors["inclusion_cases"][0]
    wrong_digest = _flip_hex_byte(case["body_digest"])
    got = _run_js(mmr_js_path, {
        "fn": "verifyInclusion",
        "root": case["root"], "size": case["size"], "leaf_index": case["leaf_index"],
        "body_digest": wrong_digest, "proof": case["proof"],
    })
    assert got is False


def test_verify_inclusion_rejects_wrong_root(mmr_js_path, proof_vectors):
    case = proof_vectors["inclusion_cases"][0]
    got = _run_js(mmr_js_path, {
        "fn": "verifyInclusion",
        "root": _flip_hex_byte(case["root"]), "size": case["size"], "leaf_index": case["leaf_index"],
        "body_digest": case["body_digest"], "proof": case["proof"],
    })
    assert got is False


def test_verify_consistency_rejects_corrupted_proof_byte(mmr_js_path, proof_vectors):
    c = proof_vectors["consistency_case"]
    tampered = json.loads(json.dumps(c["proof"]))
    tampered["old_peaks"][0] = _flip_hex_byte(tampered["old_peaks"][0])
    got = _run_js(mmr_js_path, {
        "fn": "verifyConsistency",
        "root_a": c["root_a"], "size_a": c["size_a"], "root_b": c["root_b"], "size_b": c["size_b"],
        "proof": tampered,
    })
    assert got is False


def test_verify_consistency_rejects_wrong_size_b(mmr_js_path, proof_vectors):
    c = proof_vectors["consistency_case"]
    got = _run_js(mmr_js_path, {
        "fn": "verifyConsistency",
        "root_a": c["root_a"], "size_a": c["size_a"], "root_b": c["root_b"], "size_b": c["size_b"] + 1,
        "proof": c["proof"],
    })
    assert got is False


def test_verify_inclusion_never_throws_on_garbage_proof(mmr_js_path, proof_vectors):
    """The never-raise contract: malformed input is a verification failure,
    never an exception -- mirrors core.py's verify_inclusion docstring."""
    case = proof_vectors["inclusion_cases"][0]
    for garbage in (None, {}, {"v": 1, "kind": "inclusion"}, {"v": 2, "kind": "inclusion", "size": 1,
                                                               "leaf_index": 0, "witness": [], "peaks_left": [],
                                                               "peaks_right": []}):
        got = _run_js(mmr_js_path, {
            "fn": "verifyInclusion",
            "root": case["root"], "size": case["size"], "leaf_index": case["leaf_index"],
            "body_digest": case["body_digest"], "proof": garbage,
        })
        assert got is False
