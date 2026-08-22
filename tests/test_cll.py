# SPDX-License-Identifier: Apache-2.0
"""CLL (Checkpointed Local Log) verification: MMR primitives cross-checked
against the committed ``test-vectors/mmr/`` set, the checkpoint digest
algorithm cross-checked against a live ``capsule_emit.checkpoint`` value,
mutant tests that must show the red (a verifier that can't reject anything
isn't a verifier), and an end-to-end offline chain: capsule + inclusion
proof + witnessed checkpoint receipt, no network, no live log.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scitt_cose import cll
from scitt_cose.receipt import build_receipt

VECTORS = Path(__file__).parent.parent / "test-vectors" / "mmr"


@pytest.fixture(scope="module")
def kat39():
    return json.loads((VECTORS / "kat39.json").read_text())


@pytest.fixture(scope="module")
def proof_vectors():
    return json.loads((VECTORS / "proof-vectors.json").read_text())


# -- KAT39: byte-identical hash/position primitives --------------------------
# Same vectors test_mmr_js_parity.py pins the JS port against; here they pin
# this module's Python primitives directly. Provenance: kat39.json's own
# `_provenance` field (datatrails/go-datatrails-merklelog, MIT licensed).


def test_interior_hash_matches_kat39_for_every_triple(kat39):
    triples = kat39["interior_triples"]
    assert len(triples) >= 18
    for t in triples:
        got = cll.interior_hash(bytes.fromhex(t["left"]), bytes.fromhex(t["right"]), t["position"])
        assert got.hex() == t["result"], f"interior_hash({t['left'][:8]}.., {t['right'][:8]}.., {t['position']})"


def test_peaks_matches_kat39_for_every_size(kat39):
    """`peak_indices` is keyed by mmr_index = size - 1 (kat39.json convention)."""
    for mmr_index_str, expected_peak_positions in kat39["peak_indices"].items():
        size = int(mmr_index_str) + 1
        assert cll.peaks(size) == expected_peak_positions


def test_root_from_peaks_matches_kat39_full_root(kat39):
    nodes = [bytes.fromhex(n) for n in kat39["nodes"]]
    size = len(nodes)
    pks = cll.peaks(size)
    root = cll.root_from_peaks([nodes[p] for p in pks])
    assert root.hex() == kat39["root_full"]
    assert cll.leaf_count(size) == 21


# -- proof-vectors.json: inclusion + consistency, positive and negative ------
# Self-generated (12 leaves, real leaf_hash), minted by the pre-port
# asg_ledger.mmr.core reference and confirmed to verify before export.


def test_inclusion_cases_verify(proof_vectors):
    for c in proof_vectors["inclusion_cases"]:
        proof = cll.InclusionProof.from_dict(c["proof"])
        ok = cll.verify_inclusion(
            bytes.fromhex(c["root"]), c["size"], c["leaf_index"], bytes.fromhex(c["body_digest"]), proof
        )
        assert ok == c["expect"], c


def test_negative_inclusion_cases_are_rejected(proof_vectors):
    for c in proof_vectors["negative_inclusion_cases"]:
        proof = cll.InclusionProof.from_dict(c["proof"])
        ok = cll.verify_inclusion(
            bytes.fromhex(c["root"]), c["size"], c["leaf_index"], bytes.fromhex(c["body_digest"]), proof
        )
        assert ok is False, f"{c['label']}: {c['description']} -- must be rejected, was accepted"


def test_consistency_case_verifies(proof_vectors):
    cc = proof_vectors["consistency_case"]
    proof = cll.ConsistencyProof.from_dict(cc["proof"])
    ok = cll.verify_consistency(
        bytes.fromhex(cc["root_a"]), cc["size_a"], bytes.fromhex(cc["root_b"]), cc["size_b"], proof
    )
    assert ok == cc["expect"], cc


def test_negative_consistency_cases_are_rejected(proof_vectors):
    for c in proof_vectors["negative_consistency_cases"]:
        proof = cll.ConsistencyProof.from_dict(c["proof"])
        ok = cll.verify_consistency(
            bytes.fromhex(c["root_a"]), c["size_a"], bytes.fromhex(c["root_b"]), c["size_b"], proof
        )
        assert ok is False, f"{c['label']}: {c['description']} -- must be rejected, was accepted"


# -- checkpoint digest: cross-checked against a live capsule_emit value ------
# Pinned by calling capsule_emit.checkpoint.emit.CheckpointRecord(**same
# fields).digest() directly against the cll-extract-mmr-to-capsule-emit
# branch (commit e3df69dfe / 34e90f1) -- the "shared format" this task
# depends on. Confirms Checkpoint.signing_body()/digest() here are a
# byte-identical port, not just structurally similar.


def test_checkpoint_digest_matches_capsule_emit_reference():
    cp = cll.Checkpoint(
        v=1,
        kind="mmr_checkpoint",
        log_id="log-a",
        mmr_size=22,
        root="898639faeacaa93b2648c748db07ca54f1dd12ffee423f260b5dcee8b6e889e1",
        peaks_digest="deadbeef" * 8,
        prev_size=11,
        prev_root="7252b657b3ce4b37e8472c04a3f75b9faba2fd8debe845dde0d49d2f8118690e",
        key_id="node-a",
        timestamp="2026-08-21T00:00:00Z",
        signature="",
    )
    assert cp.signing_body() == (
        '{"key_id":"node-a","kind":"mmr_checkpoint","log_id":"log-a","mmr_size":22,'
        '"peaks_digest":"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",'
        '"prev_root":"7252b657b3ce4b37e8472c04a3f75b9faba2fd8debe845dde0d49d2f8118690e",'
        '"prev_size":11,"root":"898639faeacaa93b2648c748db07ca54f1dd12ffee423f260b5dcee8b6e889e1",'
        '"timestamp":"2026-08-21T00:00:00Z","v":1}'
    )
    assert cp.digest() == "4115036519a7cc8b5e9b2a9b00fcf599113920d5880fc3645abfcb1f4491222c"


# -- mutant tests: must show the red ------------------------------------------


def test_mutant_tampered_leaf_fails_inclusion(proof_vectors):
    """Take a genuinely valid inclusion proof and tamper the claimed leaf
    content (a body_digest swapped for a different leaf's). This is the
    exact tamper the verifier exists to catch: a producer (or an attacker
    with proof material) claiming a capsule was included when a different
    one was. verify_inclusion must flip to False -- if it flips to True
    instead, this assertion goes red, which is the point."""
    genuine = proof_vectors["inclusion_cases"][0]
    assert genuine["expect"] is True
    proof = cll.InclusionProof.from_dict(genuine["proof"])
    root = bytes.fromhex(genuine["root"])

    tampered_digest = bytes.fromhex(proof_vectors["body_digests"][3])
    assert tampered_digest.hex() != genuine["body_digest"]

    ok = cll.verify_inclusion(root, genuine["size"], genuine["leaf_index"], tampered_digest, proof)
    assert ok is False, "tampered leaf must be rejected -- verifier accepted a swapped body_digest"

    # And the untampered original must still verify, so we know the proof
    # itself (not something else) is what's under test.
    original_digest = bytes.fromhex(genuine["body_digest"])
    assert cll.verify_inclusion(root, genuine["size"], genuine["leaf_index"], original_digest, proof)


def test_mutant_rolled_back_log_fails_consistency(proof_vectors):
    """Simulate a rollback-and-replay: an operator rewinds the log after
    size_a=11, appends *different* content, and ends up with a genuinely
    different root at size_b=22. They then try to reuse the ORIGINAL
    (size_a -> true size_b) consistency proof to vouch for the fork's root.

    The consistency proof is grounded in the true history -- its peaks
    re-bag to the true root_b, not the fork's -- so verify_consistency must
    reject the fork. This is the rollback detector the CLL verifier exists
    for: no live log, no operator cooperation required to catch it."""
    cc = proof_vectors["consistency_case"]
    assert cc["expect"] is True
    proof = cll.ConsistencyProof.from_dict(cc["proof"])
    root_a = bytes.fromhex(cc["root_a"])
    true_root_b = bytes.fromhex(cc["root_b"])

    # The fork's root: same size (22), different content after the rewind
    # point -- modeled here as the true root with one byte flipped, which is
    # indistinguishable in shape from a genuine alternate-history root (both
    # are "some other 32-byte value that isn't the true root_b").
    forked_root_b = bytes([true_root_b[0] ^ 0xFF]) + true_root_b[1:]
    assert forked_root_b != true_root_b

    ok = cll.verify_consistency(root_a, cc["size_a"], forked_root_b, cc["size_b"], proof)
    assert ok is False, (
        "rolled-back/forked log must fail consistency -- verifier accepted a replayed "
        "proof as evidence for a root it was never minted against"
    )

    # The genuine (non-rolled-back) extension must still verify.
    assert cll.verify_consistency(root_a, cc["size_a"], true_root_b, cc["size_b"], proof)


def test_verify_checkpoint_chain_rejects_the_rollback(proof_vectors):
    """Same rollback scenario, through the checkpoint-level orchestration
    (verify_checkpoint_chain) rather than the bare verify_consistency call
    -- confirms the honest ConsistencyVerification result actually surfaces
    the rejection, not just the pure function underneath it."""
    cc = proof_vectors["consistency_case"]
    proof = cll.ConsistencyProof.from_dict(cc["proof"])
    true_root_b = cc["root_b"]
    forked_root_b_bytes = bytes([bytes.fromhex(true_root_b)[0] ^ 0xFF]) + bytes.fromhex(true_root_b)[1:]

    older = cll.Checkpoint(
        v=1, kind="mmr_checkpoint", log_id="log-x", mmr_size=cc["size_a"], root=cc["root_a"],
        peaks_digest="", prev_size=0, prev_root="", key_id="node-x", timestamp="2026-08-21T00:00:00Z",
    )
    forked_newer = cll.Checkpoint(
        v=1, kind="mmr_checkpoint", log_id="log-x", mmr_size=cc["size_b"], root=forked_root_b_bytes.hex(),
        peaks_digest="", prev_size=cc["size_a"], prev_root=cc["root_a"], key_id="node-x",
        timestamp="2026-08-21T01:00:00Z",
    )
    result = cll.verify_checkpoint_chain(older, forked_newer, proof)
    assert result.ok is False
    assert result.errors, "rejection must be explained, not silent"

    genuine_newer = cll.Checkpoint(
        v=1, kind="mmr_checkpoint", log_id="log-x", mmr_size=cc["size_b"], root=true_root_b,
        peaks_digest="", prev_size=cc["size_a"], prev_root=cc["root_a"], key_id="node-x",
        timestamp="2026-08-21T01:00:00Z",
    )
    result2 = cll.verify_checkpoint_chain(older, genuine_newer, proof)
    assert result2.ok is True, result2.errors
    assert "witnessed up to size 22" in result2.status


# -- range: honestly scoped, never a completeness claim -----------------------


def test_range_proof_verifies_and_states_its_scope_honestly(proof_vectors):
    """[4, 12] is a *sub*-range (not starting at record 1) so the honesty
    caveat has something real to say: this proves records 4-12 are present
    and unaltered, and says nothing about records 1-3 or anything beyond 12."""
    root_hex = proof_vectors["full_root"]
    from_case = next(c for c in proof_vectors["inclusion_cases"] if c["leaf_index"] == 3)
    to_case = next(c for c in proof_vectors["inclusion_cases"] if c["leaf_index"] == 11)

    range_proof = cll.RangeProof(
        from_seq=4,
        to_seq=12,
        size=22,
        inclusion_from=cll.InclusionProof.from_dict(from_case["proof"]),
        inclusion_to=cll.InclusionProof.from_dict(to_case["proof"]),
    )
    checkpoint = cll.Checkpoint(
        v=1, kind="mmr_checkpoint", log_id="log-range", mmr_size=22, root=root_hex,
        peaks_digest="", prev_size=0, prev_root="", key_id="node-r", timestamp="2026-08-21T02:00:00Z",
    )

    result = cll.verify_range_against_checkpoint(
        from_seq=4,
        to_seq=12,
        from_digest=bytes.fromhex(from_case["body_digest"]),
        to_digest=bytes.fromhex(to_case["body_digest"]),
        checkpoint=checkpoint,
        proof=range_proof,
    )
    assert result.ok is True, result.errors
    assert "9 of 9" in result.scope_note
    assert "does NOT prove" in result.scope_note
    assert "range-intact != all-traffic" in result.scope_note
    assert "witnessed up to size 22" in result.status


def test_range_proof_mutant_tampered_boundary_fails(proof_vectors):
    root_hex = proof_vectors["full_root"]
    from_case = next(c for c in proof_vectors["inclusion_cases"] if c["leaf_index"] == 3)
    to_case = next(c for c in proof_vectors["inclusion_cases"] if c["leaf_index"] == 11)
    range_proof = cll.RangeProof(
        from_seq=4,
        to_seq=12,
        size=22,
        inclusion_from=cll.InclusionProof.from_dict(from_case["proof"]),
        inclusion_to=cll.InclusionProof.from_dict(to_case["proof"]),
    )
    checkpoint = cll.Checkpoint(
        v=1, kind="mmr_checkpoint", log_id="log-range", mmr_size=22, root=root_hex,
        peaks_digest="", prev_size=0, prev_root="", key_id="node-r", timestamp="2026-08-21T02:00:00Z",
    )
    # Wrong to_digest: claim record 12 was something it wasn't.
    wrong_to_digest = bytes.fromhex(proof_vectors["body_digests"][0])
    result = cll.verify_range_against_checkpoint(
        from_seq=4,
        to_seq=12,
        from_digest=bytes.fromhex(from_case["body_digest"]),
        to_digest=wrong_to_digest,
        checkpoint=checkpoint,
        proof=range_proof,
    )
    assert result.ok is False
    assert result.errors


# -- witness-lag honesty -------------------------------------------------


def test_witness_status_line_hides_nothing_when_lag_exists():
    line = cll.witness_status_line(22, "2026-08-21T02:00:00Z", current_size=25)
    assert line == (
        "witnessed up to size 22 at time 2026-08-21T02:00:00Z -- "
        "3 more entries appended since, not yet witnessed"
    )


def test_witness_status_line_is_plain_when_no_lag_is_known():
    line = cll.witness_status_line(22, "2026-08-21T02:00:00Z")
    assert line == "witnessed up to size 22 at time 2026-08-21T02:00:00Z"
    # And when the caller states current_size == mmr_size (fully caught up):
    line2 = cll.witness_status_line(22, "2026-08-21T02:00:00Z", current_size=22)
    assert "not yet witnessed" not in line2


# -- end-to-end offline: capsule + inclusion proof + witnessed checkpoint ----


def test_capsule_verifies_offline_end_to_end_via_witnessed_checkpoint(eddsa_keys):
    """The acceptance scenario: a capsule, its MMR inclusion proof, and a
    checkpoint witnessed by a Transparency-Service receipt verify together,
    offline, with no live log and no network call anywhere in this test.

    The TS receipt is minted here with scitt-cose's own build_receipt (an
    RFC 9162 tree of registered checkpoint digests -- exactly the shape a
    real TS, e.g. capsule-anchor, would produce) so this test needs nothing
    beyond what's already committed to this repo.
    """
    priv_pem, pub_pem = eddsa_keys
    pv = json.loads((VECTORS / "proof-vectors.json").read_text())

    leaf_case = next(c for c in pv["inclusion_cases"] if c["leaf_index"] == 0)
    inclusion_proof = cll.InclusionProof.from_dict(leaf_case["proof"])
    body_digest = bytes.fromhex(leaf_case["body_digest"])

    # peaks at size 22, left to right -- available directly as the
    # consistency_case's new_peaks (peaks at size_b=22).
    peak_hashes_hex = pv["consistency_case"]["proof"]["new_peaks"]
    peaks_digest = hashlib.sha256(b"".join(bytes.fromhex(h) for h in peak_hashes_hex)).hexdigest()

    checkpoint = cll.Checkpoint(
        v=1,
        kind="mmr_checkpoint",
        log_id="demo-log",
        mmr_size=22,
        root=pv["full_root"],
        peaks_digest=peaks_digest,
        prev_size=0,
        prev_root="",
        key_id="node-demo",
        timestamp="2026-08-21T03:00:00Z",
        signature="unverified-by-this-layer",  # opaque to this module, see cll.py boundary note
    )

    # Mint a synthetic TS log of registered checkpoint digests (as
    # capsule-anchor's /v1/digest endpoint would), with our checkpoint's
    # entry_hash at leaf_index=2 of a 5-entry tree.
    other_digests = [hashlib.sha256(f"other-checkpoint-{i}".encode()).hexdigest() for i in range(4)]
    ts_entries = other_digests[:2] + [checkpoint.ts_entry_hash()] + other_digests[2:]
    receipt = build_receipt(
        leaf_entry_hex=checkpoint.ts_entry_hash(),
        leaf_index=2,
        tree_entries_hex=ts_entries,
        alg="EdDSA",
        log_private_key_pem=priv_pem,
    )

    result = cll.verify_leaf_against_checkpoint(
        body_digest=body_digest,
        leaf_index=leaf_case["leaf_index"],
        checkpoint=checkpoint,
        proof=inclusion_proof,
        receipt=receipt,
        ts_public_key_pem=pub_pem,
        current_size=25,
    )
    assert result.ok is True, result.errors
    assert result.receipt_result is not None and result.receipt_result.ok
    assert result.status == (
        "witnessed up to size 22 at time 2026-08-21T03:00:00Z -- "
        "3 more entries appended since, not yet witnessed"
    )


def test_end_to_end_fails_offline_if_receipt_is_for_a_different_checkpoint(eddsa_keys):
    """The receipt-binding mutant: a receipt that genuinely verifies, but
    over a digest that does not match *this* checkpoint's own recomputed
    ts_entry_hash, must not be accepted -- otherwise any valid receipt for
    any checkpoint could be waved at an unrelated one."""
    priv_pem, pub_pem = eddsa_keys
    pv = json.loads((VECTORS / "proof-vectors.json").read_text())
    leaf_case = next(c for c in pv["inclusion_cases"] if c["leaf_index"] == 0)

    checkpoint = cll.Checkpoint(
        v=1, kind="mmr_checkpoint", log_id="demo-log", mmr_size=22, root=pv["full_root"],
        peaks_digest="", prev_size=0, prev_root="", key_id="node-demo",
        timestamp="2026-08-21T03:00:00Z",
    )

    unrelated_entries = [hashlib.sha256(f"unrelated-{i}".encode()).hexdigest() for i in range(4)]
    receipt = build_receipt(
        leaf_entry_hex=unrelated_entries[1],
        leaf_index=1,
        tree_entries_hex=unrelated_entries,
        alg="EdDSA",
        log_private_key_pem=priv_pem,
    )

    result = cll.verify_leaf_against_checkpoint(
        body_digest=bytes.fromhex(leaf_case["body_digest"]),
        leaf_index=leaf_case["leaf_index"],
        checkpoint=checkpoint,
        proof=cll.InclusionProof.from_dict(leaf_case["proof"]),
        receipt=receipt,
        ts_public_key_pem=pub_pem,
    )
    assert result.ok is False
    assert any("checkpoint receipt" in e for e in result.errors)
