#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME generator for ``test-vectors/mmr/*.json`` — the vectors that pin
the vanilla-JS MMR completeness-certificate port (``hosted_profiles.hosted``'s
``MMR_JS``) against capsule-ledger's Python reference (``asg_ledger.mmr.core``).

This script is NOT run in CI and has NO runtime dependency from scitt-cose on
capsule-ledger (scitt-cose stays vendor-neutral; MMR is capsule-ledger's
concept, never scitt-cose's). It requires a local ``capsule-ledger`` checkout
next to this repo (``../capsule-ledger`` by default, override with
``--capsule-ledger-path``) purely as a one-time, read-only oracle to mint the
committed JSON. The committed vectors are the artifact; re-running this script
is only for provenance / regenerating a future version, exactly like
``scripts/generate_test_vectors.py``'s v1 set.

Two files are produced:

* ``kat39.json`` — the upstream MMRIVER-draft 39-node KAT (originally
  ``go-datatrails-merklelog``'s ``mmr/draft_kat39_test.go``, MIT licensed,
  copied into capsule-ledger's ``tests/test_mmr_kat39.py``), replayed through
  ``asg_ledger.mmr.core.add_leaf`` and re-exported here so the JS port's
  ``interiorHash``/``rootFromPeaks``/``peaks``/``heightAt`` primitives can be
  checked byte-for-byte against the same published node array. ``root_full``
  is *not* an upstream-pinned value (see ``core.py``'s own docstring caveat)
  — it is a Python/JS cross-language parity check only.
* ``proof-vectors.json`` — a fresh, self-generated 22-node MMR (12 leaves,
  real ``leaf_hash``, arbitrary body digests) with real ``InclusionProof`` /
  ``ConsistencyProof`` objects from ``core.inclusion_proof`` /
  ``core.consistency_proof``, each confirmed to verify under the Python
  reference before being written out. This is what pins the *behavior* of
  the ported ``verifyInclusion``/``verifyConsistency`` (not just the low-level
  hash primitives the KAT39 set covers).
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "test-vectors" / "mmr"


def _load_capsule_ledger(cl_path: Path):
    sys.path.insert(0, str(cl_path))
    from asg_ledger.mmr import core  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("_kat39_ref", cl_path / "tests" / "test_mmr_kat39.py")
    kat39 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kat39)
    return core, kat39


def _asdict_proof(p) -> dict:
    return dataclasses.asdict(p)


def generate_kat39(core, kat39) -> dict:
    from asg_ledger.mmr.store import MemoryNodeStore  # noqa: PLC0415

    store = MemoryNodeStore()
    interior_triples = []  # (left_hex, right_hex, parent_pos, result_hex) -- pure interior_hash KAT data
    for leaf_hex in kat39.KAT39_LEAVES:
        leaf = bytes.fromhex(leaf_hex)
        size = store.size()
        leaf_pos = size
        new_nodes = [leaf]
        existing_peaks = [] if size == 0 else core.peaks(size)
        peak_idx = len(existing_peaks) - 1
        height = 0
        cur_hash = leaf
        while peak_idx >= 0 and core.height_at(existing_peaks[peak_idx]) == height:
            left_pos = existing_peaks[peak_idx]
            left_hash = store.node(left_pos)
            parent_pos = leaf_pos + len(new_nodes)
            parent_hash = core.interior_hash(left_hash, cur_hash, parent_pos)
            interior_triples.append({
                "left": left_hash.hex(), "right": cur_hash.hex(),
                "position": parent_pos, "result": parent_hash.hex(),
            })
            new_nodes.append(parent_hash)
            cur_hash = parent_hash
            height += 1
            peak_idx -= 1
        store.append_nodes(new_nodes)

    assert store.size() == len(kat39.KAT39_NODES)
    assert [store.node(i).hex() for i in range(store.size())] == kat39.KAT39_NODES

    root_full = core.root_from_peaks([store.node(p) for p in core.peaks(store.size())])
    return {
        "_provenance": (
            "leaves/nodes/peak_indices/peak_hashes copied verbatim (attributed) from "
            "datatrails/go-datatrails-merklelog mmr/draft_kat39_test.go via capsule-ledger's "
            "tests/test_mmr_kat39.py. interior_triples/root_full are derived by replaying "
            "asg_ledger.mmr.core's add_leaf/interior_hash/root_from_peaks over the same leaves -- "
            "a Python/JS cross-language parity check, not independently upstream-pinned (see "
            "asg_ledger/mmr/core.py's own docstring caveat on root_from_peaks's provenance)."
        ),
        "leaves": kat39.KAT39_LEAVES,
        "nodes": kat39.KAT39_NODES,
        "peak_indices": {str(k): v for k, v in kat39.KAT39_PEAK_INDICES.items()},
        "peak_hashes": {str(k): v for k, v in kat39.KAT39_PEAK_HASHES.items()},
        "interior_triples": interior_triples,
        "root_full": root_full.hex(),
    }


def generate_proof_vectors(core) -> dict:
    from asg_ledger.mmr.store import MemoryNodeStore  # noqa: PLC0415

    store = MemoryNodeStore()
    body_digests = [hashlib.sha256(f"record-{i}".encode()).digest() for i in range(12)]
    for bd in body_digests:
        core.add_leaf(store, core.leaf_hash(bd))

    def root_at(size: int) -> str:
        return core.root_from_peaks([store.node(p) for p in core.peaks(size)]).hex()

    sizes_after_n = {}
    scratch = MemoryNodeStore()
    for i, bd in enumerate(body_digests):
        core.add_leaf(scratch, core.leaf_hash(bd))
        sizes_after_n[i + 1] = scratch.size()

    full_size = store.size()
    full_root = root_at(full_size)

    inclusion_cases = []
    for leaf_index in (0, 3, 7, 11):
        proof = core.inclusion_proof(store, leaf_index, full_size)
        assert core.verify_inclusion(
            bytes.fromhex(full_root), full_size, leaf_index, body_digests[leaf_index], proof
        )
        inclusion_cases.append({
            "leaf_index": leaf_index,
            "size": full_size,
            "body_digest": body_digests[leaf_index].hex(),
            "proof": _asdict_proof(proof),
            "root": full_root,
            "expect": True,
        })

    size_a = sizes_after_n[7]
    size_b = full_size
    root_a = root_at(size_a)
    root_b = full_root
    cproof = core.consistency_proof(store, size_a, size_b)
    assert core.verify_consistency(bytes.fromhex(root_a), size_a, bytes.fromhex(root_b), size_b, cproof)

    return {
        "_provenance": (
            "Self-generated (not upstream) -- 12 leaves, real leaf_hash, arbitrary body "
            "digests, minted by asg_ledger.mmr.core.inclusion_proof/consistency_proof and "
            "confirmed to verify under the Python reference before export. Pins the ported "
            "verifyInclusion/verifyConsistency *behavior*, not just the hash primitives."
        ),
        "body_digests": [b.hex() for b in body_digests],
        "full_size": full_size,
        "full_root": full_root,
        "inclusion_cases": inclusion_cases,
        "consistency_case": {
            "size_a": size_a,
            "root_a": root_a,
            "size_b": size_b,
            "root_b": root_b,
            "proof": _asdict_proof(cproof),
            "expect": True,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--capsule-ledger-path", default=str(REPO.parent / "capsule-ledger"))
    ap.add_argument("--force", action="store_true", help="overwrite existing committed vectors")
    args = ap.parse_args()

    cl_path = Path(args.capsule_ledger_path).resolve()
    if not (cl_path / "asg_ledger" / "mmr" / "core.py").exists():
        print(f"capsule-ledger checkout not found at {cl_path}", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    kat39_out = OUT_DIR / "kat39.json"
    proofs_out = OUT_DIR / "proof-vectors.json"
    if not args.force and (kat39_out.exists() or proofs_out.exists()):
        print("committed vectors already exist -- pass --force to regenerate", file=sys.stderr)
        return 2

    core, kat39 = _load_capsule_ledger(cl_path)
    kat39_out.write_text(json.dumps(generate_kat39(core, kat39), indent=2) + "\n")
    proofs_out.write_text(json.dumps(generate_proof_vectors(core), indent=2) + "\n")
    print(f"wrote {kat39_out}\nwrote {proofs_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
