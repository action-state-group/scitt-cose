#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME generator for ``test-vectors/mmr/range-vectors.json`` -- pins the
vanilla-JS range-membership port (``hosted_profiles.hosted``'s ``MMR_JS``'s
``verifyRange``) against checkpointed-local-log's Python reference
(``cll.checkpoint.core.range_proof``/``verify_range``), the CLL vectors this
script mints.

Not run in CI, no runtime dependency from scitt-cose on checkpointed-local-log
(``scitt_cose.cll.verify_range`` is a byte-identical PORT, never an import --
see that module's docstring for why the dependency would otherwise be
circular). Requires a local ``checkpointed-local-log`` checkout next to this
repo (``../checkpointed-local-log`` by default, override with
``--cll-path``) purely as a one-time, read-only oracle to mint the committed
JSON. The committed vectors are the artifact; re-running this script is only
for provenance / regenerating a future version.

Cases (positive): 1-leaf range, 3-leaf range, a range crossing multiple
peaks, and the from_seq=1 (leaf index 0) edge case.
Cases (negative): replaced interior leaf, deleted interior leaf (length
mismatch), sparse selection (right-shaped digest list, wrong window), and a
mismatched checkpoint root -- the exact bug class this task closes (a
two-boundary-inclusion proof never looked at these).
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "test-vectors" / "mmr"


def _load_cll(cll_path: Path):
    sys.path.insert(0, str(cll_path))
    from cll.checkpoint import core  # noqa: PLC0415
    from cll.checkpoint.store import MemoryNodeStore  # noqa: PLC0415

    return core, MemoryNodeStore


def _asdict_proof(p) -> dict:
    return dataclasses.asdict(p)


def generate_range_vectors(core, MemoryNodeStore) -> dict:
    store = MemoryNodeStore()
    n = 7
    body_digests = [hashlib.sha256(f"range-record-{i}".encode()).digest() for i in range(n)]
    for bd in body_digests:
        core.add_leaf(store, core.leaf_hash(bd))
    full_size = store.size()
    assert core.peaks(full_size) == [6, 9, 10]  # 7 leaves -> 3 mountains, heights [2, 1, 0]
    full_root = core.root_from_peaks([store.node(p) for p in core.peaks(full_size)])

    def make_case(name: str, from_index: int, to_index: int) -> dict:
        # `size` is fixed to node_count(to_index + 1) -- the MMR exactly as
        # it stood right after leaf `to_index` was appended -- matching the
        # convention MmrLedger.range_proof (and the seq-based verify_range
        # wrapper both here and in checkpointed-local-log's index.py) always
        # uses: verify_range's own `leaf_count(proof.size) == to_seq` check
        # requires it. A range proof against a larger/later checkpoint size
        # is reached via a separate consistency_proof bridge, not by minting
        # the range proof at that larger size directly.
        size = core.node_count(to_index + 1)
        root = core.root_from_peaks([store.node(p) for p in core.peaks(size)])
        proof = core.range_proof(store, from_index, to_index, size)
        digests = body_digests[from_index : to_index + 1]
        assert core.verify_range(root, size, from_index, to_index, digests, proof)
        return {
            "name": name,
            "from_seq": from_index + 1,
            "to_seq": to_index + 1,
            "size": size,
            "root": root.hex(),
            "body_digests": [d.hex() for d in digests],
            "proof": _asdict_proof(proof),
            "expect": True,
        }

    range_cases = [
        make_case("single-leaf", 4, 4),
        make_case("three-leaf", 2, 4),
        make_case("first-leaf", 0, 2),
        make_case("cross-peak", 1, 6),  # spans all 3 mountains (peaks at positions 6, 9, 10)
    ]

    # -- negative cases: same genuine proof, tampered/mismatched inputs ------
    base = make_case("interior-tamper-base", 2, 6)
    negative_cases = []

    replaced = list(base["body_digests"])
    tampered = bytearray(bytes.fromhex(replaced[2]))  # seq 5 -- strictly interior of [3,7]
    tampered[0] ^= 0xFF
    replaced[2] = tampered.hex()
    negative_cases.append({
        "label": "replaced-interior-record",
        "from_seq": base["from_seq"], "to_seq": base["to_seq"], "size": base["size"],
        "root": base["root"], "body_digests": replaced, "proof": base["proof"],
    })

    deleted = base["body_digests"][:2] + base["body_digests"][3:]  # drop seq 5
    negative_cases.append({
        "label": "deleted-interior-record",
        "from_seq": base["from_seq"], "to_seq": base["to_seq"], "size": base["size"],
        "root": base["root"], "body_digests": deleted, "proof": base["proof"],
    })

    sparse_source = make_case("sparse-source", 1, 5)  # right shape (5 digests), wrong window
    negative_cases.append({
        "label": "sparse-selection-wrong-window",
        "from_seq": base["from_seq"], "to_seq": base["to_seq"], "size": base["size"],
        "root": base["root"], "body_digests": sparse_source["body_digests"], "proof": base["proof"],
    })

    wrong_root = bytes(range(32)).hex()
    negative_cases.append({
        "label": "mismatched-checkpoint-root",
        "from_seq": base["from_seq"], "to_seq": base["to_seq"], "size": base["size"],
        "root": wrong_root, "body_digests": base["body_digests"], "proof": base["proof"],
    })

    for case in negative_cases:
        proof_obj = core.RangeProof(**case["proof"])
        assert not core.verify_range(
            bytes.fromhex(case["root"]),
            case["size"],
            proof_obj.from_index,
            proof_obj.to_index,
            [bytes.fromhex(d) for d in case["body_digests"]],
            proof_obj,
        ), f"negative case {case['label']!r} unexpectedly verified"

    return {
        "_provenance": (
            "Self-generated (not upstream) -- 9 leaves, real leaf_hash, arbitrary body "
            "digests, minted by cll.checkpoint.core.range_proof and confirmed to verify "
            "(positives) or correctly fail (negatives) under the Python reference before "
            "export. Pins the ported verifyRange *behavior*: "
            "every leaf in the claimed range participates in rebuilding the "
            "root, not just the two boundary leaves, so a deleted or replaced interior "
            "record is caught."
        ),
        "body_digests": [d.hex() for d in body_digests],
        "full_size": full_size,
        "full_root": full_root.hex(),
        "range_cases": range_cases,
        "negative_range_cases": negative_cases,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cll-path", default=str(REPO.parent / "checkpointed-local-log"))
    ap.add_argument("--force", action="store_true", help="overwrite existing committed vectors")
    args = ap.parse_args()

    cll_path = Path(args.cll_path).resolve()
    if not (cll_path / "cll" / "checkpoint" / "core.py").exists():
        print(f"checkpointed-local-log checkout not found at {cll_path}", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "range-vectors.json"
    if not args.force and out.exists():
        print("committed vectors already exist -- pass --force to regenerate", file=sys.stderr)
        return 2

    core, MemoryNodeStore = _load_cll(cll_path)
    out.write_text(json.dumps(generate_range_vectors(core, MemoryNodeStore), indent=2) + "\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
