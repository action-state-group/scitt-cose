# SPDX-License-Identifier: Apache-2.0
"""Conformance against the STANDARD's own published test vectors (RFC 6962 / 9162).

Cross-language agreement with our own Go verifier cures *self-consistency*. But a
community verifier also needs to agree with the *ecosystem's reference values* —
not just with a second implementation we wrote. These are the canonical RFC 6962
(SHA-256) Merkle test vectors used by the Certificate Transparency reference and
by Google's Trillian: the same leaf inputs, root hashes, inclusion proofs and
consistency proofs that every conformant CT/SCITT log is checked against.

The constants below are EXTERNAL reference values (published by the standard /
its reference implementations), so this test anchors our Merkle code to the
ecosystem, independent of our own emitter. RFC 9162 reuses the RFC 6962 SHA-256
Merkle Tree Hash, so these are the vectors a SCITT Receipt's inclusion proof
ultimately rests on.
"""
from __future__ import annotations

from scitt_cose import (
    consistency_proof,
    inclusion_proof,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)

# Canonical RFC 6962 test entries d0..d7 (hex of each leaf's raw input bytes).
LEAVES = [
    "",  # d0 (empty input)
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
]

# --- Published Merkle Tree Hash roots (RFC 6962 reference / Trillian) --------
EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ONE_LEAF_ROOT = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
EIGHT_LEAF_ROOT = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"

# --- Published inclusion proofs in the 8-entry tree -------------------------
INCLUSION_0_8 = [
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
]
INCLUSION_5_8 = [
    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
]

# --- Published consistency proofs -------------------------------------------
CONSISTENCY_1_8 = [
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
]
CONSISTENCY_6_8 = [
    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
]
CONSISTENCY_2_5 = [
    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
]


def test_published_roots():
    assert merkle_root([]) == EMPTY_ROOT
    assert merkle_root(LEAVES[:1]) == ONE_LEAF_ROOT
    assert merkle_root(LEAVES) == EIGHT_LEAF_ROOT


def test_published_inclusion_proofs():
    assert inclusion_proof(LEAVES, 0) == INCLUSION_0_8
    assert inclusion_proof(LEAVES, 5) == INCLUSION_5_8
    # And they verify against the published root.
    assert verify_inclusion(LEAVES[0], 0, 8, INCLUSION_0_8, EIGHT_LEAF_ROOT)
    assert verify_inclusion(LEAVES[5], 5, 8, INCLUSION_5_8, EIGHT_LEAF_ROOT)


def test_published_consistency_proofs():
    assert consistency_proof(LEAVES, 1, 8) == CONSISTENCY_1_8
    assert consistency_proof(LEAVES, 6, 8) == CONSISTENCY_6_8
    assert consistency_proof(LEAVES[:5], 2, 5) == CONSISTENCY_2_5
    # And they verify between the published sub-roots.
    assert verify_consistency(
        merkle_root(LEAVES[:1]), EIGHT_LEAF_ROOT, 1, 8, CONSISTENCY_1_8
    )
    assert verify_consistency(
        merkle_root(LEAVES[:6]), EIGHT_LEAF_ROOT, 6, 8, CONSISTENCY_6_8
    )
    assert verify_consistency(
        merkle_root(LEAVES[:2]), merkle_root(LEAVES[:5]), 2, 5, CONSISTENCY_2_5
    )
