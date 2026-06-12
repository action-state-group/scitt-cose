# SPDX-License-Identifier: Apache-2.0
"""RFC 6962 / RFC 9162 SHA-256 Merkle-tree primitives (clean-room).

The tree is built over an ordered list of *entries*. Each entry is supplied as a
hex string of raw bytes; this module does the domain-separated hashing:

* leaf hash   : ``SHA-256(0x00 || entry_bytes)``           (RFC 6962 §2.1)
* interior    : ``SHA-256(0x01 || left || right)``         over raw 32-byte hashes
* empty tree  : ``SHA-256("")``                            (RFC 6962 §2.1)

Odd levels use the RFC 6962 recursive split: for ``n > 1`` leaves let ``k`` be
the largest power of two strictly less than ``n``; the left subtree is the first
``k`` leaves, the right subtree the remaining ``n - k``.

All public inputs and outputs are lowercase hex strings. This is an independent
implementation (no external Merkle / transparency library is imported), and it
includes both inclusion (§2.1.1) and consistency (§2.1.2) proofs.
"""
from __future__ import annotations

import hashlib

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

#: Largest tree size a verifier will entertain from an attacker-supplied proof.
#: 2**62 is the largest power of two that is representable as a positive int64
#: (max 2**63 - 1), so the Python and the cross-language Go verifier share the
#: EXACT same ceiling and agree on accept/reject for every tree_size — there is
#: no band one accepts and the other cannot represent. It keeps the inclusion-
#: proof depth (and the fold's recursion depth) at most 62, well under any stack
#: limit. No real transparency log approaches this; it exists purely to bound the
#: cost of a hostile proof before any hashing/recursion happens.
MAX_TREE_SIZE = 1 << 62


def _leaf_hash_bytes(entry: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_pow2_below(n: int) -> int:
    """k = largest power of two strictly less than n (requires n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over already-computed leaf hashes."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return _node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def leaf_hash(entry_hex: str) -> str:
    """RFC 6962 leaf hash of a single entry (hex in, hex out)."""
    return _leaf_hash_bytes(bytes.fromhex(entry_hex)).hex()


def merkle_root(entries_hex: list[str]) -> str:
    """RFC 6962 Merkle root over an ordered list of hex entries.

    Order-sensitive and deterministic. An empty list yields ``SHA-256("")``.
    Returns a 64-char lowercase hex string.
    """
    leaves = [_leaf_hash_bytes(bytes.fromhex(e)) for e in entries_hex]
    return _mth(leaves).hex()


def inclusion_proof(entries_hex: list[str], index: int) -> list[str]:
    """RFC 6962 §2.1.1 inclusion (audit) path for ``entries_hex[index]``.

    Returns the ordered list of sibling node hashes (hex), bottom-up, needed to
    recompute the root from the leaf at ``index``.
    """
    n = len(entries_hex)
    if not 0 <= index < n:
        raise IndexError(f"index {index} out of range for {n} entries")
    leaves = [_leaf_hash_bytes(bytes.fromhex(e)) for e in entries_hex]

    def path(sub: list[bytes], m: int) -> list[bytes]:
        if len(sub) == 1:
            return []
        k = _largest_pow2_below(len(sub))
        if m < k:
            return path(sub[:k], m) + [_mth(sub[k:])]
        return path(sub[k:], m - k) + [_mth(sub[:k])]

    return [node.hex() for node in path(leaves, index)]


def _expected_inclusion_path_len(tree_size: int, index: int) -> int:
    """Exact number of audit-path siblings for ``index`` in an RFC 6962 tree of
    ``tree_size`` entries — i.e. the leaf's depth under the recursive split."""
    n = 0
    size, m = tree_size, index
    while size > 1:
        k = _largest_pow2_below(size)
        if m < k:
            size = k
        else:
            size, m = size - k, m - k
        n += 1
    return n


def root_from_inclusion_proof(
    leaf_entry_hex: str,
    index: int,
    tree_size: int,
    audit_path_hex: list[str],
) -> str | None:
    """Fold a leaf up its RFC 6962 §2.1.1 audit path to the root, or ``None``.

    Returns the reconstructed root hex if the leaf at ``index`` (in a tree of
    ``tree_size`` entries) combined with ``audit_path_hex`` yields a single root;
    ``None`` if the index, ``tree_size``, or path length is inconsistent.

    Resource safety: ``tree_size`` is rejected above :data:`MAX_TREE_SIZE`, and
    the audit path **must** be exactly the expected length for ``(tree_size,
    index)`` before any hashing. This makes the proof length an explicit checked
    invariant (not an emergent property of the recursion) and bounds the fold's
    recursion depth to at most 63 — so a hostile ``tree_size`` / over-long path
    can neither forge an inclusion nor exhaust the stack.
    """
    if not 0 <= index < tree_size or tree_size > MAX_TREE_SIZE:
        return None
    if len(audit_path_hex) != _expected_inclusion_path_len(tree_size, index):
        return None
    target = _leaf_hash_bytes(bytes.fromhex(leaf_entry_hex))
    siblings = list(audit_path_hex)

    def fold(size: int, m: int) -> bytes | None:
        if size == 1:
            return target
        if not siblings:
            return None
        k = _largest_pow2_below(size)
        sibling = bytes.fromhex(siblings.pop())  # outermost sibling at this level
        if m < k:
            child = fold(k, m)
            return None if child is None else _node_hash(child, sibling)
        child = fold(size - k, m - k)
        return None if child is None else _node_hash(sibling, child)

    computed = fold(tree_size, index)
    if computed is None or siblings:
        return None
    return computed.hex()


def verify_inclusion(
    leaf_entry_hex: str,
    index: int,
    tree_size: int,
    audit_path_hex: list[str],
    root_hex: str,
) -> bool:
    """Verify an RFC 6962 §2.1.1 inclusion proof.

    ``leaf_entry_hex`` is the *entry* (not its leaf hash) claimed at ``index`` in
    a tree of ``tree_size`` entries; ``audit_path_hex`` is the sibling list from
    :func:`inclusion_proof`. Returns ``True`` iff the path reconstructs
    ``root_hex``.
    """
    computed = root_from_inclusion_proof(leaf_entry_hex, index, tree_size, audit_path_hex)
    return computed is not None and computed == root_hex


# ---------------------------------------------------------------------------
# RFC 6962 §2.1.2 consistency proof
# ---------------------------------------------------------------------------
#
# PROOF(m, D[n]) for 0 < m < n is defined recursively in the RFC via the helper
# SUBPROOF(m, D[n], b) where b indicates whether the subtree rooted at the
# current node is "on the path" of the older (size-m) tree's right edge.


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        # The subtree is fully contained in the older tree.
        return [] if b else [_mth(leaves)]
    # m < n here.
    k = _largest_pow2_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [_mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [_mth(leaves[:k])]


def consistency_proof(entries_hex: list[str], m: int, n: int) -> list[str]:
    """RFC 6962 §2.1.2 consistency proof between sizes ``m`` and ``n``.

    Proves that the size-``m`` tree is a prefix of the size-``n`` tree.
    ``entries_hex`` must contain at least ``n`` entries (the first ``n`` are
    used). Returns the hex proof node list. ``m == 0`` yields an empty proof
    (the empty tree is trivially consistent with any tree); ``m == n`` likewise.
    """
    if not 0 <= m <= n:
        raise ValueError(f"require 0 <= m <= n; got m={m}, n={n}")
    if n > len(entries_hex):
        raise ValueError(f"need at least n={n} entries, have {len(entries_hex)}")
    if m == 0 or m == n:
        return []
    leaves = [_leaf_hash_bytes(bytes.fromhex(e)) for e in entries_hex[:n]]
    # Per the RFC, the top-level call uses b = True (the size-m subtree starts at
    # the complete left edge of the older tree).
    return [node.hex() for node in _subproof(m, leaves, True)]


def verify_consistency(
    first_root_hex: str,
    second_root_hex: str,
    first_size: int,
    second_size: int,
    proof_hex: list[str],
) -> bool:
    """Verify an RFC 6962 §2.1.2 consistency proof.

    Returns ``True`` iff ``proof_hex`` proves that the size-``first_size`` tree
    (root ``first_root_hex``) is a prefix of the size-``second_size`` tree (root
    ``second_root_hex``).
    """
    m, n = first_size, second_size
    if m < 0 or n < 0 or m > n:
        return False
    if m == 0:
        # Empty old tree: nothing to prove; proof must be empty.
        return not proof_hex
    if m == n:
        # Same tree: roots must match and proof must be empty (RFC convention).
        return not proof_hex and first_root_hex == second_root_hex

    proof = [bytes.fromhex(h) for h in proof_hex]

    # RFC 6962 §2.1.2 verification algorithm (the canonical CT formulation).
    # When the old tree is a perfect subtree (m is a power of two), its root is
    # omitted from the proof and seeded directly; otherwise the first proof node
    # IS the old subtree root used to seed both reconstructions.
    if m & (m - 1) == 0:  # m is a power of two
        proof = [bytes.fromhex(first_root_hex)] + proof
    if not proof:
        return False

    fn, sn = m - 1, n - 1
    # Shift past the bits where the old and new trees share the same right edge.
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = proof[0]
    sr = proof[0]
    for node in proof[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = _node_hash(node, fr)
            sr = _node_hash(node, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = _node_hash(sr, node)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr.hex() == first_root_hex and sr.hex() == second_root_hex


__all__ = [
    "leaf_hash",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "root_from_inclusion_proof",
    "consistency_proof",
    "verify_consistency",
    "MAX_TREE_SIZE",
]
