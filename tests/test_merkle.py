# SPDX-License-Identifier: Apache-2.0
"""RFC 6962/9162 Merkle: root, inclusion, and consistency proofs."""
from __future__ import annotations

import hashlib

import pytest

from scitt_cose import merkle


def _entries(n):
    return [bytes([i, i, i]).hex() for i in range(n)]


def test_empty_root_is_sha256_empty():
    assert merkle.merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_single_leaf_root():
    e = b"hello".hex()
    expected = hashlib.sha256(b"\x00" + b"hello").hexdigest()
    assert merkle.merkle_root([e]) == expected


def test_two_leaf_root():
    a, b = b"a", b"b"
    la = hashlib.sha256(b"\x00" + a).digest()
    lb = hashlib.sha256(b"\x00" + b).digest()
    expected = hashlib.sha256(b"\x01" + la + lb).hexdigest()
    assert merkle.merkle_root([a.hex(), b.hex()]) == expected


def test_order_sensitive():
    assert merkle.merkle_root([b"a".hex(), b"b".hex()]) != merkle.merkle_root(
        [b"b".hex(), b"a".hex()]
    )


@pytest.mark.parametrize("n", range(1, 17))
def test_inclusion_all_indices(n):
    es = _entries(n)
    root = merkle.merkle_root(es)
    for i in range(n):
        path = merkle.inclusion_proof(es, i)
        assert merkle.verify_inclusion(es[i], i, n, path, root)


def test_inclusion_wrong_leaf_fails():
    es = _entries(8)
    root = merkle.merkle_root(es)
    path = merkle.inclusion_proof(es, 3)
    assert not merkle.verify_inclusion(b"nope".hex(), 3, 8, path, root)


def test_inclusion_wrong_index_fails():
    es = _entries(8)
    root = merkle.merkle_root(es)
    path = merkle.inclusion_proof(es, 3)
    assert not merkle.verify_inclusion(es[3], 4, 8, path, root)


def test_inclusion_tampered_path_fails():
    es = _entries(8)
    root = merkle.merkle_root(es)
    path = merkle.inclusion_proof(es, 3)
    path[0] = ("00" * 32)
    assert not merkle.verify_inclusion(es[3], 3, 8, path, root)


def test_inclusion_index_out_of_range_raises():
    es = _entries(4)
    with pytest.raises(IndexError):
        merkle.inclusion_proof(es, 4)


@pytest.mark.parametrize("n", range(1, 13))
def test_consistency_all_pairs(n):
    es = _entries(n)
    root_n = merkle.merkle_root(es)
    for m in range(0, n + 1):
        root_m = merkle.merkle_root(es[:m])
        proof = merkle.consistency_proof(es, m, n)
        assert merkle.verify_consistency(root_m, root_n, m, n, proof), (m, n)


def test_consistency_wrong_old_root_fails():
    es = _entries(7)
    root_n = merkle.merkle_root(es)
    proof = merkle.consistency_proof(es, 3, 7)
    bad_old = merkle.merkle_root(_entries(3)[::-1])  # different size-3 tree
    assert not merkle.verify_consistency(bad_old, root_n, 3, 7, proof)


def test_consistency_wrong_new_root_fails():
    es = _entries(7)
    root_m = merkle.merkle_root(es[:3])
    proof = merkle.consistency_proof(es, 3, 7)
    assert not merkle.verify_consistency(root_m, "00" * 32, 3, 7, proof)


def test_consistency_tampered_proof_fails():
    es = _entries(9)
    root_m = merkle.merkle_root(es[:4])
    root_n = merkle.merkle_root(es)
    proof = merkle.consistency_proof(es, 4, 9)
    assert proof
    proof[0] = "ff" * 32
    assert not merkle.verify_consistency(root_m, root_n, 4, 9, proof)


def test_consistency_m_zero_is_empty():
    es = _entries(5)
    assert merkle.consistency_proof(es, 0, 5) == []
    assert merkle.verify_consistency(
        merkle.merkle_root([]), merkle.merkle_root(es), 0, 5, []
    )


def test_consistency_m_equals_n():
    es = _entries(5)
    root = merkle.merkle_root(es)
    assert merkle.consistency_proof(es, 5, 5) == []
    assert merkle.verify_consistency(root, root, 5, 5, [])


def test_consistency_power_of_two_old_tree():
    # m a power of two exercises the "old root omitted from proof" branch.
    es = _entries(10)
    for m in (1, 2, 4, 8):
        root_m = merkle.merkle_root(es[:m])
        root_n = merkle.merkle_root(es)
        proof = merkle.consistency_proof(es, m, 10)
        assert merkle.verify_consistency(root_m, root_n, m, 10, proof), m
