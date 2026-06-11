# SPDX-License-Identifier: Apache-2.0
"""COSE Receipt build/verify (detached + attached) and negatives."""
from __future__ import annotations

import cbor2
import pytest

from scitt_cose import merkle
from scitt_cose.cose_sign1 import CoseError
from scitt_cose.receipt import (
    HDR_VDP,
    HDR_VDS,
    VDS_RFC9162_SHA256,
    build_receipt,
    verify_receipt,
)


def _entries(n):
    return [bytes([i, 7, i]).hex() for i in range(n)]


def test_build_verify_detached(alg_keys):
    alg, priv, pub = alg_keys
    es = _entries(6)
    idx = 4
    receipt = build_receipt(
        leaf_entry_hex=es[idx], leaf_index=idx, tree_entries_hex=es,
        alg=alg, log_private_key_pem=priv, detached=True,
    )
    res = verify_receipt(receipt, leaf_entry_hex=es[idx], log_public_key_pem=pub)
    assert res.ok, res.errors
    assert res.root == merkle.merkle_root(es)
    assert res.tree_size == 6
    assert res.leaf_index == 4


def test_build_verify_attached(alg_keys):
    alg, priv, pub = alg_keys
    es = _entries(5)
    idx = 2
    receipt = build_receipt(
        leaf_entry_hex=es[idx], leaf_index=idx, tree_entries_hex=es,
        alg=alg, log_private_key_pem=priv, detached=False,
    )
    # payload slot must carry the root bytes
    payload = cbor2.loads(receipt).value[2]
    assert payload == bytes.fromhex(merkle.merkle_root(es))
    res = verify_receipt(receipt, leaf_entry_hex=es[idx], log_public_key_pem=pub)
    assert res.ok, res.errors


def test_vds_in_protected_and_vdp_shape(eddsa_keys):
    priv, _pub = eddsa_keys
    es = _entries(4)
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    protected_bstr, unprotected, _payload, _sig = cbor2.loads(receipt).value
    protected = cbor2.loads(protected_bstr)
    assert protected[HDR_VDS] == VDS_RFC9162_SHA256
    vdp = unprotected[HDR_VDP]
    inclusion = vdp[-1]
    assert isinstance(inclusion, (list, tuple)) and len(inclusion) == 1  # cbor2>=6: tuple
    tree_size, leaf_index, path = cbor2.loads(inclusion[0])
    assert tree_size == 4 and leaf_index == 1
    assert all(isinstance(p, bytes) for p in path)


def test_wrong_leaf_fails(eddsa_keys):
    priv, pub = eddsa_keys
    es = _entries(6)
    receipt = build_receipt(
        leaf_entry_hex=es[3], leaf_index=3, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    res = verify_receipt(receipt, leaf_entry_hex=b"wrong".hex(), log_public_key_pem=pub)
    assert not res.ok
    assert res.errors


def test_wrong_log_key_fails(eddsa_keys, other_eddsa_keys):
    priv, _pub = eddsa_keys
    _o, opub = other_eddsa_keys
    es = _entries(6)
    receipt = build_receipt(
        leaf_entry_hex=es[3], leaf_index=3, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    res = verify_receipt(receipt, leaf_entry_hex=es[3], log_public_key_pem=opub)
    assert not res.ok
    assert any("signature" in e for e in res.errors)


def test_tampered_proof_fails(eddsa_keys):
    priv, pub = eddsa_keys
    es = _entries(8)
    receipt = build_receipt(
        leaf_entry_hex=es[5], leaf_index=5, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    # corrupt the first audit-path node inside the vdp (rebuild — cbor2>=6 yields
    # immutable frozendict/tuple, so copy each level before mutating)
    protected_bstr, unprotected, payload, sig = cbor2.loads(receipt).value
    unprotected = dict(unprotected)
    vdp = dict(unprotected[HDR_VDP])
    proofs = list(vdp[-1])
    ts, li, path = cbor2.loads(proofs[0])
    path = list(path)
    path[0] = b"\xff" * 32
    proofs[0] = cbor2.dumps([ts, li, path])
    vdp[-1] = proofs
    unprotected[HDR_VDP] = vdp
    tampered = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, unprotected, payload, sig]))
    res = verify_receipt(tampered, leaf_entry_hex=es[5], log_public_key_pem=pub)
    assert not res.ok


def test_bad_vds_rejected(eddsa_keys):
    priv, pub = eddsa_keys
    es = _entries(4)
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    protected_bstr, unprotected, payload, sig = cbor2.loads(receipt).value
    protected = cbor2.loads(protected_bstr)
    protected[HDR_VDS] = 999
    tampered = cbor2.dumps(
        cbor2.CBORTag(18, [cbor2.dumps(protected), unprotected, payload, sig])
    )
    res = verify_receipt(tampered, leaf_entry_hex=es[1], log_public_key_pem=pub)
    assert not res.ok
    assert any("vds" in e for e in res.errors)


def test_build_leaf_mismatch_raises(eddsa_keys):
    priv, _pub = eddsa_keys
    es = _entries(4)
    with pytest.raises(CoseError):
        build_receipt(
            leaf_entry_hex=b"nope".hex(), leaf_index=1, tree_entries_hex=es,
            alg="EdDSA", log_private_key_pem=priv,
        )


def test_verify_receipt_survives_cbor2_6_immutable_output(monkeypatch, eddsa_keys):
    """Regression (surfaced by the leon<->manny bilateral test): cbor2>=6 returns
    CBOR maps as ``frozendict`` (not a dict subclass) and arrays as ``tuple``.
    verify_receipt must still parse such output. We build with normal cbor2 then
    verify under simulated cbor2>=6 decoding."""
    import hashlib
    from collections.abc import Mapping

    import cbor2

    from scitt_cose import build_receipt, verify_receipt

    class FrozenDict(Mapping):  # mimics cbor2>=6 frozendict: a Mapping, not a dict
        def __init__(self, d):
            self._d = dict(d)
        def __getitem__(self, k):
            return self._d[k]
        def __iter__(self):
            return iter(self._d)
        def __len__(self):
            return len(self._d)

    priv, pub = eddsa_keys
    entries = [hashlib.sha256(f"e{i}".encode()).hexdigest() for i in range(5)]
    leaf = entries[2]
    receipt = build_receipt(
        leaf_entry_hex=leaf, leaf_index=2, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv,
    )

    real = cbor2.loads

    def _freeze(v):
        if isinstance(v, (bytes, bytearray, str)):
            return v
        if isinstance(v, dict):
            return FrozenDict({k: _freeze(x) for k, x in v.items()})
        if isinstance(v, (list, tuple)):
            return tuple(_freeze(x) for x in v)
        return v

    def fake_loads(b, *a, **k):
        out = real(b, *a, **k)
        if isinstance(out, cbor2.CBORTag):
            return cbor2.CBORTag(out.tag, _freeze(out.value))
        return _freeze(out)

    monkeypatch.setattr(cbor2, "loads", fake_loads)
    r = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert r.ok, r.errors
