# SPDX-License-Identifier: Apache-2.0
"""COSE Receipt build/verify (detached + attached) and negatives."""
from __future__ import annotations

import cbor2
import pytest

from scitt_cose import merkle
from scitt_cose.cose_sign1 import CoseError
from scitt_cose.receipt import (
    CWT_CLAIM_IAT,
    HDR_CWT_CLAIMS,
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
    """Regression (surfaced by a cross-instance verification test): cbor2>=6
    returns CBOR maps as ``frozendict`` (not a dict subclass) and arrays as
    ``tuple``. verify_receipt must still parse such output. We build with normal
    cbor2 then verify under simulated cbor2>=6 decoding."""
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


# ---------------------------------------------------------------------------
# 0.3.0 — iat + protected_header_ext surfacing
# ---------------------------------------------------------------------------

def _inject_protected(receipt: bytes, extra_protected: dict) -> bytes:
    """Rebuild a receipt bytes with additional protected-header entries.

    Injects ``extra_protected`` into the signed protected header and strips the
    signature (so the result is structurally valid CBOR but the signature will
    NOT verify). Used to test surfacing of protected-header fields before the
    sig-verify step.  To also produce a *verifiable* receipt the caller must
    re-sign; for surfacing tests we only need structural validity up to the
    sig-check step — so tests that assert on iat/protected_header_ext MUST NOT
    assert ``r.ok``.
    """
    tag = cbor2.loads(receipt)
    protected_bstr, unprotected, payload, sig = tag.value
    ph = cbor2.loads(protected_bstr)
    ph.update(extra_protected)
    new_protected_bstr = cbor2.dumps(ph)
    return cbor2.dumps(cbor2.CBORTag(18, [new_protected_bstr, unprotected, payload, sig]))


def _build_receipt_with_protected(
    extra_protected: dict,
    alg: str,
    priv: bytes,
    pub: bytes,
) -> tuple[bytes, list[str], str]:
    """Build a properly-signed receipt that includes ``extra_protected`` in the
    protected header, returning ``(receipt_bytes, entries, leaf_hex)``."""
    import hashlib

    from scitt_cose.cose_sign1 import sign_sign1
    from scitt_cose.merkle import inclusion_proof, merkle_root
    from scitt_cose.receipt import (
        HDR_VDP,
        HDR_VDS,
        VDP_INCLUSION_PROOFS,
        VDS_RFC9162_SHA256,
        _encode_inclusion_proof,
    )

    entries = [hashlib.sha256(f"e{i}".encode()).hexdigest() for i in range(4)]
    idx = 1
    root_hex = merkle_root(entries)
    audit_path = inclusion_proof(entries, idx)
    inclusion_blob = _encode_inclusion_proof(len(entries), idx, audit_path)

    protected = {HDR_VDS: VDS_RFC9162_SHA256}
    protected.update(extra_protected)
    unprotected = {HDR_VDP: {VDP_INCLUSION_PROOFS: [inclusion_blob]}}

    receipt = sign_sign1(
        bytes.fromhex(root_hex),
        alg=alg,
        private_key_pem=priv,
        protected=protected,
        unprotected=unprotected,
        detached=True,
    )
    return receipt, entries, entries[idx]


def test_iat_surfaced_when_present(eddsa_keys):
    """A receipt signed with iat in the CWT claims map surfaces it in ReceiptResult."""
    priv, pub = eddsa_keys
    iat_value = 1_700_000_000  # arbitrary Unix timestamp

    receipt, entries, leaf = _build_receipt_with_protected(
        {HDR_CWT_CLAIMS: {CWT_CLAIM_IAT: iat_value}},
        alg="EdDSA",
        priv=priv,
        pub=pub,
    )
    r = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert r.ok, r.errors
    assert r.iat == iat_value
    # CWT_CLAIMS is a known/processed label; not in ext map
    assert HDR_CWT_CLAIMS not in r.protected_header_ext


def test_iat_none_when_absent(eddsa_keys):
    """A receipt built without CWT claims still verifies and returns iat=None.

    This is the byte-identical backward-compat path: the pre-0.3.0 receipt
    shape must verify unchanged and produce iat=None.
    """
    priv, pub = eddsa_keys
    es = _entries(5)
    idx = 2
    receipt = build_receipt(
        leaf_entry_hex=es[idx], leaf_index=idx, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    r = verify_receipt(receipt, leaf_entry_hex=es[idx], log_public_key_pem=pub)
    assert r.ok, r.errors
    assert r.iat is None
    assert r.protected_header_ext == {}


def test_unknown_protected_label_in_ext_map(eddsa_keys):
    """An unrecognized private-use protected label appears in protected_header_ext
    with its raw value and does NOT break verification.

    Uses label -65537 (a private-use negative int, not named or interpreted by
    this library) as a generic example of any profile-specific signed field.
    The neutral lib surfaces it as-is; callers interpret it independently.
    """
    priv, pub = eddsa_keys
    private_label = -65537
    private_value = b"some-opaque-value"

    receipt, entries, leaf = _build_receipt_with_protected(
        {private_label: private_value},
        alg="EdDSA",
        priv=priv,
        pub=pub,
    )
    r = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert r.ok, r.errors
    assert private_label in r.protected_header_ext
    assert r.protected_header_ext[private_label] == private_value
    # iat unaffected
    assert r.iat is None
