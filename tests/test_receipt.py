# SPDX-License-Identifier: Apache-2.0
"""COSE Receipt build/verify (detached + attached) and negatives."""
from __future__ import annotations

import json
from pathlib import Path

import cbor2
import pytest

from scitt_cose import merkle
from scitt_cose.cose_sign1 import CoseError
from scitt_cose.receipt import (
    CWT_CLAIM_IAT,
    CWT_CLAIM_ISS,
    CWT_CLAIM_SUB,
    HDR_CWT_CLAIMS,
    HDR_GRADE,
    HDR_KID,
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

    Uses ``HDR_GRADE`` (-65537, the single-sourced private-use witness grade
    label -- see the module docstring) as a generic example of any
    profile-specific signed field. The neutral lib surfaces it as-is; callers
    interpret it independently.
    """
    priv, pub = eddsa_keys
    private_label = HDR_GRADE
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


# --- RFC 9943 §6 receipt claims: iss / sub / kid ---------------------------
# Additive, backward-compatible (all three
# stay optional here; a caller supplying none of them gets the exact
# pre-existing wire shape, see test_build_receipt_without_claims_unchanged).


def test_build_receipt_with_iss_sub_kid(alg_keys):
    """build_receipt threads iss/sub/kid into the protected header, and they
    round-trip through verify_receipt -- proving they are SIGNED (covered by
    the COSE_Sign1 signature over the protected bstr), not just present."""
    alg, priv, pub = alg_keys
    es = _entries(5)
    idx = 2
    kid_bytes = bytes.fromhex("39bb654c9dc0afe1")

    receipt = build_receipt(
        leaf_entry_hex=es[idx], leaf_index=idx, tree_entries_hex=es,
        alg=alg, log_private_key_pem=priv,
        iss="did:web:witness.example",
        sub="entry:deadbeef",
        kid=kid_bytes,
    )
    r = verify_receipt(receipt, leaf_entry_hex=es[idx], log_public_key_pem=pub)
    assert r.ok, r.errors
    assert r.issuer == "did:web:witness.example"
    assert r.subject == "entry:deadbeef"
    # kid (label 4) is not a CWT claim -- it surfaces via the generic
    # unrecognized-protected-label passthrough, same as any private-use label.
    assert r.protected_header_ext[HDR_KID] == kid_bytes


def test_build_receipt_without_claims_unchanged(alg_keys):
    """Omitting iss/sub/kid produces the exact pre-existing wire shape --
    byte-identical to a call before this change, same discipline as iat."""
    alg, priv, pub = alg_keys
    es = _entries(5)
    idx = 2
    receipt = build_receipt(
        leaf_entry_hex=es[idx], leaf_index=idx, tree_entries_hex=es,
        alg=alg, log_private_key_pem=priv,
    )
    protected = cbor2.loads(cbor2.loads(receipt).value[0])
    assert HDR_CWT_CLAIMS not in protected
    assert HDR_KID not in protected
    r = verify_receipt(receipt, leaf_entry_hex=es[idx], log_public_key_pem=pub)
    assert r.ok, r.errors
    assert r.issuer is None
    assert r.subject is None


@pytest.mark.parametrize("tamper_claim", [CWT_CLAIM_ISS, CWT_CLAIM_SUB, CWT_CLAIM_IAT])
def test_tampered_cwt_claim_fails_signature(eddsa_keys, tamper_claim):
    """Mutant check: flipping iss, sub or iat AFTER signing (protected header
    tampered, signature left alone) must fail verification -- proving each
    claim is covered by the COSE_Sign1 signature, not just carried
    unauthenticated in the payload or response body."""
    priv, pub = eddsa_keys
    receipt, entries, leaf = _build_receipt_with_protected(
        {HDR_CWT_CLAIMS: {
            CWT_CLAIM_ISS: "did:web:witness.example",
            CWT_CLAIM_SUB: "entry:original",
            CWT_CLAIM_IAT: 1_700_000_000,
        }},
        alg="EdDSA", priv=priv, pub=pub,
    )
    # Sanity: the untampered receipt verifies.
    ok = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert ok.ok, ok.errors

    outer = cbor2.loads(receipt)
    protected = cbor2.loads(outer.value[0])
    protected[HDR_CWT_CLAIMS] = dict(protected[HDR_CWT_CLAIMS])
    protected[HDR_CWT_CLAIMS][tamper_claim] = "tampered-value"
    tampered_protected_bstr = cbor2.dumps(protected)
    tampered = cbor2.CBORTag(
        outer.tag, [tampered_protected_bstr, outer.value[1], outer.value[2], outer.value[3]]
    )
    tampered_bytes = cbor2.dumps(tampered)

    bad = verify_receipt(tampered_bytes, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert not bad.ok
    assert any("signature did not verify" in e for e in bad.errors)


def test_tampered_kid_fails_signature(eddsa_keys):
    """Mutant check: flipping kid (label 4, protected -- not a CWT claim)
    AFTER signing must fail verification the same way iss/sub tampering does."""
    priv, pub = eddsa_keys
    kid_bytes = bytes.fromhex("39bb654c9dc0afe1")
    receipt, entries, leaf = _build_receipt_with_protected(
        {HDR_KID: kid_bytes}, alg="EdDSA", priv=priv, pub=pub,
    )
    ok = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert ok.ok, ok.errors

    outer = cbor2.loads(receipt)
    protected = cbor2.loads(outer.value[0])
    protected[HDR_KID] = bytes.fromhex("ffffffffffffffff")
    tampered_protected_bstr = cbor2.dumps(protected)
    tampered = cbor2.CBORTag(
        outer.tag, [tampered_protected_bstr, outer.value[1], outer.value[2], outer.value[3]]
    )
    tampered_bytes = cbor2.dumps(tampered)

    bad = verify_receipt(tampered_bytes, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert not bad.ok
    assert any("signature did not verify" in e for e in bad.errors)


# --- header claims are never surfaced from a receipt whose signature fails ---
# Grade-forgery class: a receipt signed under an attacker's key can carry any
# grade/iat it likes in its protected header. Verified under the real pinned
# key it fails, and none of those claims may reach the caller.

_GRADE = "mmr-verified"
_GRADED_HEADER = {HDR_CWT_CLAIMS: {CWT_CLAIM_IAT: 1_700_001_000}, HDR_GRADE: _GRADE}


def _assert_claims_withheld(r):
    assert r.ok is False
    assert HDR_GRADE not in r.protected_header_ext
    assert r.protected_header_ext == {}
    assert r.iat is None
    assert r.issuer is None
    assert r.subject is None
    assert _GRADE not in repr(r)
    assert any("claims withheld" in e for e in r.errors), r.errors


def test_grade_not_exposed_when_signed_by_non_pinned_key(eddsa_keys, other_eddsa_keys):
    _priv, real_pub = eddsa_keys
    attacker_priv, attacker_pub = other_eddsa_keys
    receipt, _entries_, leaf = _build_receipt_with_protected(
        _GRADED_HEADER, alg="EdDSA", priv=attacker_priv, pub=attacker_pub,
    )
    r = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=real_pub)
    _assert_claims_withheld(r)
    assert any("signature did not verify" in e for e in r.errors)


def test_grade_not_exposed_when_signature_bytes_corrupted(eddsa_keys):
    priv, pub = eddsa_keys
    receipt, _entries_, leaf = _build_receipt_with_protected(
        _GRADED_HEADER, alg="EdDSA", priv=priv, pub=pub,
    )
    protected_bstr, unprotected, payload, sig = cbor2.loads(receipt).value
    bad_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    tampered = cbor2.dumps(cbor2.CBORTag(18, [protected_bstr, unprotected, payload, bad_sig]))
    r = verify_receipt(tampered, leaf_entry_hex=leaf, log_public_key_pem=pub)
    _assert_claims_withheld(r)
    assert any("signature did not verify" in e for e in r.errors)


def test_grade_still_exposed_on_valid_receipt(eddsa_keys):
    priv, pub = eddsa_keys
    receipt, _entries_, leaf = _build_receipt_with_protected(
        _GRADED_HEADER, alg="EdDSA", priv=priv, pub=pub,
    )
    r = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=pub)
    assert r.ok, r.errors
    assert r.protected_header_ext[HDR_GRADE] == _GRADE
    assert r.iat == 1_700_001_000
    assert not any("claims withheld" in e for e in r.errors)


def test_build_receipt_iat_grade_round_trip(alg_keys):
    """``build_receipt(iat=, grade=)`` signs both into the protected header
    alongside iss/sub (the existing CWT claims map is extended, not replaced),
    and a valid receipt surfaces them: iat on the result, grade via
    ``protected_header_ext``."""
    alg, priv, pub = alg_keys
    es = _entries(5)
    receipt = build_receipt(
        leaf_entry_hex=es[2], leaf_index=2, tree_entries_hex=es, alg=alg,
        log_private_key_pem=priv, iss="did:web:witness.example", sub="entry:x",
        iat=1_700_000_000, grade=_GRADE,
    )
    protected = cbor2.loads(cbor2.loads(receipt).value[0])
    assert protected[HDR_CWT_CLAIMS] == {
        CWT_CLAIM_ISS: "did:web:witness.example",
        CWT_CLAIM_SUB: "entry:x",
        CWT_CLAIM_IAT: 1_700_000_000,
    }
    assert protected[HDR_GRADE] == _GRADE
    r = verify_receipt(receipt, leaf_entry_hex=es[2], log_public_key_pem=pub)
    assert r.ok, r.errors
    assert r.iat == 1_700_000_000
    assert r.issuer == "did:web:witness.example"
    assert r.subject == "entry:x"
    assert r.protected_header_ext == {HDR_GRADE: _GRADE}


def test_build_receipt_iat_grade_matches_frozen_vector_header(eddsa_keys):
    """The kwargs produce the exact protected-header bytes of the frozen
    ``synthetic-eddsa-iat-grade`` vector (key order 395, 15, -65537, 1), so the
    library path and the hand-built vector generator agree on the wire."""
    priv, _pub = eddsa_keys
    d = _RECEIPT_V1 / "synthetic-eddsa-iat-grade"
    exp = json.loads((d / "expected.json").read_text())
    es = [bytes([i]).hex() for i in range(exp["tree_size"])]
    receipt = build_receipt(
        leaf_entry_hex=exp["leaf_entry_hex"], leaf_index=exp["leaf_index"],
        tree_entries_hex=es, alg="EdDSA", log_private_key_pem=priv,
        iat=exp["iat"], grade=exp["grade"],
    )
    frozen = cbor2.loads((d / "receipt.cose").read_bytes())
    assert cbor2.loads(receipt).value[0] == frozen.value[0]


def test_tampered_grade_value_fails_signature(eddsa_keys):
    """Mutant check: changing the grade VALUE after ``build_receipt`` signed it
    must fail verification and expose no header claims at all."""
    priv, pub = eddsa_keys
    es = _entries(4)
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA",
        log_private_key_pem=priv, iat=1_700_001_000, grade="basic",
    )
    assert verify_receipt(receipt, leaf_entry_hex=es[1], log_public_key_pem=pub).ok
    outer = cbor2.loads(receipt)
    protected = dict(cbor2.loads(outer.value[0]))
    protected[HDR_GRADE] = _GRADE
    tampered = cbor2.dumps(
        cbor2.CBORTag(outer.tag, [cbor2.dumps(protected), outer.value[1], outer.value[2], outer.value[3]])
    )
    r = verify_receipt(tampered, leaf_entry_hex=es[1], log_public_key_pem=pub)
    _assert_claims_withheld(r)
    assert any("signature did not verify" in e for e in r.errors)


_RECEIPT_V1 = Path(__file__).resolve().parent.parent / "test-vectors" / "receipt-v1"


@pytest.mark.parametrize(
    "vid", sorted(p.name for p in _RECEIPT_V1.iterdir() if (p / "expected.json").is_file())
)
def test_frozen_receipt_v1_vectors_unchanged(vid):
    """The published receipt-v1 vectors (incl. the pre-iat/grade real capture)
    verify exactly as their frozen expected.json says: ok, iat, grade."""
    d = _RECEIPT_V1 / vid
    exp = json.loads((d / "expected.json").read_text())
    r = verify_receipt(
        (d / "receipt.cose").read_bytes(),
        leaf_entry_hex=exp["leaf_entry_hex"],
        log_public_key_pem=(d / "log-key.pub").read_bytes(),
    )
    assert r.ok is exp["ok"], r.errors
    assert r.iat == exp["iat"]
    assert r.protected_header_ext.get(HDR_GRADE) == exp["grade"]
    if exp["ok"]:
        assert r.root == exp["root"]


def test_donated_multi_proof_orders_and_malformed_tail():
    directory = Path(__file__).parents[1] / "test-vectors/v1/valid-eddsa-multi-proof"
    expected = json.loads((directory / "expected.json").read_text())
    key = (directory / "log-key.pub").read_bytes()
    for name in ("receipt.cose", "receipt-reordered.cose"):
        receipt = (directory / name).read_bytes()
        result = verify_receipt(receipt, leaf_entry_hex=expected["leaf_entry"], log_public_key_pem=key)
        assert result.ok, result.errors
        assert result.leaf_index == expected["leaf_index"]
    tagged = cbor2.loads(receipt)
    protected, unprotected, payload, signature = tagged.value
    proofs = list(unprotected[396][-1])
    proofs.append(cbor2.dumps([0, 0, []]))
    malformed = cbor2.dumps(cbor2.CBORTag(18, [protected, {396: {-1: proofs}}, payload, signature]))
    result = verify_receipt(malformed, leaf_entry_hex=expected["leaf_entry"], log_public_key_pem=key)
    assert result.errors == ["invalid tree size or leaf index"]


def test_inclusion_proof_rejects_trailing_cbor():
    from scitt_cose.receipt import _decode_inclusion_proof

    with pytest.raises(CoseError, match="trailing CBOR"):
        _decode_inclusion_proof(cbor2.dumps([1, 0, []]) + b"\x00")
