# SPDX-License-Identifier: Apache-2.0
"""COSE Receipt build (primitive) + verify.

A *Receipt* is a COSE_Sign1, signed by a transparency log, whose payload is the
Merkle tree root and whose unprotected header carries a *verifiable data proof*
(vdp) — here an RFC 9162 SHA-256 inclusion proof for one leaf. This is the
plumbing a transparency service would emit; operating such a service (a hosted
registration endpoint) is **out of scope** for this library, but the primitive
to mint and to verify a Receipt is included.

Encoding (tracks draft-ietf-cose-merkle-tree-proofs-18):

* protected header:
    * label ``1``   = alg code point (signed by the log key)
    * label ``395`` = verifiable-data-structure (vds); ``1`` = RFC9162_SHA256
* unprotected header:
    * label ``396`` = verifiable-data-proofs (vdp) map; key ``-1``
      ("inclusion proofs") -> array of inclusion-proof bstrs
* payload = the Merkle root bytes (detached by default; supplied by the verifier
  out of band, or attached)

Each inclusion-proof bstr is ``cbor([tree_size, leaf_index, [audit_path bstrs]])``.

The vds value is read from the **protected** header only (it is security-relevant
and must be integrity-protected by the signature). See the README for the honest
caveat that this vdp shape tracks the draft and is validated here by round-trip,
not against a frozen RFC.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union

import cbor2

from . import merkle
from .cose_sign1 import HDR_ALG, CoseError, sign_sign1, verify_sign1

#: Protected header label carrying the verifiable-data-structure identifier.
HDR_VDS = 395
#: Unprotected header label carrying the verifiable-data-proofs map.
HDR_VDP = 396
#: vds value: RFC 9162 SHA-256 Merkle tree.
VDS_RFC9162_SHA256 = 1
#: vdp map key for the inclusion-proofs array.
VDP_INCLUSION_PROOFS = -1

PemLike = Union[bytes, str]


@dataclass
class ReceiptResult:
    """Outcome of :func:`verify_receipt`.

    ``ok`` is ``True`` only when the inclusion proof reconstructs a root *and*
    the COSE_Sign1 over that root verifies under the log key. On any failure
    ``ok`` is ``False`` and ``errors`` explains why.
    """

    ok: bool = False
    root: str | None = None
    tree_size: int | None = None
    leaf_index: int | None = None
    errors: list = field(default_factory=list)


def _encode_inclusion_proof(tree_size: int, leaf_index: int, audit_path_hex: list[str]) -> bytes:
    return cbor2.dumps(
        [tree_size, leaf_index, [bytes.fromhex(h) for h in audit_path_hex]]
    )


def _plain(v):
    """Normalize cbor2 output across versions: cbor2>=6 returns CBOR maps as
    ``frozendict`` (not a ``dict`` subclass) and arrays as ``tuple``. Convert to
    plain ``dict``/``list`` so structural checks are cbor2-version-independent.
    ``bytes``/``str`` pass through unchanged."""
    if isinstance(v, (bytes, bytearray, str)):
        return v
    if hasattr(v, "items"):  # dict or cbor2>=6 frozendict
        return {k: _plain(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v


def _decode_inclusion_proof(blob: bytes):
    arr = _plain(cbor2.loads(blob))
    if not isinstance(arr, (list, tuple)) or len(arr) != 3:
        raise CoseError("inclusion proof must be [tree_size, leaf_index, [path]]")
    tree_size, leaf_index, path = arr
    if not isinstance(tree_size, int) or not isinstance(leaf_index, int):
        raise CoseError("inclusion proof tree_size/leaf_index must be ints")
    if not isinstance(path, (list, tuple)):
        raise CoseError("inclusion proof path must be an array")
    audit_path_hex = [bytes(p).hex() for p in path]
    return tree_size, leaf_index, audit_path_hex


def build_receipt(
    *,
    leaf_entry_hex: str,
    leaf_index: int,
    tree_entries_hex: list[str],
    alg: str,
    log_private_key_pem: PemLike,
    detached: bool = True,
) -> bytes:
    """Mint a COSE Receipt for one leaf of an RFC 9162 Merkle tree.

    Computes the root and the inclusion proof over ``tree_entries_hex`` for the
    entry at ``leaf_index`` (which must equal ``leaf_entry_hex``), then signs a
    COSE_Sign1 over the root with the log key. By default the payload (the root)
    is detached.
    """
    if not 0 <= leaf_index < len(tree_entries_hex):
        raise CoseError(f"leaf_index {leaf_index} out of range for {len(tree_entries_hex)} entries")
    if tree_entries_hex[leaf_index] != leaf_entry_hex:
        raise CoseError("leaf_entry_hex does not match tree_entries_hex[leaf_index]")

    root_hex = merkle.merkle_root(tree_entries_hex)
    audit_path = merkle.inclusion_proof(tree_entries_hex, leaf_index)
    inclusion_blob = _encode_inclusion_proof(len(tree_entries_hex), leaf_index, audit_path)

    protected = {HDR_VDS: VDS_RFC9162_SHA256}
    unprotected = {HDR_VDP: {VDP_INCLUSION_PROOFS: [inclusion_blob]}}

    return sign_sign1(
        bytes.fromhex(root_hex),
        alg=alg,
        private_key_pem=log_private_key_pem,
        protected=protected,
        unprotected=unprotected,
        detached=detached,
    )


def verify_receipt(
    receipt: bytes,
    *,
    leaf_entry_hex: str,
    log_public_key_pem: PemLike,
) -> ReceiptResult:
    """Verify a COSE Receipt for ``leaf_entry_hex``.

    Steps: read vds from the protected header (must be ``1`` / RFC9162_SHA256);
    decode the inclusion proof from the unprotected vdp; reconstruct the Merkle
    root from ``leaf_entry_hex`` + the proof; then verify the COSE_Sign1 over that
    reconstructed root with the log key. Never raises — failures land in
    :attr:`ReceiptResult.errors`.
    """
    result = ReceiptResult()

    try:
        outer = cbor2.loads(receipt)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"receipt is not valid CBOR: {exc}")
        return result
    if not isinstance(outer, cbor2.CBORTag) or not isinstance(outer.value, (list, tuple)) or len(outer.value) != 4:
        result.errors.append("receipt is not a COSE_Sign1 message")
        return result

    protected_bstr, unprotected, _payload_slot, _signature = outer.value
    unprotected = _plain(unprotected)
    try:
        protected = _plain(cbor2.loads(protected_bstr)) if protected_bstr else {}
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"protected header is not valid CBOR: {exc}")
        return result
    if not isinstance(protected, dict):
        result.errors.append("protected header is not a map")
        return result

    # vds MUST come from the protected (integrity-protected) header.
    vds = protected.get(HDR_VDS)
    if vds != VDS_RFC9162_SHA256:
        result.errors.append(
            f"protected vds (label 395) is {vds!r}; expected {VDS_RFC9162_SHA256} (RFC9162_SHA256)"
        )
        return result
    if HDR_ALG not in protected:
        result.errors.append("protected header missing alg (label 1)")
        return result

    if not isinstance(unprotected, dict):
        result.errors.append("unprotected header is not a map")
        return result
    vdp = unprotected.get(HDR_VDP)
    if not isinstance(vdp, dict):
        result.errors.append("unprotected vdp (label 396) missing or not a map")
        return result
    inclusion_proofs = vdp.get(VDP_INCLUSION_PROOFS)
    if not isinstance(inclusion_proofs, (list, tuple)) or not inclusion_proofs:
        result.errors.append("vdp has no inclusion proofs (key -1)")
        return result

    try:
        tree_size, leaf_index, audit_path_hex = _decode_inclusion_proof(bytes(inclusion_proofs[0]))
    except CoseError as exc:
        result.errors.append(str(exc))
        return result

    result.tree_size = tree_size
    result.leaf_index = leaf_index

    # Reconstruct the root by folding the leaf up the audit path. We do not yet
    # know the claimed root, so derive it and then check the signature over it.
    reconstructed = _reconstruct_root(leaf_entry_hex, leaf_index, tree_size, audit_path_hex)
    if reconstructed is None:
        result.errors.append("inclusion proof does not reconstruct a root for this leaf")
        return result
    result.root = reconstructed

    # Verify the COSE_Sign1 over the reconstructed root. This proves the log
    # signed *this* root, binding the leaf+proof to the log's signature.
    try:
        verify_sign1(
            receipt,
            public_key_pem=log_public_key_pem,
            detached_payload=bytes.fromhex(reconstructed),
        )
    except CoseError as exc:
        result.errors.append(f"receipt signature did not verify: {exc}")
        return result

    result.ok = True
    return result


def _reconstruct_root(
    leaf_entry_hex: str, leaf_index: int, tree_size: int, audit_path_hex: list[str]
) -> str | None:
    """Fold a leaf up its audit path to the root (RFC 6962 §2.1.1), or None."""
    return merkle.root_from_inclusion_proof(
        leaf_entry_hex, leaf_index, tree_size, audit_path_hex
    )


__all__ = [
    "ReceiptResult",
    "build_receipt",
    "verify_receipt",
    "HDR_VDS",
    "HDR_VDP",
    "VDS_RFC9162_SHA256",
    "VDP_INCLUSION_PROOFS",
]
