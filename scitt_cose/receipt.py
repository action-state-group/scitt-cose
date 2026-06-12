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
from .cose_sign1 import (
    COSE_SIGN1_TAG,
    HDR_ALG,
    HDR_CRIT,
    CoseError,
    sign_sign1,
    strict_decode,
    verify_sign1,
)

#: Protected header label carrying the verifiable-data-structure identifier.
HDR_VDS = 395
#: Unprotected header label carrying the verifiable-data-proofs map.
HDR_VDP = 396
#: vds value: RFC 9162 SHA-256 Merkle tree.
VDS_RFC9162_SHA256 = 1
#: vdp map key for the inclusion-proofs array.
VDP_INCLUSION_PROOFS = -1

#: A receipt carries one inclusion proof per leaf; an array longer than this is
#: hostile padding, capped before any per-element work (paired with the bstr
#: type-check that prevents bytes(int) over-allocation).
_MAX_INCLUSION_PROOFS = 16

#: Protected-header labels the receipt layer understands, for RFC 9052 §3.1
#: crit enforcement: alg (1), crit (2) itself, and vds (395) which this layer
#: actively reads. A receipt marking any of these critical is accepted; an
#: unknown critical label is still rejected.
_RECEIPT_UNDERSTOOD = frozenset({HDR_ALG, HDR_CRIT, HDR_VDS})

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


#: An inclusion path longer than this cannot belong to any tree we accept
#: (MAX_TREE_SIZE = 2**63 → depth <= 63). Reject early, before building the path.
_MAX_AUDIT_PATH = 64


def _decode_inclusion_proof(blob: bytes):
    try:
        arr = _plain(cbor2.loads(blob))
    except Exception as exc:  # noqa: BLE001 - map any parser error to CoseError
        raise CoseError(f"inclusion proof is not valid CBOR: {type(exc).__name__}") from exc
    if not isinstance(arr, (list, tuple)) or len(arr) != 3:
        raise CoseError("inclusion proof must be [tree_size, leaf_index, [path]]")
    tree_size, leaf_index, path = arr
    # bool is an int subclass; exclude it explicitly so True/False can't pose as
    # a size/index.
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        raise CoseError("inclusion proof tree_size must be an int")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise CoseError("inclusion proof leaf_index must be an int")
    if not isinstance(path, (list, tuple)):
        raise CoseError("inclusion proof path must be an array")
    if len(path) > _MAX_AUDIT_PATH:
        raise CoseError(f"inclusion proof path too long ({len(path)} > {_MAX_AUDIT_PATH})")
    audit_path_hex = []
    for node in path:
        if not isinstance(node, (bytes, bytearray)):
            raise CoseError("inclusion proof path element is not a byte string")
        audit_path_hex.append(bytes(node).hex())
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

    # Strict decode at the trust boundary: rejects trailing bytes, indefinite-
    # length / non-canonical encodings, and duplicate protected-header keys
    # (the same gate the statement path uses). verify_receipt never raises, so
    # the structural CoseError is captured into errors rather than propagated.
    try:
        outer = strict_decode(receipt)
    except CoseError as exc:
        result.errors.append(f"receipt rejected: {exc}")
        return result
    if outer.tag != COSE_SIGN1_TAG or not isinstance(outer.value, (list, tuple)) or len(outer.value) != 4:
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

    # vds MUST come from the protected (integrity-protected) header. The error
    # does NOT echo the attacker-supplied vds value back (no input reflection in
    # responses); it names only the expected structure.
    if protected.get(HDR_VDS) != VDS_RFC9162_SHA256:
        result.errors.append(
            "unsupported verifiable data structure (protected label 395); "
            "expected RFC9162_SHA256 (vds = 1)"
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
    if len(inclusion_proofs) > _MAX_INCLUSION_PROOFS:
        result.errors.append(
            f"too many inclusion proofs ({len(inclusion_proofs)} > {_MAX_INCLUSION_PROOFS})"
        )
        return result
    # Never coerce an unvalidated decoded value to bytes: a CBOR integer here
    # would make bytes(int) allocate a multi-gigabyte zero buffer from a tiny
    # receipt. Require an actual byte string first.
    first_proof = inclusion_proofs[0]
    if not isinstance(first_proof, (bytes, bytearray)):
        result.errors.append("inclusion proof entry is not a byte string")
        return result

    try:
        tree_size, leaf_index, audit_path_hex = _decode_inclusion_proof(bytes(first_proof))
    except CoseError as exc:
        result.errors.append(str(exc))
        return result

    result.tree_size = tree_size
    result.leaf_index = leaf_index

    # Reconstruct the root by folding the leaf up the audit path. The Merkle
    # layer bounds tree_size and checks the path length before any hashing, so
    # this cannot recurse without bound; the guard here is belt-and-suspenders so
    # verify_receipt's "never raises" contract holds even if that changes.
    try:
        reconstructed = _reconstruct_root(leaf_entry_hex, leaf_index, tree_size, audit_path_hex)
    except Exception as exc:  # noqa: BLE001 - contract: never raise, map to errors
        result.errors.append(f"inclusion proof could not be evaluated: {type(exc).__name__}")
        return result
    if reconstructed is None:
        result.errors.append("inclusion proof does not reconstruct a root for this leaf")
        return result
    result.root = reconstructed

    # Verify the COSE_Sign1 over the reconstructed root. This proves the log
    # signed *this* root, binding the leaf+proof to the log's signature. The
    # receipt layer actively processes vds (395), so it is advertised as
    # understood — a receipt that legitimately marks vds critical is accepted,
    # while any *other* unknown critical header is still rejected (RFC 9052 §3.1).
    try:
        verify_sign1(
            receipt,
            public_key_pem=log_public_key_pem,
            detached_payload=bytes.fromhex(reconstructed),
            understood_labels=_RECEIPT_UNDERSTOOD,
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
