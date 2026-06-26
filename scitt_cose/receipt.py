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

import hashlib
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
#: vds value: CCF ccf.v1 Merkle format (used by scitt-ccf-ledger v7+).
VDS_CCF_LEDGER_SHA256 = 2
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

#: Extended understood set for CCF receipts: adds kid (4), CWT_Claims (15),
#: and the ccf.v1 label. CCF does not currently mark these critical, but
#: declaring them understood future-proofs against that changing.
_CCF_RECEIPT_UNDERSTOOD = _RECEIPT_UNDERSTOOD | frozenset({4, 15, "ccf.v1"})

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


def _verify_ccf_v1_proof(proof_blob: bytes, claim_digest: bytes) -> bytes:
    """Decode a CCF ccf.v1 inclusion proof and compute the Merkle root.

    The proof blob is a CBOR map
    ``{1: [write_set_digest, ce_string, claim_digest], 2: [[left, hash], ...]}``.
    Returns the root as 32 raw bytes. Raises :class:`CoseError` on any structural
    problem or if the embedded claim digest does not match the supplied value.

    Algorithm (from ``ccf.cose.verify_receipt``):
    ``leaf_hash = SHA-256(write_set_digest ‖ SHA-256(ce_string.encode()) ‖ claim_digest)``
    then for each ``(left, sibling)`` in the path:
    ``accumulator = SHA-256(sibling ‖ acc)`` if left else ``SHA-256(acc ‖ sibling)``.
    """
    try:
        proof = _plain(cbor2.loads(proof_blob))
    except Exception as exc:  # noqa: BLE001
        raise CoseError(f"CCF proof is not valid CBOR: {type(exc).__name__}") from exc
    if not isinstance(proof, dict):
        raise CoseError("CCF proof must be a CBOR map (keys 1 and 2)")
    leaf = proof.get(1)
    if not isinstance(leaf, (list, tuple)) or len(leaf) != 3:
        raise CoseError("CCF proof leaf (key 1) must be a 3-element array")
    write_set_digest, ce_string, proof_claim_digest = leaf[0], leaf[1], leaf[2]
    if not isinstance(write_set_digest, (bytes, bytearray)) or len(write_set_digest) != 32:
        raise CoseError("CCF proof write_set_digest must be 32 bytes")
    if not isinstance(ce_string, str):
        raise CoseError("CCF proof ce_string must be a text string")
    if not isinstance(proof_claim_digest, (bytes, bytearray)) or len(proof_claim_digest) != 32:
        raise CoseError("CCF proof claim_digest must be 32 bytes")
    if bytes(proof_claim_digest) != claim_digest:
        raise CoseError("CCF proof claim_digest does not match the supplied leaf_entry_hex")

    accumulator = hashlib.sha256(
        bytes(write_set_digest)
        + hashlib.sha256(ce_string.encode()).digest()
        + bytes(proof_claim_digest)
    ).digest()

    path = proof.get(2, [])
    if not isinstance(path, (list, tuple)):
        raise CoseError("CCF proof path (key 2) must be an array")
    if len(path) > _MAX_AUDIT_PATH:
        raise CoseError(f"CCF proof path too long ({len(path)} > {_MAX_AUDIT_PATH})")
    for step in path:
        if not isinstance(step, (list, tuple)) or len(step) != 2:
            raise CoseError("CCF proof path step must be [left: bool, hash: bytes]")
        left, sibling = step[0], step[1]
        if not isinstance(left, bool):
            raise CoseError("CCF proof path step left must be a bool")
        if not isinstance(sibling, (bytes, bytearray)) or len(sibling) != 32:
            raise CoseError("CCF proof path sibling must be 32 bytes")
        if left:
            accumulator = hashlib.sha256(bytes(sibling) + accumulator).digest()
        else:
            accumulator = hashlib.sha256(accumulator + bytes(sibling)).digest()

    return accumulator


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

    Handles two verifiable data structures:

    * **vds=1 (RFC9162_SHA256)** — the default: inclusion proof carried as
      ``cbor([tree_size, leaf_index, [audit_path]])``; root reconstructed via
      the RFC 6962 Merkle fold; COSE_Sign1 verified over that root.
    * **vds=2 (CCF ccf.v1)** — Microsoft CCF: proof carried as
      ``cbor({1: [write_set_digest, ce_string, claim_digest], 2: [[left, hash], ...]})``;
      root computed by SHA-256 over the CCF leaf formula then walked up an
      RFC 6962–style sibling path; COSE_Sign1 (ES384) verified over that root.

    Never raises — failures land in :attr:`ReceiptResult.errors`.
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
    except Exception as exc:  # noqa: BLE001 - name only, never echo input bytes
        result.errors.append(f"protected header is not valid CBOR ({type(exc).__name__})")
        return result
    if not isinstance(protected, dict):
        result.errors.append("protected header is not a map")
        return result

    # vds MUST come from the protected (integrity-protected) header.
    vds = protected.get(HDR_VDS)
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

    if vds == VDS_RFC9162_SHA256:
        # --- vds=1: RFC9162_SHA256 ---
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

    elif vds == VDS_CCF_LEDGER_SHA256:
        # --- vds=2: CCF ccf.v1 ---
        try:
            claim_digest = bytes.fromhex(leaf_entry_hex)
        except ValueError as exc:
            result.errors.append(f"leaf_entry_hex is not valid hex: {exc}")
            return result
        try:
            root_bytes = _verify_ccf_v1_proof(bytes(first_proof), claim_digest)
        except CoseError as exc:
            result.errors.append(str(exc))
            return result
        result.root = root_bytes.hex()
        try:
            verify_sign1(
                receipt,
                public_key_pem=log_public_key_pem,
                detached_payload=root_bytes,
                understood_labels=_CCF_RECEIPT_UNDERSTOOD,
            )
        except CoseError as exc:
            result.errors.append(f"receipt signature did not verify: {exc}")
            return result

    else:
        # The error does NOT echo the attacker-supplied vds value back (no input
        # reflection in responses); it names only the supported structures.
        result.errors.append(
            "unsupported verifiable data structure (protected label 395); "
            "expected RFC9162_SHA256 (vds=1) or CCF_LEDGER_SHA256 (vds=2)"
        )
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
    "VDS_CCF_LEDGER_SHA256",
    "VDP_INCLUSION_PROOFS",
]
