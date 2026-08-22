# SPDX-License-Identifier: Apache-2.0
"""CLL (Checkpointed Local Log) verification: MMR inclusion, consistency, and
range proofs against a signed checkpoint, plus honest witness-lag rendering.

A CLL is a locally-appended log (an Agent Action Capsule stream) that
periodically commits to a Merkle Mountain Range (MMR) accumulator and
registers the resulting *checkpoint* with a SCITT Transparency Service (TS),
per Amendment E. The checkpoint/MMR-producing side lives in
``capsule_emit.checkpoint`` (opt-in subpackage; ``core.py``/``index.py``/
``emit.py``). This module is the other half: **a verifier that cannot check
the log is a half-verifier** (Amendment E). It lets a third party who holds
only a capsule, an inclusion proof, and a witnessed checkpoint confirm the
whole chain **offline** — no live log, no trust in the operator's own
signature scheme.

Why the hash/position primitives below are a byte-identical **port**, not an
import: ``capsule-emit``'s own ``checkpoint`` extra already depends on
``scitt-cose>=0.2.0`` (for TS-receipt verification via :func:`receipt.
verify_receipt`) — the dependency runs producer -> verifier. A reverse import
here would be circular, and would also make this vendor-neutral verifier
require every producer's exact package, which defeats the point of a neutral
verifier. So the pure MMR math (``leaf_hash``, ``interior_hash``,
``root_from_peaks``, position math, and the two total, never-raising
``verify_inclusion``/``verify_consistency`` functions) is duplicated here,
cross-checked against the same KAT39 vectors and the same self-generated
proof vectors committed at ``test-vectors/mmr/`` (``kat39.json``,
``proof-vectors.json`` — minted from the pre-port ``asg_ledger.mmr.core``
reference and confirmed to verify before export; see
``scripts/generate_mmr_kat39_vectors.py``). The checkpoint digest algorithm
(:meth:`Checkpoint.digest`) is likewise a byte-identical port of
``capsule_emit.checkpoint.emit.CheckpointRecord.signing_body``/``digest``,
cross-checked in ``tests/test_cll.py`` against a value computed live from
that module (commit ``e3df69dfe`` / ``34e90f1``, branch
``cll-extract-mmr-to-capsule-emit``).

Boundary, deliberately: this module verifies **the log**, not the operator.
A checkpoint's ``signature`` field is produced by a caller-supplied, opaque
``Signer`` on the producer side (HMAC, Ed25519, whatever the deployment
picks) — there is no single scheme a neutral verifier can check generically,
so that step is out of scope here. What a neutral third party CAN check
without any shared secret is (1) that a leaf is genuinely under the
checkpoint's committed MMR root, (2) that one checkpoint's peaks genuinely
extend an earlier one (no rollback), and (3) that the checkpoint digest
itself was seen by a Transparency Service at some point in *its* append-only
log — via the existing :func:`receipt.verify_receipt`, reused unchanged.

Honesty rule enforced throughout: every verification result renders a
"witnessed up to size S at time T" status rather than a bare boolean. Lag
(the gap between what a checkpoint witnesses and what the caller separately
knows the log has grown to) is always surfaced when known, never hidden.
Range proofs are verified with an explicit, permanent caveat: a proof that a
contiguous range is intact is not a proof that no other records exist —
range-intact != all-traffic. A verifier that lets a range proof read as a
completeness claim is answering a different, unasked question.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .receipt import ReceiptResult, verify_receipt

DIGEST_LEN = 32
MAX_MMR_SIZE = 2**50

__all__ = [
    "DIGEST_LEN",
    "MAX_MMR_SIZE",
    "InvalidArgumentError",
    "leaf_hash",
    "interior_hash",
    "root_from_peaks",
    "height_at",
    "node_count",
    "leaf_count",
    "leaf_index_to_pos",
    "peaks",
    "InclusionProof",
    "ConsistencyProof",
    "RangeProof",
    "verify_inclusion",
    "verify_consistency",
    "verify_range",
    "Checkpoint",
    "witness_status_line",
    "InclusionVerification",
    "ConsistencyVerification",
    "RangeVerification",
    "verify_leaf_against_checkpoint",
    "verify_checkpoint_chain",
    "verify_range_against_checkpoint",
]


class InvalidArgumentError(ValueError):
    """A caller-supplied argument (size, leaf_index, digest shape) is invalid."""


def _assert_digest(d: bytes, what: str = "digest") -> None:
    if not isinstance(d, (bytes, bytearray)) or len(d) != DIGEST_LEN:
        raise InvalidArgumentError(f"{what} must be {DIGEST_LEN} bytes")


def _require_nonneg_int(n: int, what: str) -> None:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise InvalidArgumentError(f"{what} must be a non-negative integer: {n}")


# -- hashing (byte-identical port of capsule_emit.checkpoint.core) -----------


def leaf_hash(body_digest: bytes) -> bytes:
    """leaf_hash = sha256(0x00 || body_digest)."""
    _assert_digest(body_digest, "body_digest")
    return hashlib.sha256(b"\x00" + body_digest).digest()


def interior_hash(left: bytes, right: bytes, position: int) -> bytes:
    """interior_hash = sha256(be64(position+1) || left || right). `position`
    is the 0-based array index the new interior node occupies (MMRIVER-draft
    convention, position-committed against equivocation)."""
    _assert_digest(left, "left")
    _assert_digest(right, "right")
    _require_nonneg_int(position, "position")
    pos_bytes = (position + 1).to_bytes(8, "big")
    return hashlib.sha256(pos_bytes + left + right).digest()


def root_from_peaks(peak_hashes: list[bytes]) -> bytes:
    """Root = bagged peaks, right-to-left, no domain-separator byte: pop the
    two rightmost, combine as sha256(right || left), push back, repeat.
    Root of an empty MMR is 32 zero bytes."""
    if not peak_hashes:
        return bytes(DIGEST_LEN)
    for p in peak_hashes:
        _assert_digest(p, "peak")
    hashes = list(peak_hashes)
    while len(hashes) > 1:
        right = hashes.pop()
        left = hashes.pop()
        hashes.append(hashlib.sha256(right + left).digest())
    return hashes[0]


# -- position math -------------------------------------------------------


def height_at(pos: int) -> int:
    """Height of the node at 0-indexed flat-array position `pos` (0 = leaf)."""
    _require_nonneg_int(pos, "pos")
    pos1 = pos + 1
    h = 0
    while 2 ** (h + 1) - 1 < pos1:
        h += 1
    while h > 0:
        size = 2 ** (h + 1) - 1
        if pos1 == size:
            return h
        left_size = 2**h - 1
        if pos1 > left_size:
            pos1 -= left_size
        h -= 1
    return 0


def node_count(leaf_count_: int) -> int:
    """nodeCount(f) = 2f - popcount(f): total node count for `f` leaves."""
    _require_nonneg_int(leaf_count_, "leaf_count")
    return 2 * leaf_count_ - bin(leaf_count_).count("1")


def peaks(size: int) -> list[int]:
    """Peak positions (left to right) of an MMR with `size` nodes. Raises if
    `size` does not decompose into a strictly-height-decreasing mountain
    sequence (i.e. is not a valid, complete MMR node count)."""
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size >= MAX_MMR_SIZE:
        raise InvalidArgumentError(f"invalid MMR size: {size}")
    result: list[int] = []
    remaining = size
    offset = 0
    prev_height = float("inf")
    while remaining > 0:
        h = 0
        while 2 ** (h + 2) - 1 <= remaining:
            h += 1
        if h >= prev_height:
            raise InvalidArgumentError(f"invalid MMR size (not a valid node count): {size}")
        m_size = 2 ** (h + 1) - 1
        offset += m_size
        result.append(offset - 1)
        remaining -= m_size
        prev_height = h
    return result


def leaf_count(size: int) -> int:
    """Number of leaves in an MMR of `size` nodes. Raises on an invalid size."""
    pks = peaks(size)
    return sum(2 ** height_at(p) for p in pks)


def leaf_index_to_pos(leaf_index: int) -> int:
    """Position of the nth (0-indexed) leaf: node_count(leaf_index)."""
    _require_nonneg_int(leaf_index, "leaf_index")
    pos = node_count(leaf_index)
    if pos >= MAX_MMR_SIZE:
        raise InvalidArgumentError(f"leaf_index too large: {leaf_index}")
    return pos


@dataclass(frozen=True)
class _PathStep:
    sibling_pos: int
    target_is_right: bool
    parent_pos: int


def _find_containing_peak(pos: int, peak_positions: list[int]) -> int:
    for i, peak_pos in enumerate(peak_positions):
        h = height_at(peak_pos)
        m_size = 2 ** (h + 1) - 1
        start = peak_pos - m_size + 1
        if start <= pos <= peak_pos:
            return i
    return -1


def _locate_path(root_pos: int, height: int, target_pos: int) -> list[_PathStep]:
    top_down: list[_PathStep] = []
    cur_root = root_pos
    cur_height = height
    while cur_height > 0 and cur_root != target_pos:
        parent_pos = cur_root
        left_size = 2**cur_height - 1
        left_child_root = cur_root - left_size - 1
        right_child_root = cur_root - 1
        if target_pos <= left_child_root:
            top_down.append(_PathStep(right_child_root, False, parent_pos))
            cur_root = left_child_root
        else:
            top_down.append(_PathStep(left_child_root, True, parent_pos))
            cur_root = right_child_root
        cur_height -= 1
    top_down.reverse()
    return top_down


def _parse_digest_hex(h: object) -> bytes:
    if not isinstance(h, str):
        raise InvalidArgumentError("proof element is not a hex string")
    b = bytes.fromhex(h)
    if len(b) != DIGEST_LEN:
        raise InvalidArgumentError(f"proof element has wrong digest length: {len(b)}")
    return b


# -- proof shapes (wire-identical to capsule_emit.checkpoint) ----------------


@dataclass(frozen=True)
class InclusionProof:
    """Sibling hashes up to the leaf's peak, then the other peaks needed to
    re-bag the root. Hex-encoded, JSON-serializable, and parses directly from
    the JSON a ``capsule_emit.checkpoint.core.inclusion_proof`` call
    produces -- no field renaming, no reshaping."""

    v: int
    kind: str
    size: int
    leaf_index: int
    witness: tuple[str, ...]
    peaks_left: tuple[str, ...]
    peaks_right: tuple[str, ...]

    @classmethod
    def from_dict(cls, d: dict) -> InclusionProof:
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            size=int(d["size"]),
            leaf_index=int(d["leaf_index"]),
            witness=tuple(d["witness"]),
            peaks_left=tuple(d["peaks_left"]),
            peaks_right=tuple(d["peaks_right"]),
        )

    def to_dict(self) -> dict:
        return {
            "v": self.v,
            "kind": self.kind,
            "size": self.size,
            "leaf_index": self.leaf_index,
            "witness": list(self.witness),
            "peaks_left": list(self.peaks_left),
            "peaks_right": list(self.peaks_right),
        }


@dataclass(frozen=True)
class ConsistencyProof:
    """Proves the MMR at ``size_b >= size_a`` extends the MMR at ``size_a``:
    each old peak is shown contained in the new MMR and re-bags to
    ``root_b``. Wire-identical to ``capsule_emit.checkpoint.core.
    ConsistencyProof``."""

    v: int
    kind: str
    size_a: int
    size_b: int
    old_peaks: tuple[str, ...]
    witness: tuple[tuple[str, ...], ...]
    new_peaks: tuple[str, ...]

    @classmethod
    def from_dict(cls, d: dict) -> ConsistencyProof:
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            size_a=int(d["size_a"]),
            size_b=int(d["size_b"]),
            old_peaks=tuple(d["old_peaks"]),
            witness=tuple(tuple(w) for w in d["witness"]),
            new_peaks=tuple(d["new_peaks"]),
        )

    def to_dict(self) -> dict:
        return {
            "v": self.v,
            "kind": self.kind,
            "size_a": self.size_a,
            "size_b": self.size_b,
            "old_peaks": list(self.old_peaks),
            "witness": [list(w) for w in self.witness],
            "new_peaks": list(self.new_peaks),
        }


@dataclass(frozen=True)
class RangeProof:
    """Proves a contiguous leaf range ``[from_seq, to_seq]`` (inclusive,
    1-indexed) belongs to the MMR of the given ``size`` -- composed from
    inclusion proofs of the two range boundaries. See
    :func:`verify_range_against_checkpoint`'s docstring for exactly what
    this does and does NOT establish."""

    from_seq: int
    to_seq: int
    size: int
    inclusion_from: InclusionProof
    inclusion_to: InclusionProof

    @classmethod
    def from_dict(cls, d: dict) -> RangeProof:
        return cls(
            from_seq=int(d["from_seq"]),
            to_seq=int(d["to_seq"]),
            size=int(d["size"]),
            inclusion_from=InclusionProof.from_dict(d["inclusion_from"]),
            inclusion_to=InclusionProof.from_dict(d["inclusion_to"]),
        )

    def to_dict(self) -> dict:
        return {
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "size": self.size,
            "inclusion_from": self.inclusion_from.to_dict(),
            "inclusion_to": self.inclusion_to.to_dict(),
        }


# -- pure verifiers: total, never raise --------------------------------------


def verify_inclusion(
    root: bytes, size: int, leaf_index: int, body_digest: bytes, proof: InclusionProof
) -> bool:
    """Pure inclusion verification. No reader, never raises. A verifier is a
    total function from (possibly adversarial) bytes to a boolean, never a
    partial one."""
    try:
        _assert_digest(root, "root")
        _assert_digest(body_digest, "body_digest")
        if proof is None or proof.v != 1 or proof.kind != "inclusion":
            return False
        if proof.size != size or proof.leaf_index != leaf_index:
            return False
        if not isinstance(size, int) or size < 0 or size >= MAX_MMR_SIZE:
            return False
        if not isinstance(leaf_index, int) or leaf_index < 0:
            return False
        if (
            not isinstance(proof.witness, (list, tuple))
            or not isinstance(proof.peaks_left, (list, tuple))
            or not isinstance(proof.peaks_right, (list, tuple))
        ):
            return False

        lc = leaf_count(size)
        if leaf_index >= lc:
            return False

        leaf_pos = leaf_index_to_pos(leaf_index)
        pks = peaks(size)
        peak_idx = _find_containing_peak(leaf_pos, pks)
        if peak_idx == -1:
            return False

        peak_pos = pks[peak_idx]
        peak_height = height_at(peak_pos)
        path = _locate_path(peak_pos, peak_height, leaf_pos)

        if len(proof.witness) != len(path):
            return False
        if len(proof.peaks_left) != peak_idx:
            return False
        if len(proof.peaks_right) != len(pks) - peak_idx - 1:
            return False

        witness_bytes = [_parse_digest_hex(w) for w in proof.witness]
        peaks_left_bytes = [_parse_digest_hex(w) for w in proof.peaks_left]
        peaks_right_bytes = [_parse_digest_hex(w) for w in proof.peaks_right]

        acc = leaf_hash(body_digest)
        for step, sib in zip(path, witness_bytes):
            acc = (
                interior_hash(sib, acc, step.parent_pos)
                if step.target_is_right
                else interior_hash(acc, sib, step.parent_pos)
            )

        all_peaks = [*peaks_left_bytes, acc, *peaks_right_bytes]
        computed_root = root_from_peaks(all_peaks)
        return computed_root == root
    except Exception:
        return False


def verify_consistency(
    root_a: bytes, size_a: int, root_b: bytes, size_b: int, proof: ConsistencyProof
) -> bool:
    """Pure consistency verification. No reader, never raises. This is the
    rollback detector: a forked/rewound log that replays a different tail
    after ``size_a`` produces a genuinely different ``root_b`` at the same
    ``size_b`` -- a proof minted against the true history cannot be replayed
    to vouch for the fork, because its peaks re-bag to the true root, not
    the fork's."""
    try:
        _assert_digest(root_a, "root_a")
        _assert_digest(root_b, "root_b")
        if proof is None or proof.v != 1 or proof.kind != "consistency":
            return False
        if proof.size_a != size_a or proof.size_b != size_b:
            return False
        if not isinstance(size_a, int) or size_a < 0:
            return False
        if not isinstance(size_b, int) or size_b < size_a:
            return False
        if (
            not isinstance(proof.old_peaks, (list, tuple))
            or not isinstance(proof.new_peaks, (list, tuple))
            or not isinstance(proof.witness, (list, tuple))
        ):
            return False

        old_peak_positions = peaks(size_a)
        new_peak_positions = peaks(size_b)

        if len(proof.old_peaks) != len(old_peak_positions):
            return False
        if len(proof.new_peaks) != len(new_peak_positions):
            return False
        if len(proof.witness) != len(old_peak_positions):
            return False

        old_peaks_bytes = [_parse_digest_hex(w) for w in proof.old_peaks]
        new_peaks_bytes = [_parse_digest_hex(w) for w in proof.new_peaks]

        if root_from_peaks(old_peaks_bytes) != root_a:
            return False
        if root_from_peaks(new_peaks_bytes) != root_b:
            return False

        for i, p in enumerate(old_peak_positions):
            containing_idx = _find_containing_peak(p, new_peak_positions)
            if containing_idx == -1:
                return False

            new_peak_pos = new_peak_positions[containing_idx]
            new_peak_height = height_at(new_peak_pos)
            path = _locate_path(new_peak_pos, new_peak_height, p)

            w = proof.witness[i]
            if not isinstance(w, (list, tuple)) or len(w) != len(path):
                return False
            w_bytes = [_parse_digest_hex(x) for x in w]

            acc = old_peaks_bytes[i]
            for step, sib in zip(path, w_bytes):
                acc = (
                    interior_hash(sib, acc, step.parent_pos)
                    if step.target_is_right
                    else interior_hash(acc, sib, step.parent_pos)
                )
            if acc != new_peaks_bytes[containing_idx]:
                return False

        return True
    except Exception:
        return False


def verify_range(
    root: bytes,
    from_seq: int,
    to_seq: int,
    from_digest: bytes,
    to_digest: bytes,
    proof: RangeProof,
) -> bool:
    """Pure range verification. No reader, never raises. Proves the boundary
    leaves are genuinely bound to their claimed digests under one common,
    peaks()-validated root; a valid MMR size is only ever a complete
    accounting of exactly ``leaf_count(size)`` leaves, so this also certifies
    every leaf strictly between the boundaries is structurally present.

    Callers wanting the honest "what this does NOT prove" caveat should use
    :func:`verify_range_against_checkpoint`, which wraps this with that
    rendering."""
    try:
        if proof is None or proof.from_seq != from_seq or proof.to_seq != to_seq:
            return False
        if from_seq < 1 or to_seq < from_seq:
            return False
        if leaf_count(proof.size) != to_seq:
            return False
        if not verify_inclusion(root, proof.size, from_seq - 1, from_digest, proof.inclusion_from):
            return False
        if not verify_inclusion(root, proof.size, to_seq - 1, to_digest, proof.inclusion_to):
            return False
        return True
    except Exception:
        return False


# -- checkpoint --------------------------------------------------------------


@dataclass
class Checkpoint:
    """A signed snapshot of one log's MMR peak set at ``mmr_size``. Wire-
    identical to ``capsule_emit.checkpoint.emit.CheckpointRecord`` (verify-
    relevant fields only -- ``witnesses`` are handled separately, as
    receipts, by the orchestration functions below rather than stored here).

    :meth:`digest` is a byte-identical port of ``CheckpointRecord.digest()``:
    sha256 hex of the deterministic JSON (``sort_keys=True``,
    ``separators=(",", ":")``) over every field below except ``signature``.
    This is what gets registered with the Transparency Service, and what a
    verifier must independently recompute rather than trust from a caller-
    supplied value -- otherwise a receipt for an unrelated digest could be
    waved at the wrong checkpoint.
    """

    v: int
    kind: str
    log_id: str
    mmr_size: int
    root: str
    peaks_digest: str
    prev_size: int
    prev_root: str
    key_id: str
    timestamp: str
    signature: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Checkpoint:
        return cls(
            v=int(d["v"]),
            kind=d["kind"],
            log_id=d["log_id"],
            mmr_size=int(d["mmr_size"]),
            root=d["root"],
            peaks_digest=d["peaks_digest"],
            prev_size=int(d["prev_size"]),
            prev_root=d.get("prev_root", ""),
            key_id=d["key_id"],
            timestamp=d["timestamp"],
            signature=d.get("signature", ""),
        )

    def signing_body(self) -> str:
        body = {
            "v": self.v,
            "kind": self.kind,
            "log_id": self.log_id,
            "mmr_size": self.mmr_size,
            "root": self.root,
            "peaks_digest": self.peaks_digest,
            "prev_size": self.prev_size,
            "prev_root": self.prev_root,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        """64-char lowercase hex: sha256 of the signing body (UTF-8)."""
        return hashlib.sha256(self.signing_body().encode()).hexdigest()

    def ts_entry_hash(self) -> str:
        """The Transparency-Service entry hash a receipt for this checkpoint
        must be minted over: sha256(bytes.fromhex(digest())).hex() -- matches
        ``WitnessRecord.entry_hash``'s documented derivation. Independently
        recomputable from the checkpoint's own fields; never trusted from a
        caller-supplied witness object."""
        return hashlib.sha256(bytes.fromhex(self.digest())).digest().hex()

    def root_bytes(self) -> bytes:
        return bytes.fromhex(self.root)

    def prev_root_bytes(self) -> bytes:
        if not self.prev_root:
            raise InvalidArgumentError("checkpoint has no prev_root (it is the first checkpoint)")
        return bytes.fromhex(self.prev_root)


# -- honest rendering ---------------------------------------------------------


def witness_status_line(
    mmr_size: int,
    timestamp: str,
    *,
    current_size: int | None = None,
) -> str:
    """Render "witnessed up to size {S} at time {T}" -- the one honest
    sentence a checkpoint entitles a verifier to say. If `current_size` (a
    larger size the caller separately knows the log has reached -- e.g. from
    a fresher unwitnessed capsule) is supplied, the gap is stated explicitly
    rather than left implicit. Witnessing a size never implies witnessing
    anything beyond it; lag is a fact about the world, not a defect to
    smooth over."""
    line = f"witnessed up to size {mmr_size} at time {timestamp}"
    if current_size is not None and current_size > mmr_size:
        lag = current_size - mmr_size
        line += f" -- {lag} more entr{'y' if lag == 1 else 'ies'} appended since, not yet witnessed"
    return line


# -- result objects + orchestration -------------------------------------------


@dataclass
class InclusionVerification:
    """Outcome of :func:`verify_leaf_against_checkpoint`. ``ok`` is True only
    when both the MMR inclusion proof AND (if a receipt was supplied) the
    checkpoint's TS receipt verify. ``status`` always renders, win or lose --
    an honest verifier reports what it checked even on failure."""

    ok: bool = False
    status: str = ""
    receipt_result: ReceiptResult | None = None
    errors: list = field(default_factory=list)


def verify_leaf_against_checkpoint(
    *,
    body_digest: bytes,
    leaf_index: int,
    checkpoint: Checkpoint,
    proof: InclusionProof,
    receipt: bytes | None = None,
    ts_public_key_pem: bytes | str | None = None,
    current_size: int | None = None,
) -> InclusionVerification:
    """Verify one capsule's inclusion under a checkpoint, offline, end to
    end: (1) the MMR inclusion proof against the checkpoint's committed
    ``root``/``mmr_size``; (2) if `receipt` + `ts_public_key_pem` are given,
    the checkpoint's own Transparency-Service receipt (recomputing
    ``ts_entry_hash()`` independently rather than trusting any caller-
    supplied value). Never raises.

    Passing only `body_digest`/`leaf_index`/`checkpoint`/`proof` verifies the
    log-local claim alone (no third-party freshness evidence); adding
    `receipt` closes the loop to "and a Transparency Service saw this
    checkpoint too."
    """
    result = InclusionVerification()
    try:
        root = checkpoint.root_bytes()
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"checkpoint root is not valid hex: {exc}")
        return result

    inclusion_ok = verify_inclusion(root, checkpoint.mmr_size, leaf_index, body_digest, proof)
    if not inclusion_ok:
        result.errors.append(
            f"inclusion proof does not reconstruct checkpoint root at size {checkpoint.mmr_size}"
        )

    receipt_ok = True
    if receipt is not None:
        if ts_public_key_pem is None:
            result.errors.append("receipt supplied without ts_public_key_pem")
            receipt_ok = False
        else:
            rr = verify_receipt(
                receipt,
                leaf_entry_hex=checkpoint.ts_entry_hash(),
                log_public_key_pem=ts_public_key_pem,
            )
            result.receipt_result = rr
            receipt_ok = rr.ok
            if not rr.ok:
                result.errors.extend(f"checkpoint receipt: {e}" for e in rr.errors)

    result.status = witness_status_line(
        checkpoint.mmr_size, checkpoint.timestamp, current_size=current_size
    )
    result.ok = inclusion_ok and receipt_ok
    return result


@dataclass
class ConsistencyVerification:
    """Outcome of :func:`verify_checkpoint_chain`."""

    ok: bool = False
    status: str = ""
    errors: list = field(default_factory=list)


def verify_checkpoint_chain(
    older: Checkpoint,
    newer: Checkpoint,
    proof: ConsistencyProof,
    *,
    current_size: int | None = None,
) -> ConsistencyVerification:
    """Verify that `newer` genuinely extends `older` for the same
    ``log_id`` -- no rollback, no silent fork -- via a cryptographic
    consistency proof over their peak sets. Never raises.

    This is independent of (and does not require) the ``prev_size``/
    ``prev_root`` fields the checkpoints themselves carry: those are the
    operator's own claim, self-attested; `proof` is the thing a third party
    can actually check without trusting the operator's bookkeeping.
    """
    result = ConsistencyVerification()
    if older.log_id != newer.log_id:
        result.errors.append(f"log_id mismatch: {older.log_id!r} vs {newer.log_id!r}")
        return result
    if newer.mmr_size < older.mmr_size:
        result.errors.append(
            f"newer checkpoint size {newer.mmr_size} < older size {older.mmr_size} -- rollback"
        )
        return result

    try:
        root_a = older.root_bytes()
        root_b = newer.root_bytes()
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"checkpoint root is not valid hex: {exc}")
        return result

    ok = verify_consistency(root_a, older.mmr_size, root_b, newer.mmr_size, proof)
    if not ok:
        result.errors.append(
            f"consistency proof does not link size {older.mmr_size} to size "
            f"{newer.mmr_size} -- log may have been rolled back or forked"
        )
    result.status = witness_status_line(newer.mmr_size, newer.timestamp, current_size=current_size)
    result.ok = ok
    return result


@dataclass
class RangeVerification:
    """Outcome of :func:`verify_range_against_checkpoint`. ``scope_note`` is
    always populated on success -- the honest bound on what a range proof
    establishes, stated even when nobody asked."""

    ok: bool = False
    status: str = ""
    scope_note: str = ""
    errors: list = field(default_factory=list)


def verify_range_against_checkpoint(
    *,
    from_seq: int,
    to_seq: int,
    from_digest: bytes,
    to_digest: bytes,
    checkpoint: Checkpoint,
    proof: RangeProof,
    current_size: int | None = None,
) -> RangeVerification:
    """Verify that log records ``[from_seq, to_seq]`` (inclusive) are
    genuinely, contiguously present under `checkpoint`. Never raises.

    Range-intact is not all-traffic: this proves the claimed range is a
    real, unbroken slice of the checkpointed log (a scope-census of exactly
    those records, nothing more) -- it does NOT prove no records exist
    outside ``[from_seq, to_seq]``, that the log started at record 1, or
    that ``to_seq`` is the log's current end. A range proof answers "is
    this slice real and unaltered", never "is this the whole log".
    """
    result = RangeVerification()
    try:
        root = checkpoint.root_bytes()
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"checkpoint root is not valid hex: {exc}")
        return result

    ok = verify_range(root, from_seq, to_seq, from_digest, to_digest, proof)
    if not ok:
        result.errors.append(
            f"range proof for [{from_seq}, {to_seq}] does not verify against checkpoint "
            f"root at size {checkpoint.mmr_size}"
        )

    n = to_seq - from_seq + 1
    result.scope_note = (
        f"proves {n} of {n} claimed records in [{from_seq}, {to_seq}] are present, "
        "contiguous, and unaltered under this checkpoint -- it does NOT prove these are "
        "the only records the log holds, nor that no records exist outside this range "
        "(range-intact != all-traffic)"
    )
    result.status = witness_status_line(
        checkpoint.mmr_size, checkpoint.timestamp, current_size=current_size
    )
    result.ok = ok
    return result
