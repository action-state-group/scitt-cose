# SPDX-License-Identifier: Apache-2.0
"""AAC capsule parser and digest-graph builder for the P1 verification surface.

Parses an Agent Action Capsule JSON dict into a GraphView that the capsule-page
renderer uses for digest-graph display, privilege-log view, and
VERIFIED-BUT-OPAQUE handling of unknown artifact types.

No external dependencies beyond the stdlib: importable in the same zero-framework
environment as hosted.py.

Profile plug-point: register additional profile parsers in ``PROFILE_PARSERS``.

**Not part of the published ``scitt-cose`` package.** This module lives outside
the ``scitt_cose/`` directory (see ``[tool.setuptools] packages`` in
pyproject.toml) so the neutral wheel carries no application-profile awareness.
It is consumed only by its sibling ``hosted_profiles/hosted.py`` when run from
a full repo checkout (the deployed hosted verify surface — see the
Dockerfile), and by the test suite.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Known AAC artifact types — profile-specific rendering is available for these.
# Unknown types receive VERIFIED-BUT-OPAQUE treatment (§5.5 property): the
# cryptographic verification runs identically; the rendering is opaque.
# ---------------------------------------------------------------------------
_KNOWN_TYPES: frozenset[str] = frozenset({
    "capsule",
    "offer_terms",
    "wicket_manifest",
    "response",
    "gate_checks",
    "subject",
    "bilateral_subject",
    "compute_attestation",
    "agent_input",
    "agent_output",
})


def _is_hex64(s: object) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    return frozenset(s.lower()).issubset(frozenset("0123456789abcdef"))


def _json_digest(obj: Any) -> str:
    """Canonical JSON (sorted keys, compact) SHA-256 hex — mirrors agent_action_capsule."""
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(blob).hexdigest()


def _short(digest: str) -> str:
    return digest[:8] + "…" + digest[-4:]


def _unwrap(cap: dict) -> dict:
    """Unwrap a Disclosure Envelope (``{"capsule": {...}, "disclosures": {...}}``)
    to the underlying capsule. A bare capsule (no "capsule" key) passes through
    unchanged. Mirrors ``CAPSULE_JS``'s ``unwrapEnvelope()``."""
    inner = cap.get("capsule") if isinstance(cap, dict) else None
    return inner if isinstance(inner, dict) else cap


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    id: str          # unique key in this graph (usually the hex digest)
    node_type: str   # e.g. "capsule", "offer_terms", "wicket_manifest"
    digest: str      # 64-hex SHA-256
    label: str       # short human label for display
    is_known_type: bool
    is_withheld: bool = True          # True → digest only; payload not provided
    revealed_payload: Any = None      # non-None if payload provided AND digest matches


@dataclass
class GraphEdge:
    from_id: str
    to_id: str
    label: str        # "attests_over" | "chains_to" | "commits_to" | "effect_response"
    edge_type: str    # same values; kept separate so callers can remap display


@dataclass
class PrivilegeLogEntry:
    artifact_id: str    # display key, e.g. "sealed_terms_hash"
    artifact_type: str
    digest: str
    is_withheld: bool
    is_known_type: bool
    match_ok: bool | None   # None = withheld; True/False = revealed and recomputed
    context: str            # dotted path to where this digest appears in the capsule


@dataclass
class GraphView:
    profile: str                # "aac" for now; new profiles register in PROFILE_PARSERS
    is_binding: bool            # True = bilateral (two capsules), False = single
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    privilege_log: list[PrivilegeLogEntry] = field(default_factory=list)
    raw_capsules: list[dict] = field(default_factory=list)
    unknown_types: list[str] = field(default_factory=list)
    parse_error: str | None = None  # set if capsule JSON is not recognisable


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def parse_capsule(data: dict) -> GraphView:
    """Parse an AAC capsule (single or bilateral binding) into a GraphView.

    Accepts:
    * A single capsule dict (has ``capsule_id`` at top level).
    * A bilateral binding dict (has ``buyer_capsule`` + ``seller_capsule``).

    Returns a populated GraphView on success; ``GraphView.parse_error`` is set if
    the input is not recognisable.
    """
    if not isinstance(data, dict):
        return GraphView(profile="aac", is_binding=False, parse_error="not a JSON object")
    if "buyer_capsule" in data and "seller_capsule" in data:
        return _parse_binding(data)
    if isinstance(data.get("capsule"), dict):
        # Disclosure Envelope (draft-mih-scitt-agent-action-capsule-disclosure-envelope-00):
        # {"capsule": {...unmodified...}, "disclosures": {"agent_input": ..., "agent_output": ...}}.
        # A bare capsule (no "capsule" wrapper key) is the legacy/WITHHELD-only shape below.
        disclosures = data.get("disclosures")
        return _parse_single(data["capsule"], disclosures if isinstance(disclosures, dict) else None)
    if "capsule_id" in data:
        return _parse_single(data)
    return GraphView(profile="aac", is_binding=False, parse_error="not an AAC capsule or binding")


def _parse_single(cap: dict, disclosures: dict | None = None) -> GraphView:
    view = GraphView(profile="aac", is_binding=False)
    view.raw_capsules = [cap]
    capsule_id = cap.get("capsule_id", "")
    if not _is_hex64(capsule_id):
        view.parse_error = f"capsule_id is not a 64-hex digest: {capsule_id!r}"
        return view
    cap_node = GraphNode(
        id=capsule_id, node_type="capsule", digest=capsule_id,
        label=f"capsule {_short(capsule_id)}", is_known_type=True,
    )
    view.nodes.append(cap_node)
    _extract_refs(view, cap, capsule_id, prefix="", disclosures=disclosures)
    return view


def _parse_binding(data: dict) -> GraphView:
    view = GraphView(profile="aac", is_binding=True)
    buyer_cap = data.get("buyer_capsule") or {}
    seller_cap = data.get("seller_capsule") or {}
    view.raw_capsules = [c for c in (buyer_cap, seller_cap) if c]
    buyer_id = buyer_cap.get("capsule_id", "")
    seller_id = seller_cap.get("capsule_id", "")
    sealed_hash = data.get("sealed_terms_hash", "")
    terms = data.get("terms")

    if _is_hex64(buyer_id):
        view.nodes.append(GraphNode(
            id=buyer_id, node_type="capsule", digest=buyer_id,
            label=f"buyer capsule {_short(buyer_id)}", is_known_type=True,
        ))
    if _is_hex64(seller_id):
        view.nodes.append(GraphNode(
            id=seller_id, node_type="capsule", digest=seller_id,
            label=f"seller capsule {_short(seller_id)}", is_known_type=True,
        ))

    if _is_hex64(sealed_hash):
        revealed = terms is not None
        match_ok = (_json_digest(terms) == sealed_hash) if revealed else None
        view.nodes.append(GraphNode(
            id=sealed_hash, node_type="offer_terms", digest=sealed_hash,
            label=f"offer terms {_short(sealed_hash)}",
            is_known_type=True, is_withheld=not revealed,
            revealed_payload=terms if revealed else None,
        ))
        view.privilege_log.append(PrivilegeLogEntry(
            artifact_id="sealed_terms_hash", artifact_type="offer_terms",
            digest=sealed_hash, is_withheld=not revealed, is_known_type=True,
            match_ok=match_ok, context="binding.sealed_terms_hash",
        ))
        if _is_hex64(buyer_id):
            view.edges.append(GraphEdge(buyer_id, sealed_hash, "attests_over", "attests_over"))
        if _is_hex64(seller_id):
            view.edges.append(GraphEdge(seller_id, sealed_hash, "attests_over", "attests_over"))

    if _is_hex64(buyer_id) and _is_hex64(seller_id):
        view.edges.append(GraphEdge(seller_id, buyer_id, "chains_to", "chains_to"))

    envelope_disclosures = data.get("disclosures") if isinstance(data.get("disclosures"), dict) else {}
    buyer_disclosures = envelope_disclosures.get("buyer") if isinstance(envelope_disclosures.get("buyer"), dict) else None
    seller_disclosures = envelope_disclosures.get("seller") if isinstance(envelope_disclosures.get("seller"), dict) else None
    if _is_hex64(buyer_id):
        _extract_refs(view, buyer_cap, buyer_id, prefix="buyer", disclosures=buyer_disclosures)
    if _is_hex64(seller_id):
        _extract_refs(view, seller_cap, seller_id, prefix="seller", disclosures=seller_disclosures)
    return view


def _extract_refs(
    view: GraphView, cap: dict, capsule_id: str, prefix: str, disclosures: dict | None = None
) -> None:
    """Extract digest-typed fields from cap into view.nodes/edges/privilege_log.

    ``disclosures`` is the Disclosure Envelope's out-of-band {agent_input, agent_output}
    object for this capsule — NEVER read from cap["model_attestation"]["compute_attestation"],
    which is digest-committed (embedding a payload there would change capsule_id).
    """
    disclosures = disclosures or {}
    seen = {n.id for n in view.nodes}
    pfx = f"{prefix}." if prefix else ""

    def _add(digest: str, node_type: str, label: str, context: str) -> bool:
        if digest in seen:
            return False
        is_known = node_type in _KNOWN_TYPES
        if not is_known and node_type not in view.unknown_types:
            view.unknown_types.append(node_type)
        view.nodes.append(GraphNode(
            id=digest, node_type=node_type, digest=digest,
            label=f"{label} {_short(digest)}", is_known_type=is_known, is_withheld=True,
        ))
        seen.add(digest)
        view.privilege_log.append(PrivilegeLogEntry(
            artifact_id=label, artifact_type=node_type, digest=digest,
            is_withheld=True, is_known_type=is_known, match_ok=None, context=context,
        ))
        return True

    # Prior capsule (chain link)
    chain = cap.get("chain") or {}
    prior_id = chain.get("parent_capsule_id", "")
    if _is_hex64(prior_id) and prior_id not in seen:
        view.nodes.append(GraphNode(
            id=prior_id, node_type="capsule", digest=prior_id,
            label=f"prior capsule {_short(prior_id)}", is_known_type=True,
        ))
        seen.add(prior_id)
        view.edges.append(GraphEdge(capsule_id, prior_id, "chains_to", "chains_to"))

    # Subject digest (compute_attestation)
    ma = cap.get("model_attestation") or {}
    ca = ma.get("compute_attestation") or {}
    subj = ca.get("subject_digest", "")
    if _is_hex64(subj):
        if _add(subj, "subject", "subject", f"{pfx}compute_attestation.subject_digest"):
            view.edges.append(GraphEdge(capsule_id, subj, "attests_over", "attests_over"))

    # Agent input / output digests (compute_attestation) — withheld by default;
    # reveal when preimage is supplied alongside the digest under the sibling key.
    for _key, _type, _label in (
        ("agent_input_digest", "agent_input", "agent input"),
        ("agent_output_digest", "agent_output", "agent output"),
    ):
        _digest = ca.get(_key, "")
        if not _is_hex64(_digest) or _digest in seen:
            continue
        _pre = disclosures.get(_type)
        _revealed = _pre is not None
        if _revealed:
            # String payloads are hashed as raw UTF-8 bytes; objects use canonical JSON.
            if isinstance(_pre, str):
                _match = hashlib.sha256(_pre.encode()).hexdigest() == _digest
            else:
                _match = _json_digest(_pre) == _digest
        else:
            _match = None
        _ctx = (
            "payload carried in fragment; recomputed against committed digest"
            if _revealed
            else f"{pfx}compute_attestation — payload not carried in the record"
        )
        view.nodes.append(GraphNode(
            id=_digest, node_type=_type, digest=_digest,
            label=f"{_label} {_short(_digest)}", is_known_type=True,
            is_withheld=not _revealed,
            revealed_payload=_pre if _revealed else None,
        ))
        seen.add(_digest)
        view.privilege_log.append(PrivilegeLogEntry(
            artifact_id=_label, artifact_type=_type,
            digest=_digest, is_withheld=not _revealed, is_known_type=True,
            match_ok=_match, context=_ctx,
        ))
        view.edges.append(GraphEdge(capsule_id, _digest, "attests_over", "attests_over"))

    # Effect response digest
    effect = cap.get("effect") or {}
    resp_digest = effect.get("response_digest", "")
    if _is_hex64(resp_digest):
        if _add(resp_digest, "response", "response", f"{pfx}effect.response_digest"):
            view.edges.append(GraphEdge(capsule_id, resp_digest, "effect_response", "effect_response"))

    # Constraint evidence digests (withheld manifests)
    for c in (cap.get("constraints") or []):
        ev = c.get("evidence_digest", "")
        cid = c.get("id", "constraint")
        if _is_hex64(ev):
            if _add(ev, "wicket_manifest", f"manifest [{cid}]",
                    f"{pfx}constraints[{cid}].evidence_digest"):
                view.edges.append(GraphEdge(capsule_id, ev, "commits_to", "commits_to"))


# ---------------------------------------------------------------------------
# Ritual evaluation — the 4-stage conformance surface (Integrity / Sequence /
# Authenticity / Witness) used by the tamper-states view. Operates over a
# *bundle*: an ordered list of capsule dicts (a single capsule is a bundle of
# one). No network access here — Witness is evaluated from data the caller
# already fetched (or declares absent), never fetched inside this function.
# ---------------------------------------------------------------------------

@dataclass
class ChainGap:
    before_index: int   # index of the capsule right before the gap
    after_index: int     # index of the capsule right after the gap
    missing_parent: str  # the parent_capsule_id that isn't in the bundle


def find_chain_gaps(capsules: list[dict]) -> list[ChainGap]:
    """Detect breaks in ``chain.parent_capsule_id`` linkage across a bundle.

    A gap exists when a capsule names a well-formed parent digest that does
    not match any other capsule_id present in the bundle. Order in ``capsules``
    is assumed to be the display/chain order (as loaded from a bundle array).
    Each item is unwrapped first — a Disclosure-Envelope-wrapped bundle item
    carries capsule_id/chain nested under "capsule", not at the top level.
    """
    caps = [_unwrap(c) for c in capsules]
    ids = {c.get("capsule_id") for c in caps if _is_hex64(c.get("capsule_id", ""))}
    gaps: list[ChainGap] = []
    for i, cap in enumerate(caps):
        if i == 0:
            continue
        parent = (cap.get("chain") or {}).get("parent_capsule_id", "")
        if _is_hex64(parent) and parent not in ids:
            gaps.append(ChainGap(before_index=i - 1, after_index=i, missing_parent=parent))
    return gaps


@dataclass
class RitualStage:
    name: str    # "Integrity" | "Sequence" | "Authenticity" | "Witness"
    status: str  # "pass" | "fail" | "skip" — "skip" means not disproven, not checked
    detail: str


@dataclass
class Finding:
    code: str    # "digest_mismatch" | "chain_gap" | "witness_invalid"
    stage: str
    label: str
    text: str
    meta: str


@dataclass
class RitualSummary:
    stages: list[RitualStage] = field(default_factory=list)
    finding: Finding | None = None


def _check_authenticity(capsules: list[dict]) -> RitualStage:
    """Verify any embedded signed statements for real; never trust a claimed flag.

    A capsule may carry an optional ``signed_statement`` sidecar:
    ``{"statement_b64": ..., "pubkey_pem": ...}`` — a COSE_Sign1 Signed
    Statement over that capsule's own canonical bytes. Capsule bundles carry
    no COSE bytes by default (the JSON travels in the URL fragment only), so
    this stage is honestly "skip" when none is supplied — it never reports
    "pass" for a check that did not run.
    """
    sidecars = [c.get("signed_statement") for c in capsules if c.get("signed_statement")]
    if not sidecars:
        return RitualStage(
            "Authenticity", "skip", "not checked — no signed statement provided for this bundle"
        )
    import base64

    from scitt_cose.statement import parse_signed_statement

    for sc in sidecars:
        try:
            stmt_bytes = base64.b64decode(sc.get("statement_b64", ""))
            pub = sc.get("pubkey_pem", "")
            pub_bytes = pub.encode() if isinstance(pub, str) else pub
            parsed = parse_signed_statement(stmt_bytes, public_key_pem=pub_bytes)
            if parsed.get("signature_verified") is not True:
                return RitualStage("Authenticity", "fail", "at least one signature did not verify")
        except Exception:  # noqa: BLE001 - malformed sidecar counts as a fail, not a crash
            return RitualStage("Authenticity", "fail", "at least one signature did not verify")
    return RitualStage(
        "Authenticity", "pass", "all signatures hold — verified over the original bytes"
    )


def _check_witness(witness: dict | None) -> RitualStage:
    """Report declared witness state — never disproven by absence or timeout.

    ``witness`` shape: ``{"held": int, "configured": int, "reachable": bool,
    "verified": bool | None}``. Absent → "skip" (no witness data provided).
    Unreachable → "skip" ("unreachable is never rendered as disproven").
    An explicit ``verified: False`` (a fetched receipt that failed its
    inclusion-proof check) is the one real "fail" path.
    """
    if witness is None:
        return RitualStage("Witness", "skip", "no witness data provided")
    if witness.get("verified") is False:
        return RitualStage("Witness", "fail", "inclusion proof did not verify")
    if witness.get("reachable") is False:
        return RitualStage(
            "Witness", "skip",
            "independent-witness check skipped (unreachable) — everything else verified; "
            "reconnect any time to complete it",
        )
    held = witness.get("held", 0)
    configured = witness.get("configured") or held or 1
    if held < configured:
        return RitualStage(
            "Witness", "skip", f"witnessed {held} of {configured} · retrying — rung held"
        )
    return RitualStage("Witness", "pass", f"witnessed {held} of {configured}")


def evaluate_ritual(
    capsules: list[dict],
    views: list[GraphView],
    *,
    witness: dict | None = None,
) -> RitualSummary:
    """Evaluate the 4-stage ritual over an ordered bundle and its parsed views.

    ``views`` must be ``parse_capsule`` results for each entry in ``capsules``,
    in the same order (single-capsule callers pass one-element lists of each).
    """
    stages: list[RitualStage] = []
    finding: Finding | None = None

    # Integrity: any revealed artifact whose recomputed digest disagrees with
    # its committed digest fails the stage. First mismatch becomes the finding.
    mismatches = [e for v in views for e in v.privilege_log if e.match_ok is False]
    if mismatches:
        e = mismatches[0]
        stages.append(RitualStage(
            "Integrity", "fail",
            f"record fails at stage digest_mismatch — {e.context} no longer matches its fingerprint",
        ))
        finding = Finding(
            code="digest_mismatch", stage="Integrity", label="The finding",
            text=f"{e.artifact_id} ({e.context}) is not the value that was sealed.",
            meta=f"failed stage: digest_mismatch · field group: {e.context} · digest {e.digest[:8]}…",
        )
    else:
        stages.append(RitualStage("Integrity", "pass", "every record matches its fingerprint"))

    # Sequence: chain-gap detection across the bundle. Only becomes the
    # displayed finding if Integrity did not already claim that slot.
    gaps = find_chain_gaps(capsules)
    if gaps:
        g = gaps[0]
        before_id = _unwrap(capsules[g.before_index]).get("capsule_id", "")
        after_id = _unwrap(capsules[g.after_index]).get("capsule_id", "")
        stages.append(RitualStage(
            "Sequence", "fail",
            f"gap between record {g.before_index + 1} and record {g.after_index + 1} "
            f"— record {g.after_index + 1} names a parent that is not here",
        ))
        if finding is None:
            finding = Finding(
                code="chain_gap", stage="Sequence", label="The finding",
                text=(
                    f"Whatever sits between record {g.before_index + 1} and "
                    f"record {g.after_index + 1} is not in this bundle. That is "
                    "information, not just an error: the gap has a location and "
                    "two edges you can browse from."
                ),
                meta=(
                    f"failed stage: chain_gap · window: {before_id[:8]}…→{after_id[:8]}… "
                    f"· missing parent {g.missing_parent[:8]}…"
                ),
            )
    else:
        stages.append(RitualStage(
            "Sequence", "pass", "unbroken — every record names the one before it"
        ))

    stages.append(_check_authenticity(capsules))
    stages.append(_check_witness(witness))

    return RitualSummary(stages=stages, finding=finding)


@dataclass
class RecordNote:
    index: int
    note: str            # "verifies" | "digest_mismatch" | "cites an altered record"
    is_altered: bool      # this record itself failed Integrity
    cites_altered: bool   # this record chains (directly or transitively) to an altered one


def annotate_records(capsules: list[dict], views: list[GraphView]) -> list[RecordNote]:
    """Per-record annotation for the affected-records table.

    A record that itself fails Integrity is "digest_mismatch". A record that
    doesn't fail itself but chains — directly or transitively, via
    ``chain.parent_capsule_id`` — to an altered record still verifies on its
    own terms, so it is FLAGGED ("cites an altered record"), never failed.
    Each item is unwrapped first — see ``find_chain_gaps``.
    """
    caps = [_unwrap(c) for c in capsules]
    altered_ids = {
        caps[i].get("capsule_id", "")
        for i, v in enumerate(views)
        if any(e.match_ok is False for e in v.privilege_log) and _is_hex64(caps[i].get("capsule_id", ""))
    }
    by_id = {c.get("capsule_id", ""): c for c in caps if _is_hex64(c.get("capsule_id", ""))}

    notes: list[RecordNote] = []
    for i, cap in enumerate(caps):
        cid = cap.get("capsule_id", "")
        if cid in altered_ids:
            notes.append(RecordNote(i, "digest_mismatch", True, False))
            continue
        cites = False
        seen: set[str] = set()
        cur = cap
        while True:
            parent = (cur.get("chain") or {}).get("parent_capsule_id", "")
            if not _is_hex64(parent) or parent in seen:
                break
            seen.add(parent)
            if parent in altered_ids:
                cites = True
                break
            cur = by_id.get(parent)
            if cur is None:
                break
        notes.append(RecordNote(i, "cites an altered record" if cites else "verifies", False, cites))
    return notes


# ---------------------------------------------------------------------------
# Profile plug-point — register additional profile parsers here.
# New profiles: add a callable ``parse(data: dict) -> GraphView`` to this dict.
# The capsule page's detect_profile() runs through keys in order.
# ---------------------------------------------------------------------------
PROFILE_PARSERS: dict[str, Any] = {
    "aac": parse_capsule,
    # Machine-Mandate profile — accurate rendering of Tyche Institute's published vocabulary.
    # Source: tyche-institute/machine-mandate@524e6a3. Not an endorsement.
    "machine-mandate": None,  # populated on first import of machine_mandate to avoid circularity
}


def detect_profile(data: dict) -> str:
    """Return the profile key for ``data``, or 'unknown' if unrecognised.

    Profiles checked in priority order: aac first, then machine-mandate.
    New profiles: register in PROFILE_PARSERS and add detection here.
    """
    if isinstance(data, dict):
        if "capsule_id" in data or "buyer_capsule" in data or isinstance(data.get("capsule"), dict):
            return "aac"
        # MachineMandate: vct, eat_profile, or action_hash marker
        from .machine_mandate import is_machine_mandate  # lazy to avoid circular
        if is_machine_mandate(data):
            return "machine-mandate"
    return "unknown"


# Populate the machine-mandate slot now that machine_mandate is importable.
# This lazy approach avoids a circular import (machine_mandate imports from aac).
def _register_machine_mandate() -> None:
    try:
        from .machine_mandate import parser_entry
        PROFILE_PARSERS["machine-mandate"] = parser_entry
    except Exception:  # noqa: BLE001
        pass  # missing optional dependency; machine-mandate slot stays None

_register_machine_mandate()


__all__ = [
    "GraphNode",
    "GraphEdge",
    "PrivilegeLogEntry",
    "GraphView",
    "ChainGap",
    "RitualStage",
    "Finding",
    "RitualSummary",
    "RecordNote",
    "PROFILE_PARSERS",
    "detect_profile",
    "parse_capsule",
    "find_chain_gaps",
    "evaluate_ritual",
    "annotate_records",
]
