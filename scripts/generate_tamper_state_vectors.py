#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME generator for the ``test-vectors/tamper-states/`` vector set.

This is a *different* conformance surface from ``test-vectors/v1/``: v1 is
receipt-level (RFC 9162 SHA-256 inclusion proofs over a single COSE_Sign1
statement). This set is capsule-graph-level — it exercises
``hosted_profiles.aac.evaluate_ritual`` (Integrity / Sequence / Authenticity /
Witness) over an ordered *bundle* of Agent Action Capsules, the same model the
``/v/<capsule_id>`` verification page parses client-side. No existing vector
set (this repo's v1, or agent-action-capsule's disposition-semantics vectors)
covers this; see the T7 task notes for that search.

Each vector directory contains:
  bundle.json    the capsule bundle, in the same {"bundle": [...], "witness":
                 {...}} shape the capsule page's URL fragment accepts
  expected.json  the expected RitualSummary + per-record annotations,
                 produced by actually running hosted_profiles.aac against the
                 bundle (never hand-typed)

One capsule per bundle carries a genuine Ed25519-signed statement
(``signed_statement``) over its own canonical bytes, so Authenticity is a real
cryptographic check, not a fabricated pass.

Refuses to overwrite an already-published vector directory (append-only, like
v1) — delete it first if you intend to regenerate.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from hosted_profiles import aac  # noqa: E402
from scitt_cose.statement import build_signed_statement  # noqa: E402

OUT = REPO / "test-vectors" / "tamper-states"


def _digest(obj: object) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(blob).hexdigest()


def _hex_id(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


_SIGN_KEY = ed25519.Ed25519PrivateKey.generate()
_PRIV_PEM = _SIGN_KEY.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
)
_PUB_PEM = _SIGN_KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)


def _sign(capsule: dict, *, issuer: str) -> dict:
    """Build a genuine COSE_Sign1 signed statement over capsule's own canonical bytes."""
    payload = json.dumps(capsule, sort_keys=True, separators=(",", ":")).encode()
    stmt = build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=_PRIV_PEM,
        issuer=issuer,
        subject=capsule["capsule_id"],
        content_type="application/json",
    )
    return {
        "statement_b64": base64.b64encode(stmt).decode(),
        "pubkey_pem": _PUB_PEM.decode(),
    }


def _base_capsule(vector: str, i: int, *, parent: str | None) -> dict:
    cap = {
        "capsule_id": _hex_id(f"{vector}::capsule::{i}"),
        "action_type": "decide",
        "operator": "acme-research",
        "timestamp": f"2026-08-0{i + 1}T14:0{i}:00Z",
        "disposition": {"decision": "accept", "verdict_class": "executed"},
    }
    if parent is not None:
        cap["chain"] = {"parent_capsule_id": parent, "relation": "confirms"}
    return cap


def _summarize(bundle: list[dict], witness: dict | None) -> dict:
    """Run the real evaluator — expected.json is derived, never hand-typed."""
    views = [aac.parse_capsule(c) for c in bundle]
    summary = aac.evaluate_ritual(bundle, views, witness=witness)
    notes = aac.annotate_records(bundle, views)
    gaps = aac.find_chain_gaps(bundle)
    return {
        "stages": [{"name": s.name, "status": s.status, "detail": s.detail} for s in summary.stages],
        "finding": (
            None
            if summary.finding is None
            else {
                "code": summary.finding.code,
                "stage": summary.finding.stage,
                "text": summary.finding.text,
                "meta": summary.finding.meta,
            }
        ),
        "gaps": [
            {"before_index": g.before_index, "after_index": g.after_index, "missing_parent": g.missing_parent}
            for g in gaps
        ],
        "records": [
            {"index": n.index, "note": n.note, "is_altered": n.is_altered, "cites_altered": n.cites_altered}
            for n in notes
        ],
    }


def build_digest_mismatch() -> tuple[list[dict], dict | None]:
    v = "digest_mismatch"
    c0 = _base_capsule(v, 0, parent=None)
    c1 = _base_capsule(v, 1, parent=c0["capsule_id"])
    committed = _digest({"tool": "refund", "amount_usd": 1180})
    c1["model_attestation"] = {
        "compute_attestation": {
            "agent_input_digest": committed,
            # tampered: revealed preimage does not hash to the committed digest
            "agent_input": {"tool": "refund", "amount_usd": 9999},
        }
    }
    c2 = _base_capsule(v, 2, parent=c1["capsule_id"])  # cites the altered record
    for cap in (c0, c1, c2):
        cap["signed_statement"] = _sign(cap, issuer="acme-research")
    return [c0, c1, c2], {"held": 1, "configured": 1, "reachable": True, "verified": True}


def build_chain_gap() -> tuple[list[dict], dict | None]:
    v = "chain_gap"
    c0 = _base_capsule(v, 0, parent=None)
    c1 = _base_capsule(v, 1, parent=c0["capsule_id"])
    missing_parent = _hex_id(f"{v}::capsule::absent")
    c2 = _base_capsule(v, 2, parent=missing_parent)  # names a parent not in this bundle
    for cap in (c0, c1, c2):
        cap["signed_statement"] = _sign(cap, issuer="acme-research")
    return [c0, c1, c2], {"held": 1, "configured": 1, "reachable": True, "verified": True}


def build_witness_downgrade() -> tuple[list[dict], dict | None]:
    v = "witness_downgrade"
    c0 = _base_capsule(v, 0, parent=None)
    c1 = _base_capsule(v, 1, parent=c0["capsule_id"])
    c2 = _base_capsule(v, 2, parent=c1["capsule_id"])
    for cap in (c0, c1, c2):
        cap["signed_statement"] = _sign(cap, issuer="acme-research")
    # Declared demo witness config: enterprise bundle configured for 3
    # independent witnesses, only 1 has reported in so far. This is
    # fixture-declared data, illustrating an async multi-witness deployment
    # shape — the live anchor.agentactioncapsule.org is single-witness today.
    return [c0, c1, c2], {"held": 1, "configured": 3, "reachable": True}


def build_offline_pass() -> tuple[list[dict], dict | None]:
    v = "offline_pass"
    c0 = _base_capsule(v, 0, parent=None)
    c1 = _base_capsule(v, 1, parent=c0["capsule_id"])
    c2 = _base_capsule(v, 2, parent=c1["capsule_id"])
    for cap in (c0, c1, c2):
        cap["signed_statement"] = _sign(cap, issuer="acme-research")
    # No witness data — network unreachable; everything else verified locally.
    return [c0, c1, c2], {"reachable": False}


VECTORS = {
    "digest_mismatch": build_digest_mismatch,
    "chain_gap": build_chain_gap,
    "witness_downgrade": build_witness_downgrade,
    "offline_pass": build_offline_pass,
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, builder in VECTORS.items():
        vec_dir = OUT / name
        if vec_dir.exists():
            print(f"refusing to overwrite already-published vector: {vec_dir}", file=sys.stderr)
            continue
        vec_dir.mkdir(parents=True)
        bundle, witness = builder()
        bundle_doc = {"bundle": bundle, "witness": witness}
        expected = _summarize(bundle, witness)
        (vec_dir / "bundle.json").write_text(json.dumps(bundle_doc, indent=2, sort_keys=True) + "\n")
        (vec_dir / "expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
        print(f"wrote {vec_dir}")


if __name__ == "__main__":
    main()
