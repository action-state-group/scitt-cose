# SPDX-License-Identifier: Apache-2.0
"""Northwind Demo Bank — disputed-refund capsule chain fixture generator.

Emits a two-capsule chain demonstrating the Agent Action Capsule spec
on the live SCITT transparency surface.  All content is SYNTHETIC —
fictional bank name, fictional parties, labeled as demonstration records.
Do NOT use real customer data or real bank names here.

Usage:
    python3 demo/northwind_refund_chain.py [--output demo/fixtures]

Outputs (in --output directory):
    capsule_a.json          Capsule A (fyi  — disputed-txn query)
    capsule_b_approve.json  Capsule B (decide — refund approved, chained to A)
    capsule_c_deny.json     Capsule C (decide — refund denied, chained to A)
    tampered_b.json         Capsule B with one byte flipped (verify surface shows break)
    withheld_a.json         Withheld-artifacts manifest for A (for demo tool)
    withheld_b.json         Withheld-artifacts manifest for B-approve (for demo tool)
    reveal_a.json           Disclosed PII for A (recompute-and-match demo)
    anchor_results.json     capsule_ids, entry_hashes, receipt_b64, permalink stubs
    receipts/               .cose bytes per anchored capsule

Run once to generate; the anchor results are committed so the demo can
reproduce the same permalinks without re-anchoring.

HOLD on publish-permalinks until verify.actionstate.ai P1 deploys.
"""
from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Imports from the installed packages
# ---------------------------------------------------------------------------
from agent_action_capsule import (
    ConstraintRecord,
    Disposition,
    EffectRecord,
    emit,
    json_digest,
)
from agent_action_capsule.anchor import submit_anchor


def _sha256_jcs(obj: object) -> str:
    """SHA-256 over JCS (RFC 8785) canonical JSON — same as json_digest()."""
    return json_digest(obj)


# ---------------------------------------------------------------------------
# SYNTHETIC demo data — ALL FICTIONAL
# ---------------------------------------------------------------------------

BANK_NAME = "Northwind Demo Bank"
TXN_REF = "NDB-2024-88A-9921"
DEMO_LABEL = "demonstration record"

# Capsule A — agent input (DISCLOSED): the public dispute query
AGENT_INPUT_A = {
    "record_type": DEMO_LABEL,
    "bank": BANK_NAME,
    "request": "query_disputed_transaction",
    "transaction_ref": TXN_REF,
    "dispute_category": "unauthorized_charge",
    "query_timestamp": "2024-03-16T09:15:00Z",
    "subject_type": "transaction_dispute_query",
}

# Capsule A — agent output (WITHHELD: customer PII): full query response
AGENT_OUTPUT_A_PII = {
    "record_type": DEMO_LABEL,
    "bank": BANK_NAME,
    "transaction_ref": TXN_REF,
    "customer_name": "Morgan Chen",
    "account_number_suffix": "7842",
    "transaction_amount_usd": "247.50",
    "transaction_date": "2024-03-15",
    "merchant": "Acme Online Store",
    "dispute_status": "pending_review",
    "transaction_category": "online_retail",
}

# Capsule B — constraint evidence (WITHHELD: internal policy)
CONSTRAINT_EVIDENCE_B = {
    "record_type": DEMO_LABEL,
    "bank": BANK_NAME,
    "policy_id": "NDB-REFUND-POLICY-2024-v3",
    "policy_version_hash": "sha256:a1b2c3d4",
    "max_refund_threshold_usd": "500.00",
    "transaction_amount_usd": "247.50",
    "check_result": "within_threshold",
    "evaluated_at": "2024-03-16T14:22:58Z",
}

# Capsule B — effect / refund confirmation (WITHHELD: operational data)
REFUND_CONFIRMATION_B = {
    "record_type": DEMO_LABEL,
    "bank": BANK_NAME,
    "transaction_ref": TXN_REF,
    "refund_reference": "REF-NDB-2024-88A-9921-R1",
    "refund_amount_usd": "247.50",
    "refund_status": "processed",
    "credit_timeline_days": 3,
    "confirmation_timestamp": "2024-03-16T14:24:15Z",
}

# Capsule C — denial reason (WITHHELD: internal policy, same evidence record)
DENIAL_REASON_C = {
    "record_type": DEMO_LABEL,
    "bank": BANK_NAME,
    "policy_id": "NDB-REFUND-POLICY-2024-v3",
    "denial_code": "EVIDENCE_INSUFFICIENT",
    "denial_detail": "Merchant dispute rebuttal received within window; additional review required.",
    "evaluated_at": "2024-03-16T14:22:58Z",
}

# HITL metadata for Capsule B & C (stored in compute_attestation; DISCLOSED)
HITL_B_APPROVE = {
    "hitl_approver_name": "Jordan Kim",
    "hitl_role": "Senior Dispute Analyst",
    "hitl_review_duration_s": 47,
    "hitl_review_channel": "northwind-dispute-portal",
    "hitl_decision_timestamp": "2024-03-16T14:23:07Z",
}

HITL_C_DENY = {
    "hitl_approver_name": "Jordan Kim",
    "hitl_role": "Senior Dispute Analyst",
    "hitl_review_duration_s": 31,
    "hitl_review_channel": "northwind-dispute-portal",
    "hitl_decision_timestamp": "2024-03-16T14:22:38Z",
}


# ---------------------------------------------------------------------------
# Capsule builder helpers
# ---------------------------------------------------------------------------

def _build_capsule_a(ts: str) -> dict:
    """Capsule A — fyi, disputed-transaction query, PII response withheld."""
    agent_input_digest = _sha256_jcs(AGENT_INPUT_A)
    agent_output_digest = _sha256_jcs(AGENT_OUTPUT_A_PII)

    return emit(
        action_id=f"northwind-demo/dispute-query/{TXN_REF}",
        action_type="fyi",
        operator="northwind-demo-bank",
        developer="dispute-query-agent@v1",
        timestamp=ts,
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        compute_attestation={
            "agent_input_digest": agent_input_digest,
            "agent_output_digest": agent_output_digest,
            "runtime": "demonstration",
            "demo_note": (
                "agent_input is disclosed; agent_output is withheld "
                "(customer PII — see withheld_a.json)"
            ),
        },
        disposition=Disposition(
            decision="accept",
            approver="policy",
            human_disposed=False,
            verdict_class="executed",
        ),
    )


def _build_capsule_b(capsule_a_id: str, ts: str) -> dict:
    """Capsule B — decide, refund approved, chained to A."""
    agent_input_digest = _sha256_jcs(AGENT_INPUT_A)
    constraint_evidence_digest = _sha256_jcs(CONSTRAINT_EVIDENCE_B)
    refund_confirmation_digest = _sha256_jcs(REFUND_CONFIRMATION_B)

    return emit(
        action_id=f"northwind-demo/refund-decision/{TXN_REF}/approve",
        action_type="decide",
        operator="northwind-demo-bank",
        developer="refund-policy-agent@v1",
        timestamp=ts,
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        compute_attestation={
            "agent_input_digest": agent_input_digest,
            "runtime": "demonstration",
            **HITL_B_APPROVE,
            "demo_note": (
                "Constraint evidence digest and effect response digest are "
                "committed-but-withheld (see withheld_b.json for reasons)"
            ),
        },
        prior_capsule_id=capsule_a_id,
        chain_relation="follows",
        constraints=(
            ConstraintRecord(
                id="max-refund-limit-check",
                result="pass",
                severity="high",
                blocking=True,
                check_type="max-amount-gate",
                method="policy-engine",
                evidence_digest=constraint_evidence_digest,
            ),
        ),
        effect=EffectRecord(
            type="credit-refund",
            status="confirmed",
            response_digest=refund_confirmation_digest,
            effect_attestation="runtime_claimed",
        ),
        disposition=Disposition(
            decision="approve",
            approver="human",
            human_disposed=True,
            verdict_class="executed",
        ),
    )


def _build_capsule_c(capsule_a_id: str, ts: str) -> dict:
    """Capsule C — decide, refund denied, chained to A (refusal beat)."""
    agent_input_digest = _sha256_jcs(AGENT_INPUT_A)
    denial_reason_digest = _sha256_jcs(DENIAL_REASON_C)

    return emit(
        action_id=f"northwind-demo/refund-decision/{TXN_REF}/deny",
        action_type="decide",
        operator="northwind-demo-bank",
        developer="refund-policy-agent@v1",
        timestamp=ts,
        model_id="claude-sonnet-4-6",
        provider="anthropic",
        compute_attestation={
            "agent_input_digest": agent_input_digest,
            "runtime": "demonstration",
            **HITL_C_DENY,
            "demo_note": (
                "Denial reason digest committed-but-withheld (internal policy). "
                "No effect dispatched — denied actions do not execute."
            ),
        },
        prior_capsule_id=capsule_a_id,
        chain_relation="follows",
        constraints=(
            ConstraintRecord(
                id="max-refund-limit-check",
                result="pass",
                severity="high",
                blocking=True,
                check_type="max-amount-gate",
                method="policy-engine",
                evidence_digest=denial_reason_digest,
            ),
        ),
        disposition=Disposition(
            decision="deny",
            approver="human",
            human_disposed=True,
            verdict_class="denied",
        ),
    )


def _build_withheld_manifest_a(capsule_a: dict) -> dict:
    """Withheld-artifacts manifest for Capsule A."""
    return {
        "schema": "northwind-demo-withheld-manifest/1",
        "capsule_id": capsule_a["capsule_id"],
        "bank": BANK_NAME,
        "record_type": DEMO_LABEL,
        "withheld": [
            {
                "label": "customer_pii_response",
                "type": "agent_output",
                "capsule_field": (
                    "model_attestation.compute_attestation.agent_output_digest"
                ),
                "committed_digest": (
                    capsule_a["model_attestation"]["compute_attestation"][
                        "agent_output_digest"
                    ]
                ),
                "reason": "customer PII",
                "content_type": "application/json",
                "reveal_file": "reveal_a.json",
            }
        ],
    }


def _build_withheld_manifest_b(capsule_b: dict) -> dict:
    """Withheld-artifacts manifest for Capsule B (approve)."""
    return {
        "schema": "northwind-demo-withheld-manifest/1",
        "capsule_id": capsule_b["capsule_id"],
        "bank": BANK_NAME,
        "record_type": DEMO_LABEL,
        "withheld": [
            {
                "label": "max_refund_policy_evidence",
                "type": "constraint_evidence",
                "capsule_field": "constraints[0].evidence_digest",
                "committed_digest": capsule_b["constraints"][0]["evidence_digest"],
                "reason": "internal policy",
                "content_type": "application/json",
            },
            {
                "label": "refund_confirmation",
                "type": "effect_response",
                "capsule_field": "effect.response_digest",
                "committed_digest": capsule_b["effect"]["response_digest"],
                "reason": "operational data",
                "content_type": "application/json",
            },
        ],
    }


def _build_reveal_a() -> dict:
    """Revealed PII for Capsule A — the 'withheld-is-not-hidden' demo beat."""
    return {
        "schema": "northwind-demo-disclosure/1",
        "record_type": DEMO_LABEL,
        "bank": BANK_NAME,
        "disclosure_note": (
            "This is the disclosed agent_output that was withheld in Capsule A. "
            "The SHA-256 JCS-canonical digest of this object matches "
            "model_attestation.compute_attestation.agent_output_digest in Capsule A, "
            "proving the committed digest committed to this exact content. "
            "Nothing was hidden — only the raw data was withheld pending authorization."
        ),
        "disclosed": AGENT_OUTPUT_A_PII,
        "verify_digest_field": (
            "model_attestation.compute_attestation.agent_output_digest"
        ),
        "expected_digest": _sha256_jcs(AGENT_OUTPUT_A_PII),
    }


def _build_tampered_b(capsule_b: dict) -> dict:
    """Capsule B with one byte flipped in response_digest — detect-tamper demo."""
    import copy

    tampered = copy.deepcopy(capsule_b)
    orig = tampered["effect"]["response_digest"]
    # Flip the first hex nibble (0→1, else 0)
    flipped = ("1" if orig[0] == "0" else "0") + orig[1:]
    tampered["effect"]["response_digest"] = flipped
    tampered["_demo_tamper_note"] = (
        f"DEMONSTRATION TAMPER: effect.response_digest first nibble changed "
        f"({orig[0]!r} → {flipped[0]!r}). The capsule_id no longer matches "
        "the capsule body — verify surface should flag INTEGRITY_FAILURE."
    )
    tampered["_demo_original_response_digest"] = orig
    return tampered


# ---------------------------------------------------------------------------
# Anchor helper
# ---------------------------------------------------------------------------

def _anchor_capsule(capsule_id: str, out_dir: Path, label: str) -> dict:
    """Submit capsule_id to the live SCITT TS; save receipt; return metadata."""
    print(f"  Anchoring {label} ({capsule_id[:12]}…)")
    result = submit_anchor(capsule_id, timeout=30.0)

    receipt_file = out_dir / "receipts" / f"{label}_receipt.cose"
    receipt_file.parent.mkdir(parents=True, exist_ok=True)
    receipt_file.write_bytes(result.receipt)

    ts_file = out_dir / "receipts" / f"{label}_transparent.cose"
    ts_file.write_bytes(result.transparent_statement)

    return {
        "capsule_id": capsule_id,
        "entry_hash": result.entry_hash,
        "receipt_b64": base64.b64encode(result.receipt).decode("ascii"),
        "ts_url": result.ts_url,
        "receipt_file": str(receipt_file.relative_to(out_dir.parent)),
        "transparent_file": str(ts_file.relative_to(out_dir.parent)),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", default="demo/fixtures",
        help="Output directory for fixture files (default: demo/fixtures)",
    )
    parser.add_argument(
        "--no-anchor", action="store_true",
        help="Skip live anchor submission (offline fixture generation only)",
    )
    args = parser.parse_args(argv)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    ts_a = "2024-03-16T09:15:00Z"
    ts_b = "2024-03-16T14:23:08Z"
    ts_c = "2024-03-16T14:22:39Z"

    # ------------------------------------------------------------------
    # 1. Emit Capsule A
    # ------------------------------------------------------------------
    print("Building Capsule A (fyi — disputed-txn query)…")
    cap_a = _build_capsule_a(ts_a)
    (out / "capsule_a.json").write_text(
        json.dumps(cap_a, indent=2) + "\n", encoding="utf-8"
    )
    print(f"  capsule_id: {cap_a['capsule_id']}")

    # ------------------------------------------------------------------
    # 2. Emit Capsule B (approve, chained to A)
    # ------------------------------------------------------------------
    print("Building Capsule B (decide — refund approved, chains to A)…")
    cap_b = _build_capsule_b(cap_a["capsule_id"], ts_b)
    (out / "capsule_b_approve.json").write_text(
        json.dumps(cap_b, indent=2) + "\n", encoding="utf-8"
    )
    print(f"  capsule_id: {cap_b['capsule_id']}")

    # ------------------------------------------------------------------
    # 3. Emit Capsule C (deny, chained to A)
    # ------------------------------------------------------------------
    print("Building Capsule C (decide — refund denied, chains to A)…")
    cap_c = _build_capsule_c(cap_a["capsule_id"], ts_c)
    (out / "capsule_c_deny.json").write_text(
        json.dumps(cap_c, indent=2) + "\n", encoding="utf-8"
    )
    print(f"  capsule_id: {cap_c['capsule_id']}")

    # ------------------------------------------------------------------
    # 4. Withheld manifests + reveal
    # ------------------------------------------------------------------
    print("Building withheld manifests and disclosure…")
    (out / "withheld_a.json").write_text(
        json.dumps(_build_withheld_manifest_a(cap_a), indent=2) + "\n", encoding="utf-8"
    )
    (out / "withheld_b.json").write_text(
        json.dumps(_build_withheld_manifest_b(cap_b), indent=2) + "\n", encoding="utf-8"
    )
    (out / "reveal_a.json").write_text(
        json.dumps(_build_reveal_a(), indent=2) + "\n", encoding="utf-8"
    )

    # ------------------------------------------------------------------
    # 5. Tampered twin
    # ------------------------------------------------------------------
    print("Building tampered-twin of Capsule B…")
    tampered = _build_tampered_b(cap_b)
    (out / "tampered_b.json").write_text(
        json.dumps(tampered, indent=2) + "\n", encoding="utf-8"
    )

    # ------------------------------------------------------------------
    # 6. Anchor A + B against live SCITT TS
    # ------------------------------------------------------------------
    anchor_results: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "bank": BANK_NAME,
        "scenario": "disputed-refund-chain",
        "demo_note": "All content is SYNTHETIC — fictional bank, fictional parties.",
        "permalink_note": (
            "HOLD on publishing permalinks until verify.actionstate.ai P1 deploys. "
            "Permalink format will be: https://verify.actionstate.ai/c/<capsule_id>"
        ),
        "capsules": {},
    }

    if not args.no_anchor:
        print("Anchoring against live SCITT TS…")
        anchor_results["capsules"]["capsule_a"] = _anchor_capsule(
            cap_a["capsule_id"], out, "capsule_a"
        )
        anchor_results["capsules"]["capsule_b_approve"] = _anchor_capsule(
            cap_b["capsule_id"], out, "capsule_b_approve"
        )
        anchor_results["capsules"]["capsule_c_deny"] = _anchor_capsule(
            cap_c["capsule_id"], out, "capsule_c_deny"
        )
        print("  Anchor submissions complete.")
    else:
        print("  --no-anchor: skipping live anchor submission.")
        for label, cap in [("capsule_a", cap_a), ("capsule_b_approve", cap_b), ("capsule_c_deny", cap_c)]:
            anchor_results["capsules"][label] = {
                "capsule_id": cap["capsule_id"],
                "entry_hash": None,
                "receipt_b64": None,
                "anchored": False,
            }

    # Add permalink stubs (will be live after P1 deploy)
    for _label, meta in anchor_results["capsules"].items():
        meta["permalink_stub"] = (
            f"https://verify.actionstate.ai/c/{meta['capsule_id']}"
        )

    (out / "anchor_results.json").write_text(
        json.dumps(anchor_results, indent=2) + "\n", encoding="utf-8"
    )

    # ------------------------------------------------------------------
    # 7. Summary
    # ------------------------------------------------------------------
    print("\n=== Northwind Demo Bank — Refund Chain Fixtures ===")
    print(f"Output directory: {out}")
    print(f"\nCapsule A (fyi  — query):    {cap_a['capsule_id']}")
    print(f"Capsule B (decide — approve): {cap_b['capsule_id']}")
    print(f"Capsule C (decide — deny):    {cap_c['capsule_id']}")
    print(f"\nChain: B.chain.parent_capsule_id == A.capsule_id → {cap_b['chain']['parent_capsule_id'] == cap_a['capsule_id']}")
    print(f"        C.chain.parent_capsule_id == A.capsule_id → {cap_c['chain']['parent_capsule_id'] == cap_a['capsule_id']}")
    print("\nFiles generated:")
    for f in sorted(out.rglob("*")):
        if f.is_file():
            print(f"  {f.relative_to(out.parent)}")
    print(
        "\nPermalink format (HOLD until P1 deploy): "
        "https://verify.actionstate.ai/c/<capsule_id>"
    )


if __name__ == "__main__":
    main()
