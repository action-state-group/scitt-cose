# Northwind Demo Bank — Disputed Refund Chain

**ALL CONTENT SYNTHETIC. Fictional bank, fictional parties. Demonstration records only.**

Two-capsule chain demonstrating the Agent Action Capsule spec on the live SCITT
transparency surface. Scenario: an AI dispute agent queries a transaction, then a
second AI proposes a refund that a named human reviewer approves.

---

## Capsule chain

```
Capsule A  (fyi  — dispute query)
capsule_id: 6549127e35a6750b217520354929423a85f695acaa9decabace521bc8e7dcc8a
  └─ Capsule B  (decide — refund APPROVED)       [chain.relation=follows]
       capsule_id: fcdc47760e6c9b8f96b9b776e2003e2eb17bb659750b8f010b16a2b1375d63f8
  └─ Capsule C  (decide — refund DENIED)          [chain.relation=follows]
       capsule_id: 56bebce8ec982f7d8f5c1a4d62be58a33930994e96e384804c28bbdd9e1bc419
```

All three are registered against the live SCITT transparency service
(`ts.agentactioncapsule.org`). Real inclusion proofs are stored as base64 in `fixtures/anchor_results.json` (receipt_b64 per capsule; .cose binaries are gitignored).

**Permalinks** (live after verify.actionstate.ai P1 deploys):

| Capsule | Permalink stub |
|---------|---------------|
| A — query | `https://verify.actionstate.ai/c/6549127e35a6750b217520354929423a85f695acaa9decabace521bc8e7dcc8a` |
| B — approved | `https://verify.actionstate.ai/c/fcdc47760e6c9b8f96b9b776e2003e2eb17bb659750b8f010b16a2b1375d63f8` |
| C — denied | `https://verify.actionstate.ai/c/56bebce8ec982f7d8f5c1a4d62be58a33930994e96e384804c28bbdd9e1bc419` |

**Reveal variant** (Capsule A with PII disclosed for the "withheld ≠ hidden" beat):
`https://verify.actionstate.ai/c/6549127e35a6750b217520354929423a85f695acaa9decabace521bc8e7dcc8a?reveal=reveal_a.json`
(exact query param depends on P1 UX decision)

---

## Dual-anchor witnesses

Each capsule is registered with **two independent transparency services**:

| Witness | Endpoint | leaf_index (A / B / C) |
|---------|----------|------------------------|
| SCITT TS (RFC 9162) | `ts.agentactioncapsule.org` | see `anchor_results.json` → `.witnesses.scitt_ts` |
| Public digest anchor | `anchor.agentactioncapsule.org` | 210 / 211 / 212 |

The public anchor (`anchor.agentactioncapsule.org`) is what the verify surface's
anchor banner queries — that's why all three capsule pages show green inclusion proofs.
The SCITT TS receipt is the full COSE Receipt (RFC 9162 SHA-256 inclusion proof);
the public anchor issues its own receipt independently.

**This is not a workaround — it is the multi-witness story in practice.** The same
capsule_id is witnessed by two logs that cannot coordinate their receipts. An auditor
can check both independently. Neither can unilaterally revise the other's record.

Both receipts (base64) and entry_hashes are in `fixtures/anchor_results.json` under
`.capsules.<label>.witnesses`.

---

## Fixture files

| File | What |
|------|------|
| `fixtures/capsule_a.json` | Capsule A — sealed, agent_output_digest committed, PII withheld |
| `fixtures/capsule_b_approve.json` | Capsule B — approved, constraint evidence + effect response withheld |
| `fixtures/capsule_c_deny.json` | Capsule C — denied, no effect dispatched |
| `fixtures/withheld_a.json` | Withheld-artifacts manifest for A (reason: customer PII) |
| `fixtures/withheld_b.json` | Withheld-artifacts manifest for B (reason: internal policy + operational data) |
| `fixtures/reveal_a.json` | Disclosed PII for A — recomputes to committed digest (reveal demo) |
| `fixtures/tampered_b.json` | Capsule B with response_digest flipped — verify surface shows break |
| `fixtures/anchor_results.json` | capsule_ids, entry_hashes, receipt_b64 (base64), permalink stubs; `.cose` binaries are gitignored but re-creatable via `--no-anchor` + re-anchor |

---

## Demo script — meeting beat order

**Setup**: open the B-approved permalink first, have A and C ready in adjacent tabs.
Tampered twin link ready in a third tab (loaded but not shown yet).

**Beat 1 — the DECISION surface** *(~45s)*
> "Here's a refund decision made by an AI agent, recorded on a public neutral log."
> Show Capsule B: action_type=decide, disposition.human_disposed=True, Jordan Kim approver.
> "The agent proposed the refund. A human — Jordan Kim — reviewed and approved it.
> That approval is on the record, immutably."

**Beat 2 — the CHAIN** *(~30s)*
> "This didn't come out of nowhere. Click the chain link."
> Navigate to Capsule A via the chain prev-link.
> "The AI queried the disputed transaction first — that's capsule A.
> B chains to A. You can walk the full audit trail."

**Beat 3 — WITHHELD IS NOT HIDDEN** *(~45s)*
> "Customer PII is in A's response, but it's not in this record.
> What you see is the committed digest — a cryptographic fingerprint."
> Show withheld panel for A (agent_output_digest, reason: customer PII).
> "Now I'll disclose it."
> Click reveal — page shows PII and 'digest matches' confirmation.
> "Nothing was hidden — the digest committed to this exact content.
> Anyone who changes the data breaks the digest."

**Beat 4 — the REFUSAL BEAT** *(~20s)*
> "Earlier in the same second, the AI ran with a *different* set of facts."
> Switch to Capsule C tab.
> "Same chain, same transaction — different disposition: DENIED.
> Rebuttal evidence arrived in the dispute window.
> Verdict_class=denied, no effect dispatched. Tamper-evident either way."

**Beat 5 — TAMPER DETECTION** *(~30s)*
> "What if someone changes the refund amount after the fact?"
> Switch to tampered-twin tab.
> "One byte flipped in the response_digest. The verify surface shows the break —
> the capsule_id no longer matches the body. The log entry is untouched;
> it's the local copy that's been tampered. You'd know immediately."

**Beat 6 — THE POINT** *(~20s)*
> "Every AI action — query, decision, human approval, refusal — is on a neutral
> public log. Verifiable by anyone, with no dependency on our infrastructure.
> That's the surface we're inviting you to build on."

---

## Regenerating

```bash
# Offline (no anchor — regenerates capsule_ids deterministically):
python3 demo/northwind_refund_chain.py --no-anchor

# Live (anchor against ts.agentactioncapsule.org — overwrites receipts/):
python3 demo/northwind_refund_chain.py
```

The capsule_ids are deterministic given the synthetic timestamps and content,
so `--no-anchor` regenerates the same IDs. Re-anchoring creates new tree entries
but the capsule_ids are unchanged.
