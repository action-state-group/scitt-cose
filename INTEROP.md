# AAC Interop Registry

Status: IETF 126, Vienna, Jul 18–22 2026.

**Legend**

| Symbol | Meaning |
|--------|---------|
| `ran & verified` | result is on the public record; link below is the primary evidence |
| `agreed — scheduled` | coordinated; artifact exchange planned, not yet done |
| `proposed` | exploratory; no schedule set |
| `HOLD` | wording fixed by prior agreement with owners; no further detail until owners' review |

> A name is not evidence; a digest is — every `ran` row links a public record.

---

## Independent parties

| Counterparty | What ran / what's agreed | Status | Coordinates | Public record |
|---|---|---|---|---|
| EMILIA Protocol (Schrock) | 3 independent computations of 8cf0c36e… | ran & verified | digest `8cf0c36e…` | [agent-action-capsule PR #40](https://github.com/action-state-group/agent-action-capsule/pull/40) |
| Songbo Bu | vector repro · principal-binding -03 posted | ran & verified | draft -03 | [draft-bu-agentproto-security-principal-binding](https://datatracker.ietf.org/doc/draft-bu-agentproto-security-principal-binding/) |
| Tyche Institute (Sokolov) | TPM quote re-verified · 3rd-party row 0→1 | ran & verified | `v1.0-prior-vector` | [aep-pcr16-vector release](https://github.com/tyche-institute/aep-pcr16-vector/releases/tag/v1.0-prior-vector) · [eatf verification/2026-07-18](https://github.com/tyche-institute/eatf/tree/main/verification/2026-07-18) |
| Microsoft / CCF (Chamayou) | two-TS, both receipts ok · examples PR #4 ✓ | ran & verified | scitt-cose `269ab09` | [agent-action-capsule #4](https://github.com/action-state-group/agent-action-capsule/pull/4) · [scitt-ccf-ledger #424](https://github.com/microsoft/scitt-ccf-ledger/pull/424) · [scitt-cose 269ab09](https://github.com/action-state-group/scitt-cose/commit/269ab09) |
| NANDA / MIT | cross-registry deal-room LIVE, bridged | ran & verified | — | [verify.actionstate.ai](https://verify.actionstate.ai) |
| GlyphZero (Rampalli) | both directions ran · independent_interop | ran & verified | — | [cross-org-delegation-registry #3](https://github.com/karthik-titech/cross-org-delegation-registry/issues/3) |
| APS (Tymofii Pidlisnyi) | bidirectional cross-runs: 6/6 + 24/24, pinned | ran & verified | — | [audit-bof-preparation #9](https://github.com/mirjak/audit-bof-preparation/issues/9) |
| A2A boundary-seal (Tyche) | a2a-tck 100% MUST, ext on/off, pinned · bilateral close pending | ran & verified | capsule-emit `0.3.x` | [capsule-emit #29](https://github.com/action-state-group/capsule-emit/issues/29) |
| GAR / SOOS | SOOS/GAR sealed + verified · AARM R5 | ran & verified | leaf 166 | [anchor.agentactioncapsule.org](https://anchor.agentactioncapsule.org) |
| Continuum / COSA (Kintzele) | 32/32 Class-1 reproduction | ran — artifact pending | — | — |
| VSO / VeritasChain (Kamimura) | layering agreed · vector exchange post-Vienna | agreed — scheduled | — | [scitt-cose PR #8](https://github.com/action-state-group/scitt-cose/pull/8) |
| PermitReceipt (Lee) | freeze pending · evidentiary run Jul 23 | agreed — scheduled | — | — |
| libp2p / VTO (M.S. Gupta) | VTO × AAC interop agreed · post-Vienna | agreed — scheduled | — | — |

---

## Three-way track

pre-registered evidence protocol with PermitReceipt + MachineMandate owners; results after owners' review

Status: **HOLD**
