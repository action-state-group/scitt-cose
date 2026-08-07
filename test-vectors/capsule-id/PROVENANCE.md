<!-- SPDX-License-Identifier: Apache-2.0 -->
# capsule-id test vectors — provenance

Fixtures for `[aac-viewer-recompute-capsule-id]` — the capsule_id-vs-body
recompute check added to `CAPSULE_JS`/`BUNDLE_JS`. Generated/pinned by
`scripts/generate_capsule_id_vectors.py`.

## Source

`capsule-1.json`, `capsule-2.json`, `capsule-3.json` are the exact, real,
live-anchored capsules from the 3-capsule `dapr-agents-capsule` demo run on
2026-08-03 against `anchor.agentactioncapsule.org` (`capsule-emit` repo,
`examples/dapr-agents-capsule/run-transcript.md`; leaves 242, 243, 244). Each
one's `capsule_id` independently verifies against
`agent_action_capsule.canonical.compute_capsule_id` (RFC 8785 JCS + SHA-256) —
see `scripts/generate_capsule_id_vectors.py`'s sanity asserts. This is real
production data, not synthetic.

## The tampered fixture

`capsule-2-tampered.json` is capsule-2 (the human-rejected `decide` capsule,
leaf 243) with **only** `disposition` changed:
`{decision:reject, verdict_class:blocked}` -> `{decision:accept,
verdict_class:executed}`, `capsule_id` left byte-identical to the real,
anchored value. This reproduces the headline finding: a denial silently
reads as an approval when the viewer never recomputes `capsule_id` from the
fragment body.

**Scope note:** the filed reproduction (`asg/inbox.md
[aac-viewer-recompute-capsule-id]`) also describes changing
`model_attestation.compute_attestation.agent_input.amount` from `"48500.00"`
to `"25000.00"` on a revealed `agent_input` field. The real capsule-2 body
recovered here has `agent_input`/`agent_output` **withheld** (digest-only,
matching what was actually anchored on 2026-08-03) — no revealed-payload
variant with that amount was recoverable from any local checkout, and
re-running the live demo to mint a new one was explicitly out of scope
("do NOT redo"). The disposition-flip mutation alone is fully sufficient to
exercise the check under test (any single-field change breaks the RFC 8785
JCS digest identically, regardless of which field), and is the exact,
verified, real-data reproduction of the finding's core claim ("a denial
reads as an approval"). Reported as a scope note in the outbox, not hidden.

## Regenerating

```
python3 scripts/generate_capsule_id_vectors.py --aac-path /path/to/agent-action-capsule
```
