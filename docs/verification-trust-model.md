<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verification trust model

What the hosted viewer (`/v/<capsule_id>`, `/bundle`) checks, what it needs a
network for, what it doesn't, and exactly what a server ever learns about a
record you open. This is the differentiator against a self-attested operator
log: read it, don't take it on faith.

For the wrapper this page describes (stateless `POST /verify`, the
verifier-vs-Transparency-Service boundary), see
[`hosted-verifier-design.md`](hosted-verifier-design.md) — a design doc that
predates this viewer and is kept as a historical record, not updated here.
This page describes the shipped viewer as it runs today.

## The one-sentence version

**The record never leaves your browser, in either mode.** It rides in the
URL fragment — the part after `#` — which browsers never send over HTTP.
The server that serves the viewer's HTML/JS never sees the bytes you're
verifying.

## Why the fragment matters

A URL's fragment is stripped before the browser makes any HTTP request; it
exists only in the tab. `capsule bundle` and the capsule permalink both
encode the record as base64url **after** the `#`, so:

- Loading `https://verify.agentactioncapsule.org/bundle#<payload>` sends the
  server a request for `/bundle` — nothing after `#` is transmitted.
- Pasting JSON into the "paste bundle JSON" / "paste capsule JSON" box on
  either page does the same: it's parsed and re-encoded into the fragment
  client-side, never POSTed.
- Every check the viewer *does* run in the browser — digest recompute, chain
  linkage, Merkle inclusion/consistency, disclosure recompute — runs in
  JavaScript in your tab, against the bytes already in your tab.

You can confirm this yourself: open dev tools → Network, load a permalink,
and watch — the fragment never appears in a request.

## What's checkable with zero network

Both viewer pages run a "ritual" of independent stages, named and rendered
as pass/fail/skip, never blended into one verdict:

- **Capsule page** (`/v/<capsule_id>`): **Integrity · Sequence · Authenticity
  · Witness**
- **Bundle page** (`/bundle`): **Integrity · Sequence · Completeness ·
  Cross-check**

**Integrity, Sequence, Completeness and Cross-check are pure computation**
over the bytes already in the fragment — digest recompute against
`capsule_id`, chain-parent linkage, disclosure recompute, Merkle
range-proof math. None of it calls out anywhere, so it runs identically:

- **Offline, from disk.** `GET /bundle/offline-shell` (linked from the
  "Download self-contained copy" button on `/bundle`) returns the same DOM
  and the same JS, inlined instead of `<script src>`, with the bundle
  fragment embedded in place of a request. Save it, open it with `file://`,
  disconnect from the network entirely — Integrity, Sequence, Completeness
  and Cross-check all still run and render.
- **From the CLI.** capsule-ledger's `permalink --check` runs the same
  computation locally without a browser at all — and, unlike this browser
  page, also verifies Authenticity: the CLI has no WebCrypto-vs-COSE gap to
  work around, so it's the zero-network path that covers all three today.

**Authenticity (the COSE signature) is the honest exception, stated
plainly rather than buried:** the capsule page's Authenticity stage does
not verify a signature in the browser today, in either delivery mode. It
renders **skip** — "not checked" if no `signed_statement` is present, or
"present — not verified in the browser; use the Verify a signed statement
tool" if one is — never a fabricated pass. This viewer ships no
client-side COSE verifier yet. "The Verify a signed statement tool" is the
landing page's `POST /verify` (a network call to this same server, over
bytes it discards on return — see the Privacy posture section on `/`); for
zero network, the identical check is this package's own
`scitt_cose.statement.parse_signed_statement` (`pip install scitt-cose`,
runs anywhere, no server involved). Until browser-side verification ships,
treat the capsule page's Authenticity stage as "not evaluated here," not
as evidence either way — this is a tracked, known gap, not a silent one.

**Witness needs a network by definition** — it is a claim about a log
someone else keeps, not a property of the bytes in your hand. The capsule
page's Witness stage calls `GET /anchor-status/<capsule_id>` and, if that
succeeds, verifies the returned RFC 9162 inclusion proof against the anchor's
published key. If the anchor is unreachable, the stage renders **skipped,
not failed** — everything else keeps its independently-computed verdict, and
the finding says "reconnect any time to complete it," not "fails."
capsule-body integrity is checked first and gates this stage: a `capsule_id`
that doesn't recompute from its own fragment body is never shown a green
anchored banner no matter what the log says about that id, because the id
being logged proves nothing about a body that's since been altered.

## What a server *does* learn — stated, not buried

Two residuals, both narrower than "the record":

1. **Which `capsule_id` was viewed, and when.** The capsule page's URL path
   is `/v/<capsule_id>`, and its Witness stage calls
   `GET /anchor-status/<capsule_id>` — both send the 64-hex id (a digest, not
   the record) to the server, which can log that *this id* was checked *at
   this time*. The bundle page's Integrity/Sequence/Completeness/Cross-check
   stages send nothing; they never learn which capsules were in a bundle you
   opened there. The hosted instance additionally counts anonymous view/
   referrer totals (`/instrumentation-policy` states exactly what — a count
   and a referrer domain, never content).
2. **Trusting served JS, in hosted mode.** Loading `/v/<id>` or `/bundle`
   means your browser executes JavaScript this server sent you moments ago —
   the same trust you extend to any web page. The offline shell removes this
   once downloaded: save it, diff it against a copy you trust or against this
   repo's source, and every later open is verified against bytes you already
   inspected, not bytes fetched fresh.

Neither residual is the record itself. The payload, its digests, its chain,
and its disclosures are computed and rendered entirely client-side in both
modes; only a content-addressed id — never the content — crosses the wire,
and only for the one stage (Witness) that is inherently about a second
party's log.

## Compare: this vs. a self-attested operator log

A log an operator keeps and shows you on request asks you to trust that
operator for every property at once — that they logged it, logged it
correctly, and didn't edit it after the fact. This viewer instead makes each
property independently checkable, by anyone, without asking you to trust the
page serving the check:

| Property | How you check it here | Network required |
|---|---|---|
| Integrity (body matches its id) | recompute the digest in your own tab | no |
| Sequence (chain has no gaps) | walk `chain.parent_capsule_id` locally | no |
| Completeness / Cross-check (bundle page) | Merkle range-proof + digest recompute locally | no |
| Authenticity (COSE signature) | not evaluated by this browser page yet — `permalink --check` or `scitt-cose` locally | no, via the CLI · yes, via the hosted `/verify` tool |
| Witness (a third party saw it) | RFC 9162 inclusion proof against the anchor's published key | yes — and skips honestly when absent |

If you don't trust this server to serve you correct JS even once, download
the offline shell, verify it, and never load `/v/` or `/bundle` live again for
Integrity, Sequence, Completeness or Cross-check — the CLI's `permalink
--check` gives you the same guarantee, plus Authenticity, without a browser
in the loop at all.
