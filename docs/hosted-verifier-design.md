<!-- SPDX-License-Identifier: Apache-2.0 -->
# Hosted SCITT/COSE verifier — design

> **Status.**
> - **Private ride-along: enabled.** The verifier can be mounted into an existing
>   ASGI service (the host application) via an opt-in env flag, so it shares
>   that service's deployment. This has been run and tested privately (bound to
>   localhost; not exposed). See *Private ride-along deployment* below.
> - **Public community endpoint: still held.** A neutral, public, anonymous
>   verification URL is a coordinated recognition move (launched with the
>   standards push), not shipped reflexively. The OSS package publish is likewise
>   held. Those two are the deliberate calls; the private instance is not.

## What it is

A public, **read-only, stateless** HTTP utility that verifies a SCITT
`COSE_Sign1` Signed Statement and/or a COSE Receipt and returns *valid / invalid
+ reasons*. It exists so someone can check an artifact **without installing
anything** — and without having to trust the operator with their data.

The endpoint is a thin wrapper over the *same* library the CLI uses
(`scitt_cose.hosted.verify_payload`, which calls `parse_signed_statement` and
`verify_receipt`). `tests/test_hosted_parity.py` asserts **hosted verdict ==
local verdict** on a fixture set — so "the hosted endpoint runs the identical
verified library" is a checked claim, not marketing.

## What it is NOT — the load-bearing boundary

**It is NOT a SCITT Transparency Service.** This distinction is the whole point
and must never blur:

| | Hosted **verifier** (this design) | Hosted **Transparency Service** (separate, commercial) |
|---|---|---|
| Operation | verify only | register statements, **issue receipts**, anchor |
| State | **none** (stateless) | a durable, append-only log |
| Trust commitment | **none** — verify it yourself | uptime, integrity, non-equivocation, witnessing |
| Risk | low (read-only utility) | high (operational trust infrastructure) |
| Who must trust whom | nobody trusts the operator | the ecosystem trusts the log operator |

A verifier that starts storing submissions, issuing receipts, or anchoring has
silently become a transparency service with all of its obligations. The design
forbids that drift: no write path, no persistence, no key custody for issuance.

## Design constraints (these *are* the design)

1. **Stateless & read-only.** No database, no queue, no persistence. Each request
   is verified in memory; inputs are discarded when the handler returns. The only
   state permitted is an anonymous request counter (for capacity/abuse only).
2. **Safe for the submitter.** A submitter may send a statement that wraps *their*
   sensitive payload. They must not have to trust us with it:
   - **Nothing retained.** No statement, payload, key, or header is stored or
     logged. Logs carry method + status + an anonymous count — never bodies.
     `Cache-Control: no-store` on every response.
   - **Prefer digest/structure over plaintext.** The **receipt** path needs only
     the *leaf digest* + inclusion proof + log key — never the payload. Recommend
     that path when privacy matters.
   - **Honest caveat about statement signatures.** COSE signs the *payload bytes*;
     verifying a Signed Statement's signature therefore requires those bytes
     (or, for a detached statement, the detached payload). The endpoint processes
     them in memory and discards them, but a maximally-private submitter should
     verify locally — the library is the same, so the result is identical. This
     is stated plainly in the API capabilities response.
3. **No auth, no accounts, no PII.** It is a public utility. Identity is never
   requested or required.
4. **Rate-limited; bounded request size.** Abuse surface is controlled by a
   request-size cap (1 MB in the reference handler) and edge rate-limiting (see
   deployment shape). Both wrappers also carry an **in-process backstop**: a
   single anonymous fixed-window counter on `POST /verify` (`SCITT_VERIFY_RPM`,
   default 600/min; `0` disables for edge-only setups) returning 429 — so a
   bare deployment is never wide open. The edge remains the front line; the
   backstop is defense-in-depth. Rate-limit counters are anonymous (one global
   counter, no per-IP state) and hold no submission data.
5. **Payload-opaque.** It verifies the SCITT/COSE envelope and the receipt's
   cryptographic claims only. It never parses or validates any profile's payload
   semantics. The response strips payload bytes (reports only `payload_len`).
6. **Identical logic to local.** Same library, asserted by the parity test.

## API (proposed)

```
GET  /            -> 200  {service, summary, does[], does_not[], retention,
                           privacy[], boundary, attribution, draft_tracking}
GET  /health      -> 200  {ok: true}     (liveness probe; /healthz is an alias —
                           Google's frontend intercepts /healthz on run.app)
POST /verify      -> 200  {valid, statement, receipt, reasons, draft_tracking}
                  -> 429  when the in-process rate backstop trips (see below)
```

`GET /` is content-negotiated: with `Accept: text/html` it returns a static
landing page that renders the boundary table above **on the page itself** (no
scripts, no external assets); otherwise it returns the same data as JSON,
including the `boundary` field. Page and API are generated from the same
constants (`BOUNDARY_TABLE`), pinned by `tests/test_hosted_page.py`.

`POST /verify` request body (JSON; all base64 is standard or URL-safe):

```jsonc
{
  "statement_b64":        "…",   // optional: COSE_Sign1 Signed Statement
  "statement_pubkey_pem": "…",   // optional: PEM key to check the signature
  "receipt_b64":          "…",   // optional: COSE Receipt
  "log_pubkey_pem":       "…",   // with receipt: PEM key of the log
  "leaf_entry_hex":       "…"    // with receipt: hex of the proven leaf
}
```

At least one of `statement_b64` / `receipt_b64` is required. The response never
echoes the submitted bytes back; for statements it returns only
issuer/subject/content-type/alg/signature-verdict/`payload_len`.

A `200` is returned for a well-formed request whose artifact is *invalid* — the
verdict is in the `valid` boolean and `reasons[]`. Non-2xx is reserved for
malformed transport (oversized body, non-JSON).

## Private ride-along deployment (this pass)

The neutral package ships a **framework-free ASGI app** (`make_asgi_app()`,
stdlib-only — ASGI is just an async-callable protocol, so no web framework leaks
into the package). Any ASGI host can mount it; the host application does so
opt-in:

```python
# the host app's factory — import-guarded, OFF by default
if os.environ.get("HOST_ENABLE_SCITT_VERIFY") == "1":
    from scitt_cose.hosted import make_asgi_app
    app.mount("/scitt-verify", make_asgi_app())
```

To run it on the host service (private; bound to wherever that service binds):

```bash
pip install scitt-cose                       # make scitt_cose importable
HOST_ENABLE_SCITT_VERIFY=1 <host-app-cmd>    # mounts GET/POST /scitt-verify
```

Coupling direction is one-way and correct: **a host app may import scitt-cose;
the neutral package never imports the host app** (so it stays extractable). The
mount is import-guarded and off by default. Verified end-to-end over HTTP:

- valid statement → `valid: true`; tampered → `valid: false`;
- **digest-only receipt** verifies with a request body of only
  `{receipt_b64, log_pubkey_pem, leaf_entry_hex}` — no plaintext payload sent;
- wrong leaf → `valid: false` (a different root is reconstructed and the log
  signature fails — *verify without trusting the log*);
- the service access log contained no payloads/bodies.

This shares the host service's *deployment* without making the verifier part of
the host service's *trust surface*: it is stateless, read-only, and holds nothing.

## Standalone SCITT-only verifier (the offering)

The same library runs as its own service — a **SCITT-only verifier**, separate
from the host app and, crucially, separate from the Transparency Service. Three
run modes, all serving the identical verified logic (asserted by the parity test):

```bash
scitt-cose-serve                       # stdlib HTTP, zero extra deps
uvicorn scitt_cose.hosted:make_asgi_app --factory --port 8080   # [serve] extra
docker run -p 8080:8080 scitt-verifier # the package's Dockerfile
```

This was run and verified privately under uvicorn with **only `scitt_cose`
imported** (no host application): `GET /` returns capabilities; `POST /verify` validates
a Signed Statement and a digest-only Receipt; the capabilities declare it is
**not** a Transparency Service.

**SCITT-only verifier vs. Transparency Service — keep these two offerings apart:**

| | This: **SCITT-only verifier** | Separate: **Transparency Service** |
|---|---|---|
| Verb | verify (read-only) | register + **issue receipts** + anchor |
| State | none | durable append-only log |
| Trust obligation | none (verify it yourself) | uptime, integrity, non-equivocation |
| Code | `scitt_cose` (this package) | the hosted Authority (separate) |

The SCITT-only verifier may *verify receipts the Transparency Service issued*
(see the Authority cross-verification test), but it never becomes one.

## Deployment shape (proposed; for the public endpoint — not executed)

A single, small, stateless service — trivially horizontally scalable because it
holds no state:

- **Runtime:** one container running `scitt_cose.hosted` behind any ASGI/WSGI or
  the stdlib handler; or a serverless function (the verify call is short and
  pure, a natural fit). No attached storage, no database, no secrets beyond TLS.
- **Edge:** TLS termination + **rate limiting** + body-size limit at the gateway
  (e.g. 1 MB, N req/min/IP). The gateway, not the app, is the abuse front line.
- **Observability:** request **count** and latency only. Structured logging MUST
  be configured to exclude request/response bodies. (The reference handler's
  `log_message` is silenced precisely so a default access log can't leak a body.)
- **No keys at rest, no write path, no log storage** — the things that would make
  it a transparency service are simply absent.

## Open questions for review (before any deploy)

- Neutral host/namespace for the eventual OSS package and, if deployed, a neutral
  domain — consistent with the "community gift, not a vendor play" framing.
- Whether to offer a digest-only statement mode for profiles that sign over a
  content hash (would let signature checks avoid the plaintext entirely).
- Exact edge rate-limit policy and DoS budget.

## Abuse-surface / data-handling notes (flagged per the brief)

- **Largest residual data-handling concern:** statement *signature* verification
  needs the payload bytes in memory transiently. Mitigations: nothing retained,
  no body logging, `no-store`, and a documented "verify locally for maximal
  privacy" path (identical library). The receipt path avoids the payload entirely.
- **Abuse surface:** unauthenticated public endpoint → mitigated by statelessness
  (no amplification, no storage to exhaust), body-size cap, and edge rate limits.
- **Drift risk:** the single most important ongoing discipline is *not* letting
  this grow a write/issue/anchor path. That would change its risk class entirely
  and is out of scope by design.
