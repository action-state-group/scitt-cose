# VeritasChain VCP × scitt-cose Interop Probe

**Date:** 2026-06-30  
**Status:** ENVELOPE_COMPATIBLE ✓  
**Source draft:** `draft-kamimura-scitt-vcp-01` (Tokachi Kamimura / VeritasChain VSO)

---

## What this is

A cross-verify probe testing whether scitt-cose can process a SCITT Signed
Statement carrying a VeritasChain VCP (Verifiable Certification Protocol) event
payload.

## Finding

**Envelope-level: compatible.**  A VCP JSON event payload (per `draft-kamimura-scitt-vcp-01`
§2.1, §3.1) wrapped in a COSE_Sign1 Signed Statement verifies cleanly through
`scitt-cose.parse_signed_statement`. The COSE layer is payload-agnostic — it
treats the VCP JSON bytes as opaque, exactly as RFC 9052 §4 and the SCITT
architecture draft §3 require.

**No published VCP COSE binary artifacts (as of 2026-06-30).**  VeritasChain's
public repos (`github.com/veritaschain`) contain JSON event examples and reference
implementations but no signed COSE_Sign1 test vectors. This probe constructs the
COSE_Sign1 from the published JSON example (draft Appendix A) using a local
Ed25519 test key — the outer COSE layer is ours, the VCP payload is theirs.

**Inner VCP signing layer is independent.**  VCP events carry their own Ed25519
signature at the application layer (JCS-canonicalized JSON, `base64`-encoded per
`draft-kamimura-scitt-vcp-01` §3.1). That inner signature is opaque to
scitt-cose — we don't inspect or re-verify it. The COSE envelope wraps the
already-signed VCP event as payload.

## Probe results

| Check | Result |
|-------|--------|
| COSE_Sign1 over VCP payload: `signature_verified` | ✓ True |
| Payload round-trip (opaque) | ✓ exact match |
| Tamper (1 byte in signature region) → rejected | ✓ `signature_verified=False` |
| **Overall** | **ENVELOPE_COMPATIBLE** |

```
$ python3 interop/vcp/run_interop.py

============================================================
VeritasChain VCP × scitt-cose interop probe
============================================================

Source: draft-kamimura-scitt-vcp-01 Appendix A (synthetic key)
Payload (396 bytes): VCP SIG_ORD_EXE event (XAU/USD)

[1] Test key generated (Ed25519 — substitutes for VCP issuer key)
[2] COSE_Sign1 Signed Statement built (547 bytes)

[3] parse_signed_statement result:
    signature_verified : True
    alg                : EdDSA
    issuer             : did:vcp:exchange.example
    subject            : XAU/USD:EVT-2026-XAU-001
    content_type       : application/json
    payload (bytes)    : 396 bytes (opaque to verifier)
    payload round-trip : ✓ exact match

[4] Tamper test (flip 1 byte at offset -30):
    signature_verified=False  — rejected ✓

============================================================
Result: PASS ✓
  COSE envelope verified  : True
  Payload round-trip      : True
  Tamper rejected         : True
============================================================
```

## What would unlock full cross-verify

For a true two-party interop result (same statement, two independent verifiers):

1. **VeritasChain publishes a signed COSE_Sign1 test vector** — a `.cose` file
   signed with their actual issuer key plus the matching public key (or DID
   document).
2. We run `python3 -c "from scitt_cose import parse_signed_statement; ..."` over
   that artifact with their public key → `signature_verified=True`.
3. They run their verifier over one of our test vectors.

This is the same two-party exchange we did with Microsoft CCF (see
`interop/ccf/`). We're ready; we just need their published artifact.

## Files

| File | Purpose |
|------|---------|
| `run_interop.py` | Probe script — constructs + verifies VCP COSE_Sign1, writes result |
| `vcp-statement.cose` | COSE_Sign1 wrapping the VCP Appendix A example (test key) |
| `vcp-issuer-pub.pem` | Corresponding Ed25519 public key (regenerated each run) |
| `result.json` | Machine-readable result (written by run_interop.py) |

## Reproduced

```bash
cd /path/to/scitt-cose
pip install -e .
python3 interop/vcp/run_interop.py
# → Result: PASS ✓
```

## Source

- Draft: <https://datatracker.ietf.org/doc/html/draft-kamimura-scitt-vcp-01>
- VeritasChain GitHub: <https://github.com/veritaschain>
- VCP spec: <https://github.com/veritaschain/vcp-spec>
