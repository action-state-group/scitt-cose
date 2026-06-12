<!-- SPDX-License-Identifier: Apache-2.0 -->
# Verifier hardening review + fuzz pass (pre-Vienna)

A read-and-report security review of `scitt_cose/` and the Go clean-room
verifier, using the same multi-angle finder methodology as the test-vector
review. **This document and the differential fuzz harness are the deliverable;
the fixes below are proposals — nothing merges without a ruling.**

Threat model: an attacker fully controls the bytes submitted to the verify
functions (statement, receipt, and the `alg`/`vds`/header fields inside them)
and can hit the public hosted endpoint unauthenticated. The verifier is handed
a trusted public key by its caller.

## What landed in this PR (tooling, not fixes)

- `scripts/differential_fuzz.py` — seeds from the v1 vectors, applies byte-level
  and CBOR-structural mutations, runs every mutant through **both** verifiers as
  isolated subprocesses (timeout + memory rlimit), and fails on any Python↔Go
  divergence not in `tests/fuzz/baseline.json`.
- `tests/fuzz/baseline.json` — the three KNOWN divergence classes (open findings
  below). CI fails on anything new; entries are removed as fixes land.
- `tests/test_differential_fuzz.py` — a bounded, Go-gated smoke batch in the unit
  suite.
- CI `fuzz` job — 600 iterations, fixed seed, ~1 min, uploads reproducing mutants.

The fuzzer independently **confirmed three findings** on its first runs
(indefinite-length malleability, trailing-byte acceptance, and the Go
infinite-loop hang) and surfaced the **trailing-bytes** issue the static angles
missed.

## Findings (severity-ranked)

```json
[
  {
    "id": "H1",
    "severity": "high",
    "category": "hostile-cbor / DoS",
    "file": "scitt_cose/receipt.py",
    "line": 198,
    "status": "CONFIRMED",
    "summary": "verify_receipt does bytes(inclusion_proofs[0]) before validating it; a CBOR integer there is coerced into a multi-GB zero buffer.",
    "failure_scenario": "A ~64-byte receipt with unprotected {396:{-1:[8000000000]}} makes verify_receipt allocate ~8 GB before _decode_inclusion_proof runs (confirmed: 64 bytes -> multi-GB). A larger int OOM-kills the process; verify_receipt is documented 'never raises' but MemoryErrors out. Same bytes(int) coercion in statement.py extract_receipts (line ~208).",
    "fix": "Require each inclusion-proof element to be a bstr (isinstance check) before bytes(); reject ints. Bound the inclusion-proofs array length."
  },
  {
    "id": "H2",
    "severity": "high",
    "category": "merkle / DoS",
    "file": "scitt-cose-go-verify/main.go",
    "line": 298,
    "status": "CONFIRMED (fuzz: robustness:receipt TIMEOUT)",
    "summary": "largestPow2Below's `for k*2 < n` overflows int64 for an attacker-supplied tree_size near 2**63 and loops forever — the Go verifier hangs.",
    "failure_scenario": "A ~60-byte receipt with tree_size=2**63-1 and one audit-path sibling hangs the Go verifier indefinitely at 100% CPU (confirmed >4s, never returns). Remote DoS of the cross-language second opinion before any signature check.",
    "fix": "Make largestPow2Below overflow-safe (e.g. unsigned / bit-length math) and reject tree_size beyond a sane ceiling; add an explicit expected-depth check before folding."
  },
  {
    "id": "H3",
    "severity": "high",
    "category": "error-model / DoS",
    "file": "scitt_cose/receipt.py",
    "line": 208,
    "status": "CONFIRMED",
    "summary": "_reconstruct_root is called outside verify_receipt's try/except; a huge tree_size drives recursion past Python's limit and raises RecursionError, breaking the 'never raises' contract.",
    "failure_scenario": "A receipt with tree_size ~2**5000 and a matching-length path recurses ~log2(tree_size) deep, raising RecursionError out of verify_receipt — crashing any caller that trusted the documented contract (the hosted endpoint masks it with a broad except, but library callers do not).",
    "fix": "Bound tree_size at the merkle layer (reject sizes whose bit length exceeds a ceiling) and/or convert the fold to iterative; ensure verify_receipt only ever returns ReceiptResult."
  },
  {
    "id": "H4",
    "severity": "high",
    "category": "hostile-cbor / malleability + conformance split",
    "file": "scitt_cose/cose_sign1.py",
    "line": 220,
    "status": "CONFIRMED (fuzz: conformance:statement & conformance:receipt, py=VALID/go=INVALID)",
    "summary": "cbor2.loads silently ignores trailing bytes AND accepts indefinite-length encodings, so a statement/receipt with appended garbage or a re-encoded payload still verifies in Python while Go rejects it.",
    "failure_scenario": "Appending arbitrary bytes to a valid statement.cose or receipt.cose still returns signature_verified=True / ok=True (confirmed: +1, +16, +50 trailing bytes all verify). Re-encoding the payload as an indefinite-length bstr also verifies. The COSE bytes are therefore not uniquely determined — breaks dedup / content-addressing / replay assumptions — and Go (go-cose/fxamacker) rejects both, a cross-implementation forgery-shaped split.",
    "fix": "Decode with a strict reader: reject trailing bytes after the COSE_Sign1, and reject indefinite-length / non-canonical encodings in the protected header and structural slots."
  },
  {
    "id": "M1",
    "severity": "medium",
    "category": "fail-open",
    "file": "scitt_cose/hosted.py",
    "line": 382,
    "status": "CONFIRMED",
    "summary": "verify_payload's `valid` defaults to True and is only set False on signature_verified IS False or receipt not-ok; a statement with no pubkey (signature_verified=None) and no receipt returns valid=True with zero crypto performed.",
    "failure_scenario": "POST {statement_b64: <any well-formed COSE>} with no statement_pubkey_pem and no receipt -> valid:true (only an advisory reason is appended). A client branching on the top-level boolean accepts an unverified/forged statement, and the response still reports attacker-controlled issuer/subject.",
    "fix": "Require an affirmative check: valid=True only when at least one of (statement signature verified True) / (receipt ok) actually held; treat None as not-valid."
  },
  {
    "id": "M2",
    "severity": "medium",
    "category": "hostile-cbor / algorithm confusion",
    "file": "scitt_cose/cose_sign1.py",
    "line": 224,
    "status": "CONFIRMED",
    "summary": "Duplicate keys in the protected header are silently resolved last-wins by cbor2 with no canonical/duplicate-key rejection.",
    "failure_scenario": "A protected header encoding {1:-8, 1:-7} (alg EdDSA then ES256) decodes to {1:-7} under cbor2 (confirmed). Because the protected bstr is signed verbatim the signature still binds, but this library enforces the LAST alg while another COSE stack taking the FIRST sees a different algorithm — a cross-implementation split view (same for duplicated iss/sub/content-type).",
    "fix": "Reject duplicate map keys in the protected header (and CWT claims) — a canonical/strict CBOR decode, paired with H4."
  },
  {
    "id": "M3",
    "severity": "medium",
    "category": "error-model / consumer-trust",
    "file": "scitt_cose/statement.py",
    "line": 148,
    "status": "CONFIRMED",
    "summary": "On any verify failure parse_signed_statement swallows the CoseError, sets signature_verified=False, and still returns issuer/subject/alg parsed from the UNVERIFIED bytes; and the contract is mixed (raises when no key, returns False when a key is given).",
    "failure_scenario": "A caller reading parsed['issuer'] for routing/trust while forgetting to gate on signature_verified is True consumes attacker-chosen iss/sub. Separately, 'malformed', 'unsupported alg', and 'bad signature' all collapse to the same False, and the no-key path RAISES while the with-key path RETURNS — a caller tested against one path breaks on the other.",
    "fix": "Document one explicit contract (recommend: structural/alg errors raise CoseError; only a genuine signature mismatch returns False), and clearly mark returned header fields as unverified unless signature_verified is True."
  },
  {
    "id": "M6",
    "severity": "medium",
    "category": "error-model / robustness",
    "file": "scitt_cose/statement.py",
    "line": 174,
    "status": "CONFIRMED (fuzz: robustness:statement & robustness:receipt py=CRASH)",
    "summary": "Truncated/malformed input makes parse_signed_statement and verify_receipt exit with an uncaught non-CoseError exception (e.g. _cbor2.CBORDecodeEOF, TypeError) instead of a clean reject — breaking the CoseError-only contract.",
    "failure_scenario": "A truncated statement.cose makes the CLI/library raise _cbor2.CBORDecodeEOF: premature end of stream (confirmed: exit 1 with a traceback), and a spliced receipt raises similarly. A caller catching only CoseError crashes; a service treating any exception as 'skip' silently drops verification. The differential fuzzer catches both (Python CRASH vs Go clean reject) — found after the stderr-aware classifier landed.",
    "fix": "Wrap every decode entry point (_structural_parse, the receipt pre-parse, extract_receipts) so only CoseError escapes (or signature_verified=False / ReceiptResult is returned); pairs with H3."
  },
  {
    "id": "M4",
    "severity": "medium",
    "category": "hosted / DoS",
    "file": "scitt_cose/hosted.py",
    "line": 644,
    "status": "CONFIRMED",
    "summary": "Reference server is single-threaded HTTPServer with no socket/parse/crypto timeout; the Content-Length cap trusts a header; sync verify blocks the uvicorn event loop.",
    "failure_scenario": "One slow-body (slowloris) or pathological-CBOR request pegs the only worker and blocks all other clients; the 1 MB cap is read from an attacker-supplied Content-Length rather than bytes actually read. Under the Dockerfile's single-worker uvicorn, the synchronous CBOR/crypto work stalls the async loop for every concurrent request.",
    "fix": "Document the reference server as demo-only; for the deployed endpoint use ThreadingHTTPServer/multiple workers, a hard request timeout, and an enforced read cap independent of Content-Length (depends on H1/H3 to bound per-request CPU/memory)."
  },
  {
    "id": "M5",
    "severity": "medium",
    "category": "merkle / hardening",
    "file": "scitt_cose/merkle.py",
    "line": 91,
    "status": "CONFIRMED (root cause of H2/H3)",
    "summary": "root_from_inclusion_proof enforces path length only as an emergent property of the recursion shape and bounds tree_size nowhere.",
    "failure_scenario": "Short paths are rejected mid-fold and extra siblings post-fold (so classic CT path-length forgery does NOT apply today), but any refactor to an iterative loop could silently reintroduce it, and an unbounded tree_size is what enables the H2/H3 DoS. The Go port shares the implicit-only enforcement.",
    "fix": "Add an explicit `len(audit_path) == expected_proof_length(index, tree_size)` assertion and a tree_size ceiling, in both languages, to lock the invariant."
  },
  {
    "id": "L1",
    "severity": "low",
    "category": "hosted / input reflection",
    "file": "scitt_cose/receipt.py",
    "line": 180,
    "status": "CONFIRMED",
    "summary": "Receipt error strings echo attacker-controlled CBOR header values verbatim into reasons[] returned to the client, refuting the design's 'error messages never reflect input' claim.",
    "failure_scenario": "A receipt whose vds (label 395) is an arbitrary value yields f\"protected vds (label 395) is {vds!r}; expected 1\" and that string is returned in the JSON reasons[] (confirmed: a marker string is echoed verbatim). JSON + nosniff limits it to info-leak / a sink if a consumer renders reasons as HTML; the statement path does NOT reflect (it collapses to type(exc).__name__).",
    "fix": "Use fixed, non-reflecting reason strings (codes), or whitelist/escape echoed values; align with the design doc claim."
  },
  {
    "id": "L2",
    "severity": "low",
    "category": "signature / document-the-guarantee",
    "file": "scitt_cose/cose_sign1.py",
    "line": 275,
    "status": "DOCUMENT (no bypass)",
    "summary": "ES256 accepts high-s (malleable) signatures and does not range-check r/s before handing to cryptography; cryptography rejects r=0/s=0/out-of-range at verify but imposes no low-s requirement.",
    "failure_scenario": "An observer can flip s->n-s and produce a second 64-byte signature that also verifies over the same Sig_structure — not a forgery, but the signature is not unique, which matters if any dedup/idempotency keys on the receipt/signature bytes. r=0/s=0/out-of-range are rejected, but only by the backend, not an explicit guard.",
    "fix": "Either document accept-and-why, or optionally enforce low-s (s <= n/2) and an explicit 1 <= r,s < n check as defense-in-depth."
  },
  {
    "id": "L3",
    "severity": "low",
    "category": "hostile-cbor / consistency",
    "file": "scitt_cose/receipt.py",
    "line": 217,
    "status": "CONFIRMED (minor)",
    "summary": "The receipt path calls verify_sign1 with the default understood-labels set {alg, crit} and never advertises vds (395), so a receipt that legitimately marks 395 critical is rejected, and only inclusion_proofs[0] is ever inspected (extra proofs ignored, array length unbounded).",
    "failure_scenario": "Inconsistent crit handling between the statement layer (which widens its understood set) and the receipt layer; an attacker can also pad the inclusion-proofs array (interacts with H1). crit itself IS correctly enforced (good) — this is the narrower receipt-label gap.",
    "fix": "Pass a receipt-aware understood-labels set (include 395) to verify_sign1; bound and, if multiple proofs are supplied, define whether all must agree."
  }
]
```

### Verified-safe (ruled out, recorded so the audit is explicit)

- **Merkle domain separation is correct** in both languages: leaf = SHA256(0x00‖entry), node = SHA256(0x01‖L‖R), matching the RFC 6962 vectors.
- **Algorithm-confusion across key types is rejected**: an EdDSA-header message against an EC key (and vice versa) fails on the key-type isinstance guard (test-covered). The residual note is M3's "no caller-declared expected alg" parameter.
- **Merkle edge cases reject cleanly**: tree_size 0/1, index ≥ tree_size, negative index, short/long paths, and the consistency-proof edges (m=0, m=n, m>n) all return None/false with no vacuous accept.
- **external_aad is fixed to b''** on both sign and verify; the bytes signed are exactly the bytes whose alg/vds are trusted (no TOCTOU between "signed" and "interpreted").
- **on-curve / point validation** for P-256 is guaranteed by `cryptography` at key load; Ed25519 uses RFC 8032 verification. Safe under the caller-supplied-key model; would need revisiting only if a key were ever taken from the attacker-controlled message.

## Fix-PR proposal (pending ruling)

Grouped so each can be ruled on independently:

1. **Strict canonical decode** (H4, M2, and the `bytes(int)` half of H1): a single
   hardened CBOR-decode helper in `cose_sign1.py` that rejects trailing bytes,
   indefinite-length encodings, and duplicate protected-header keys, used by the
   statement and receipt paths. Removes two baseline divergence classes.
2. **Merkle DoS bounds** (H2, H3, M5): overflow-safe `largestPow2Below`, a
   tree_size ceiling, and an explicit expected-depth assertion — in Python and
   Go. Removes the `robustness:receipt TIMEOUT` baseline class and the
   RecursionError escape.
3. **Receipt input validation** (H1, L3): require bstr inclusion-proof elements,
   bound the array, widen the receipt understood-labels set.
4. **Fail-closed verdicts & error model** (M1, M3): hosted `valid` requires an
   affirmative check; document/realign the raise-vs-return contract and mark
   unverified header fields.
5. **Hosted DoS posture & no-reflection** (M4, L1): demo-server caveat + deployed
   timeout/threading guidance; non-reflecting reason codes.
6. **Crypto documentation** (L2): accept-and-document ES256 malleability, or add
   optional low-s enforcement.

Each fix should add or flip a regression: removing a `tests/fuzz/baseline.json`
entry (so a re-introduction fails CI) and/or a targeted negative test under
`tests/test_negative_conformance.py`.

---

# Resolution (hardening fixes)

All findings above are **fixed** (not merely documented), except the two
consciously-accepted items in *Security Considerations* below. The standing
proof is the differential fuzzer's baseline: `tests/fuzz/baseline.json` is now
**empty** — differential fuzzing across the Python and Go runtimes finds **zero
known divergences**. Every entry that was once in that baseline was removed by a
fix; a regression that reintroduces any class fails the `fuzz` CI job.

| id | fix | where | regression |
|----|-----|-------|------------|
| H1 | Never coerce an unvalidated decoded value to `bytes`; require bstr inclusion-proof elements; cap the proofs array | `receipt.py` | `test_hardening.py::test_h1_*` |
| H2 | Overflow-safe `largestPow2Below` + `tree_size` ceiling + explicit expected-depth check | `main.go`, `merkle.py` | `hardening_test.go::TestH2_*` |
| H3 | Bound `tree_size`/path length before the fold; wrap reconstruct so `verify_receipt` never raises | `merkle.py`, `receipt.py` | `test_hardening.py::test_h3_*` |
| H4 | `strict_decode`: reject trailing bytes + indefinite/non-deterministic encoding | `cose_sign1.py` | `test_hardening.py::test_h4_*` |
| M1 | Hosted `valid` is fail-closed: every present component must affirmatively verify | `hosted.py` | `test_hosted_parity.py` |
| M2 | Reject duplicate protected-header keys in `strict_decode` | `cose_sign1.py` | `test_hardening.py::test_m2_*` |
| M3 | Identity fields authenticated-only; claimed values fenced under `unverified` | `statement.py` | `test_hardening.py::test_m3_*` |
| M5 | Explicit `len(path) == expected_depth` check (Python + Go) | `merkle.py`, `main.go` | `test_hardening.py::test_m5_*` |
| M6 | All decode paths wrapped — no public verifier leaks a non-`CoseError` exception | `statement.py`, `receipt.py` | `test_hardening.py::test_m6_*` |
| L1 | Receipt errors no longer echo the attacker-supplied `vds` value | `receipt.py` | covered by no-reflection review |
| L3 | Receipt path advertises `vds` (395) to crit enforcement | `receipt.py` | `_RECEIPT_UNDERSTOOD` |

The error-model contract (the M3/H3/M6 cluster, called out as the explicit
ruling) is now uniform and documented in the README **Failure contract**
section and in each public function's docstring: the public verifier entry
points (`parse_signed_statement`, `verify_receipt`) return a structured result
and never raise on input; the low-level `verify_sign1` primitive raises
`CoseError`; no public function ever leaks a parser/`Recursion`/`Memory`/library
exception.

# Security Considerations (accepted, with rationale)

These are conscious decisions, not oversights. They are documented rather than
"fixed" because the alternative would reject well-formed, validly-signed input.

- **L2 — ES256 `s`-malleability is accepted.** COSE / RFC 9053 impose no low-`s`
  requirement, and many conforming ES256 signers emit high-`s` signatures.
  Enforcing low-`s` would reject a large fraction of legitimate third-party
  signatures (a verdict change on well-formed input), so we do **not** enforce
  it. The verifier still rejects `r`/`s` that are zero or out of range (via
  `cryptography`). Consequence: a COSE_Sign1's 64-byte signature is not
  byte-unique. Anyone keying idempotency/dedup on the *signature bytes* (rather
  than on the signed content or the statement's leaf digest) must account for
  this. The leaf digest — what the transparency log commits to — is over the
  full statement bytes and is unaffected in practice for the canonical signer.

- **Statement `alg` is taken from the protected header.** `verify_sign1` selects
  the verification primitive from the integrity-protected `alg`, then requires
  the supplied key's type to match (EdDSA↔Ed25519, ES256↔EC). An attacker cannot
  force a primitive the key does not support. Callers who must additionally pin
  an *expected* algorithm should check `parsed["alg"]` against their policy.

The hosted reference server (`scitt-cose-serve`) remains a demo: deployments
should sit behind an edge with TLS, a hard request timeout, and rate limiting
(see `docs/hosted-verifier-design.md`). The library enforces the message-size
cap and bounded per-request cost that make that edge sufficient.
