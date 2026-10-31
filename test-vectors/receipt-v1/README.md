<!-- SPDX-License-Identifier: Apache-2.0 -->
# scitt-cose receipt-v1 test vectors (iat / grade)

Receipt-only vectors (no Signed Statement) exercising the two protected
labels a receipt-only verifier reads beyond the base RFC 9162 inclusion
proof:

* `iat` — CWT Claims (protected header label 15, RFC 9597) claim 6
  (RFC 8392 §3.1.6): the witness-observed registration time.
* `grade` — private-use protected-header label `-65537`: a witness-issued
  qualitative grade string (e.g. `"mmr-verified"`).

Both labels are read from the **signed** protected header only. A conformant
verifier reports two booleans, `witness_time_established` and
`grade_cryptographically_bound`, that are `true` **only** when the
corresponding value is present *and* the receipt's signature verifies —
never inferred, never true on a failed verify. This is the same wire shape
independently converged on by:

* open PR [action-state-group/scitt-cose#44](https://github.com/action-state-group/scitt-cose/pull/44)
  (`build_receipt(iat=, grade=)` / `ReceiptResult.iat` / `ReceiptResult.grade`);
* the TRACE registry's own receipt consumer,
  `trace_registry`'s `verify_witness_receipt.py` (`witness_time_established`,
  `grade_cryptographically_bound`);
* this crate's Rust verifier (`rust/scitt-cose`).

## Stability promise

Same as `../v1/`: `receipt-v1/` is **append-only** once merged. Corrections
or additions ship as new vectors or a new version directory, never as edits
to existing files.

## The vectors

| id | ok | iat | grade | witness_time_established | grade_cryptographically_bound |
|---|---|---|---|---|---|
| `trace-sept7-witness` | true | — | — | false | false |
| `synthetic-eddsa-iat-grade` | true | ✓ | ✓ | true | true |
| `synthetic-es256-iat-grade` | true | ✓ | ✓ | true | true |
| `synthetic-eddsa-iat-only` | true | ✓ | — | true | false |
| `fail-tampered-iat` | false | — | — | false | false |
| `fail-tampered-grade` | false | — | — | false | false |
| `synthetic-es256-iat-grade-observed-only` | true | ✓ | ✓ | true | true |
| `fail-attached-payload` | false | — | — | false | false |
| `fail-attached-payload-root` | false | — | — | false | false |
| `fail-es256-secp256k1-key` | false | — | — | false | false |
| `fail-es384-p256-key` | false | — | — | false | false |
| `fail-eddsa-p256-key` | false | — | — | false | false |
| `fail-wrong-log-key` | false | — | — | false | false |
| `fail-unsupported-alg` | false | — | — | false | false |
| `fail-malformed-proof` | false | — | — | false | false |
| `fail-malformed-tail-proof` | false | — | — | false | false |
| `fail-undefined-payload` | false | — | — | false | false |

`trace-sept7-witness` is not synthetic: it is the real COSE Receipt bytes
from the Action State Group's live TRACE-registry witness, captured
2026-09-07 and already published as public evidence at
`agentrust-io/trace-registry`'s `docs/evidence/witness-2026-09-07/`. It
carries neither label — both booleans are false **permanently** for this
exact receipt (it pre-dates the labels), not pending a witness upgrade.

`synthetic-es256-iat-grade-observed-only` (appended) is the twin of
`synthetic-es256-iat-grade` under the grade label witnesses emit now,
`observed-only`. The original keeps its published bytes and its
`countersigned-observed` label, the same meaning under its earlier name.
This library does not interpret grade values: both surface exactly as signed.

`fail-tampered-iat` / `fail-tampered-grade` take a valid receipt and alter
the labeled value in the protected header *after* signing, without
re-signing — proving the value is actually covered by the signature, not
merely carried alongside it. Both must fail signature verification; a
verifier that reports either boolean `true` here has a real vulnerability
(a value inside the signed header that isn't actually checked).

The last five (appended, scitt-cose#87) each carry a valid inclusion proof
and a signature that is genuine under `log-key.pub`, and must still fail:

* `fail-attached-payload` attaches bytes other than the root and signs them.
  A verifier that checks the signature over the attached payload binds
  nothing to the leaf. `fail-attached-payload-root` attaches the root itself;
  a verifier that ignores the payload slot accepts it. A Receipt's payload is
  detached, so both fail with an error naming the payload as attached.
* `fail-es256-secp256k1-key` (ES256 under secp256k1), `fail-es384-p256-key`
  (ES384 under P-256, r and s padded to 48 bytes) and `fail-eddsa-p256-key`
  (EdDSA with a P-256 key) break the alg/key pairing: RFC 9053 §2.1 binds
  ES256 to P-256 and ES384 to P-384, and EdDSA here is Ed25519. A P-384 key
  cannot stand in for the ES256 case, since its r and s do not fit 64 bytes.

The last four (appended, scitt-cose#91) pin what a failed verify reports for
`root`, `tree_size` and `leaf_index`, in their `returned` field:

* `fail-wrong-log-key` (signed by a key other than `log-key.pub`) and
  `fail-unsupported-alg` (alg ES512, which no verifier here supports) fail in
  the signature step. The verifier reports the root, tree size and leaf index
  of the first inclusion proof that rebuilds a root, with `ok` still false.
  These values are an unauthenticated diagnostic: the proof sits in the
  unprotected header, so they show only that the receipt is shaped right for
  this leaf, never a log root, size or position. Callers use them to tell a
  malformed receipt from one signed by a key they do not hold. One exception
  is outside these vectors: the Go verifier cannot load a secp256k1 key at
  all, so on `fail-es256-secp256k1-key` it reports nothing.
* `fail-malformed-proof` (a leaf index outside its tree) fails before the
  signature step, so nothing is reported.
* `fail-malformed-tail-proof` is a genuine receipt whose valid proof is
  followed by a malformed one, `[0, 0, []]`. Every proof is checked before any
  is used, so it also fails before the signature step and reports nothing,
  although its first proof would rebuild a root.
* `fail-undefined-payload` (appended, scitt-cose#104) is the receipt of
  agent-action-capsule's shared strict vector
  `neg-witness-cll-undefined-payload`: a genuine EdDSA receipt over the
  right root whose payload slot is CBOR undefined (`0xf7`) instead of null
  (`0xf6`). Only null is detached, so it fails before any proof is read and
  reports nothing. Its leaf entry is that vector's 32-byte `entry_hash`, and
  `log-key.pub` is the witness's raw Ed25519 key as a PEM
  SubjectPublicKeyInfo. It carries `failed_at` in its own `expected.json`.

## Failure stage (`failed-at.json`)

`failed-at.json` (appended, scitt-cose#93) names the `failed_at` every
verifier must report for each vector above: `"signature"` when a proof
rebuilt a root for the leaf and the signature step failed, `"structure"` on
any earlier failure, and `null` when `ok` is true. Callers read it, instead of
whether `root` is set, to tell a malformed receipt from one signed by a key
they do not hold. It is a separate file because the published `expected.json`
files cannot change; a later vector may carry `failed_at` in its own
`expected.json` instead, and every vector must pin it in one place or the
other. Go cannot load the key of `fail-es256-secp256k1-key`, so it reports no
stage there.

## `expected.json` fields

| field | meaning |
|---|---|
| `alg` | `EdDSA`, `ES256` or `ES384` |
| `leaf_entry_hex` | hex of the leaf entry the receipt proves |
| `tree_size`, `leaf_index` | position of the leaf and size of the log |
| `ok` | must the receipt verify? |
| `root` | reconstructed Merkle root (hex) when `ok` is true, otherwise `null`; not compared when `ok` is false (see `returned`) |
| `iat`, `grade` | expected surfaced values, or `null` when absent |
| `witness_time_established`, `grade_cryptographically_bound` | expected booleans |
| `failure_contains` | substring expected somewhere in the verifier's error list (present on `ok: false` vectors only) |
| `returned` | present only on the scitt-cose#91 vectors: the `root`, `tree_size` and `leaf_index` the verifier must report, each a value or `null` |
| `failed_at` | optional, for vectors appended after `failed-at.json`: `"signature"`, `"structure"` or `null` (see above) |
| `provenance` | present only on `trace-sept7-witness`: where the real bytes came from |

## Provenance

Minted once by
[`scripts/generate_receipt_grade_vectors.py`](../../scripts/generate_receipt_grade_vectors.py),
with appends by `scripts/append_receipt_v1_observed_only.py`,
[`scripts/append_receipt_v1_strict_negatives.py`](../../scripts/append_receipt_v1_strict_negatives.py),
[`scripts/append_receipt_v1_failure_shape.py`](../../scripts/append_receipt_v1_failure_shape.py) and
[`scripts/append_receipt_v1_malformed_tail.py`](../../scripts/append_receipt_v1_malformed_tail.py)
(kept for documentation and future versions; each refuses to overwrite a
published version). The expected values were self-checked at mint time
against this repo's Python library and are cross-checked in CI against the
Rust verifier (`rust/scitt-cose`) and the Go verifier (`scitt-cose-go-verify`).
