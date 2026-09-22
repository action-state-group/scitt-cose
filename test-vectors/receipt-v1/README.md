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

`trace-sept7-witness` is not synthetic: it is the real COSE Receipt bytes
from the Action State Group's live TRACE-registry witness, captured
2026-09-07 and already published as public evidence at
`agentrust-io/trace-registry`'s `docs/evidence/witness-2026-09-07/`. It
carries neither label — both booleans are false **permanently** for this
exact receipt (it pre-dates the labels), not pending a witness upgrade.

`fail-tampered-iat` / `fail-tampered-grade` take a valid receipt and alter
the labeled value in the protected header *after* signing, without
re-signing — proving the value is actually covered by the signature, not
merely carried alongside it. Both must fail signature verification; a
verifier that reports either boolean `true` here has a real vulnerability
(a value inside the signed header that isn't actually checked).

## `expected.json` fields

| field | meaning |
|---|---|
| `alg` | `EdDSA` or `ES256` |
| `leaf_entry_hex` | hex of the leaf entry the receipt proves |
| `tree_size`, `leaf_index` | position of the leaf and size of the log |
| `ok` | must the receipt verify? |
| `root` | reconstructed Merkle root (hex), or `null` when `ok` is false |
| `iat`, `grade` | expected surfaced values, or `null` when absent |
| `witness_time_established`, `grade_cryptographically_bound` | expected booleans |
| `failure_contains` | substring expected somewhere in the verifier's error list (present on `ok: false` vectors only) |
| `provenance` | present only on `trace-sept7-witness`: where the real bytes came from |

## Provenance

Minted once by
[`scripts/generate_receipt_grade_vectors.py`](../../scripts/generate_receipt_grade_vectors.py)
(kept for documentation and future versions; it refuses to overwrite a
published version). The expected values were self-checked at mint time
against this repo's Python library and are cross-checked in CI against the
Rust verifier (`rust/scitt-cose`).
