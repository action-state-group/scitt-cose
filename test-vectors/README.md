<!-- SPDX-License-Identifier: Apache-2.0 -->
# scitt-cose cross-implementation test vectors

A stable, reproducible vector set for SCITT Signed Statements and COSE
Receipts (RFC 9162 SHA-256 verifiable data structure), built for
cross-implementation conformance: run the same committed bytes through *your*
verifier and compare against `expected.json`.

**A mismatch against your implementation is exactly the report we want** —
please open an issue with your runner's output. Agreement on *rejection* is as
load-bearing as agreement on acceptance.

## Stability promise

`v1/` is **append-only**: once merged, the published vector bytes and expected
values are never mutated. Corrections or additions ship as *new* vectors (or a
new version directory) plus a note in `manifest.json` — never as edits to
existing files. You can pin this directory and your pin will stay valid.

The promise is **enforced, not just stated**: [`SHA256SUMS`](SHA256SUMS) pins
the digest of every published file, CI verifies it (`sha256sum -c SHA256SUMS`)
on every push, and the test suite additionally checks that every file under a
published version is listed. New vectors append new lines; existing lines
never change.

## One-command verify (clean checkout)

From source:

```bash
git clone https://github.com/action-state-group/scitt-cose
cd scitt-cose && pip install -e . && python -m scitt_cose.vectors
```

From the published package (the runner ships in **scitt-cose ≥ 0.1.0**;
download this `test-vectors/` directory, then):

```bash
pip install "scitt-cose>=0.1.0"
python -m scitt_cose.vectors path/to/test-vectors          # add --json for machines
```

The Go clean-room implementation runs the same manifest:

```bash
cd scitt-cose-go-verify && go test ./...     # includes vectors_test.go
```

Both runners exit non-zero on any mismatch — including a negative vector that
unexpectedly verifies. No network access is needed anywhere in the vector path.

## Layout

```
manifest.json          machine-readable index (version, stability, vectors[])
SHA256SUMS             digest of every published file (CI-enforced immutability)
v1/<vector-id>/
  statement.cose       COSE_Sign1 Signed Statement bytes
  payload.bin          the statement's payload bytes (opaque)
  receipt.cose         COSE Receipt bytes
  issuer-key.pub       PEM public key for the statement signature
  log-key.pub          PEM public key of the (simulated) transparency log
  *.test-private       the TEST-ONLY private keys used to mint the vector
  expected.json        every value a verifier needs + the expected verdict
```

### The vectors

| id | result | failure_code |
|---|---|---|
| `valid-eddsa` | VALID | — |
| `valid-es256` | VALID | — |
| `fail-tampered-path` | INVALID | `TAMPERED_INCLUSION_PATH` |
| `fail-unsupported-vds` | INVALID | `UNSUPPORTED_VDS` |
| `fail-bad-statement-sig` | INVALID | `BAD_STATEMENT_SIGNATURE` |

Each negative vector isolates exactly one failure: `fail-tampered-path` and
`fail-unsupported-vds` carry an honest statement (only the receipt must be
rejected); `fail-bad-statement-sig` carries a verifying receipt minted over the
digest of the tampered statement bytes (only the statement signature must be
rejected).

## `expected.json` fields

| field | meaning |
|---|---|
| `payload_sha256` | SHA-256 (hex) of `payload.bin` |
| `protected_header.statement` | decoded statement protected header: `alg` (name) + `alg_code` (COSE code point), `content_type` (label 3), CWT Claims at label 15 → `issuer` (claim 1) and `subject` (claim 2) |
| `protected_header.receipt` | decoded receipt protected header: `alg`/`alg_code`, `vds` at label 395 (`1` = RFC9162_SHA256) |
| `leaf_entry` | hex of the log's leaf entry for this statement (see below) |
| `leaf_index`, `tree_size` | position of the leaf and size of the log |
| `inclusion_path` | the RFC 9162 audit path, outermost-last, hex per node (for `fail-tampered-path` this is the path *as committed*, i.e. with the flipped byte) |
| `reconstructed_root` | the Merkle root (hex) a correct verifier reconstructs; `null` when the receipt must be rejected before/without root agreement |
| `statement_signature_valid` | must the statement signature verify? |
| `receipt_valid` | must the receipt verify? |
| `result` | `VALID` \| `INVALID` (overall) |
| `failure_code` | present on INVALID vectors only |

## Deterministic tree construction (rebuild the log state yourself)

* **Leaf entry definition:** the transparency log's leaf entry for a registered
  Signed Statement is the **SHA-256 digest of the complete COSE_Sign1 statement
  bytes** (for `fail-bad-statement-sig`, the digest of the tampered bytes as
  committed — the log registered what it was given). This is not just prose:
  both runners recompute the digest from `statement.cose` and assert it equals
  `expected.json`'s `leaf_entry`, so an implementation that derives the leaf
  differently fails the suite.
* **Tree:** RFC 9162 SHA-256 Merkle tree, `tree_size = 8`, leaves in index
  order. The statement's digest sits at `leaf_index = 2`; every other leaf `i`
  is `SHA-256("scitt-cose test vectors v1 :: <vector-id> :: filler leaf <i>")`
  (ASCII).
* The receipt's payload is the Merkle root (detached); its unprotected header
  carries the inclusion proof as `cbor([tree_size, leaf_index, [audit_path]])`
  at vdp (label 396) key `-1`, per draft-ietf-cose-merkle-tree-proofs.

## Keys

All keys were freshly generated for this vector set, are committed here in
full (including private halves, named `*.test-private`), are **TEST-ONLY**, and
are never used anywhere else. Do not use them for anything.

## Provenance

Minted once by [`scripts/generate_test_vectors.py`](../scripts/generate_test_vectors.py)
(kept for documentation and future versions; it refuses to overwrite a
published version). The expected values were self-checked at mint time and are
continuously verified in CI by two independent runtimes: this repo's Python
library and the clean-room Go implementation.
