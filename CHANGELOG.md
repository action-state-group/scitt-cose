# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- RFC 9162 receipt verification checks all structurally valid inclusion proofs
  against the signed root, so an unrelated first proof cannot hide a later
  proof for the requested leaf. Impossible tree/index/path shapes and trailing
  proof CBOR are rejected as malformed before candidate selection. Shared
  append-only vectors exercise both proof orders and a zero-size tree.

### Added

- **The bundle page checks witness evidence in the browser.** It verifies the
  bundle's signed checkpoint, each witness receipt under a key from a witness
  list the reader chooses (none, the published list shipped with the page, or
  their own file), an `x-cadence-witness/v0` chain to a witnessed checkpoint, and
  an earlier witnessed checkpoint the bundle's checkpoint extends ("witnessed
  in part"). It names the level it checked and says when it only found
  evidence present. The checker is `viewer/src/witness.js`, built on its own
  into `viewer/dist/witness-check.js` (it needs only `cborg`).
- `/bundle` now loads `mmr.js`, which its range-membership check already
  called.

## [0.4.0] — 2026-09-27

### Upgrade notes

- **Breaking (wire shape): `scitt_cose.cll.RangeProof`,
  `verify_range` and `verify_range_against_checkpoint` changed shape
  (#46).** `RangeProof` now carries `from_index`/`to_index`/`witness`
  instead of `inclusion_from`/`inclusion_to`, and the verify functions take
  `body_digests` (every record's digest in the range) instead of
  `from_digest`/`to_digest`. Range proofs produced in the old two-boundary
  shape do not verify under 0.4.0; regenerate them with a producer that emits
  the new shape.
- **Behaviour change: protected-header claims are surfaced only when the
  signature verifies (#53, #56).** `verify_receipt` now populates
  `ReceiptResult.iat`, `issuer`, `subject` and `protected_header_ext` (which
  carries the `-65537` grade, when present) only when `ok` is true. On a
  signature failure they stay `None`/`{}` and `errors` gains the finding
  "protected header claims withheld (iat/iss/sub/protected_header_ext):
  receipt signature did not verify". Callers that read `iat` or
  `protected_header_ext` from a failed result in 0.3.0 now get nothing
  there; check `ok` first. (`issuer`/`subject` are new in 0.4.0 and follow
  the same rule.) The Rust and Go
  verifiers apply the same rule.
- `DRAFT_COSE_MERKLE_TREE_PROOFS` now equals `"RFC 9942"` (an alias of the
  new `RFC_COSE_RECEIPTS`) instead of
  `"draft-ietf-cose-merkle-tree-proofs-18"`, and `DRAFT_TRACKING_NOTICE` no
  longer describes COSE Receipts as an Internet-Draft (#58). Code that
  compared against the old draft string needs updating.

### Added

- **`build_receipt(iss=, sub=, kid=)`** optional kwargs, and
  **`ReceiptResult.issuer` / `ReceiptResult.subject`** surfaced from the CWT
  claims map (claims 1 and 2), per RFC 9943 §6 (#49). Omitting all three
  reproduces the pre-existing wire shape byte-for-byte. `kid` continues to
  surface through `protected_header_ext`. The docstring states that `sub` is
  the registered statement's own subject, not the submitter.
- **`HDR_GRADE = -65537`** exported from `scitt_cose.receipt` as the single
  documented constant for the private-use witness-grade label (#49). The
  library still does not interpret the label's value.
- **`build_receipt(iat=, grade=)`** optional kwargs (#57): `iat` goes into the
  protected CWT claims map (label 15, claim 6), `grade` under `HDR_GRADE`.
  With both `None` the output is byte-identical to before; a test pins the
  header bytes to the frozen `synthetic-eddsa-iat-grade` vector.
- **`RFC_COSE_RECEIPTS = "RFC 9942"`** status constant, exported from
  `scitt_cose`; `SUBSTRATE_RFCS` now includes RFC 9942 (#58).
- **Rust receipt verifier (`rust/scitt-cose`, crate version 0.1.0)** (#50): an
  offline, receipt-only verifier (coset + ed25519-dalek/p256) for RFC 9162
  SHA-256 COSE receipts against a pinned key, EdDSA and ES256, surfacing
  `iat`/grade. Not published to crates.io by this release. New
  `test-vectors/receipt-v1/` set (a captured witness receipt, synthetic
  EdDSA/ES256 iat+grade and iat-only receipts, two tamper vectors);
  `tests/test_crosslang_rust.py` cross-checks the Rust binary against the
  Python library, required in CI via `SCITT_REQUIRE_RUST=1`.

### Changed

- **`RangeProof`/`verify_range`/`verify_range_against_checkpoint`
  (`scitt_cose.cll`) now bind every leaf in the claimed range, not just the
  two boundary leaves (#46).** `RangeProof` is a byte-identical port of
  `cll.checkpoint.index.RangeProof` (checkpointed-local-log, the reference):
  it carries `from_index`/`to_index`/`witness` instead of the old
  `inclusion_from`/`inclusion_to` pair of `InclusionProof`s, and
  `verify_range`/`verify_range_against_checkpoint` take `body_digests`
  (every record's own digest in the range) instead of `from_digest`/
  `to_digest`. **Breaking, wire-incompatible with the old shape**: the old
  two-boundary proof never touched any leaf strictly between the endpoints,
  so a deleted or replaced interior record verified anyway — this closes
  that gap. `scope_note`/`verify_range_against_checkpoint`'s docstring now
  read "records *from*–*to* are present, unaltered, and bound to checkpoint
  *C* — this does not show that no other records exist" in place of the old
  "N of N claimed records" phrasing.

- Standards status: SCITT Architecture (RFC 9943) and COSE Receipts
  (RFC 9942) are both described as published RFCs in `_status.py`, the CLI
  banner, module docstrings, README and CONTRIBUTING (#58). The wire shape
  (vds 395, vdp 396, RFC9162_SHA256 = 1) is unchanged from draft -18.

### Fixed

- **`verify_receipt` no longer exposes header claims from a receipt whose
  signature fails (#53).** Previously `iat`/`issuer`/`subject`/
  `protected_header_ext` were filled from the protected header before the
  signature check and left set on failure, so a receipt signed under a
  non-pinned key still exposed its grade alongside `ok=False`. The Rust
  verifier had the same defect and is fixed the same way, with the same
  "protected header claims withheld" finding. The frozen `receipt-v1`
  vectors now also run in the Python suite.
- **Go verifier (`scitt-cose-go-verify`): the statement path withholds
  header claims unless the signature verifies (#56).** `content_type`/`kid`/
  `iss`/`sub`/`string_claims` are left empty on failure, with the finding
  "protected header claims withheld (content_type/kid/iss/sub/string_claims):
  statement signature did not verify", matching Python
  `parse_signed_statement`.

### Hosted verifier (`hosted_profiles/`, `viewer/` — not part of the PyPI package)

- Bundle viewer: the "Completeness" ritual stage is renamed "Range
  membership" (#46). `MMR_JS` gains `verifyRange`, a byte-identical port of
  the reference `verify_range`; `BUNDLE_JS`'s `checkCompleteness` calls it
  with every record's own digest rather than checking only the first/last
  record's inclusion. Rendered copy, `docs/verification-trust-model.md` and
  `README.md` updated to match.
- The viewer verifies through the canonical agent-action-capsule TypeScript
  library, bundled as `viewer/dist/aac-crypto.js`, instead of inlined copies
  (#47). This fixes nested disclosed payloads false-mismatching (DE-3) and
  rendering empty, and format-4 chained capsule_id recompute. Bundle records
  render as a provenance tree. Capsule-id parity fixtures regenerated as
  format 4.
- The Witness ritual stage renders receipt grades in words when
  `receipt_grades` is supplied; an ungraded receipt renders "ungraded"
  (#48). Without grade data the output is unchanged.
- Hostname canonicalisation (#51): verify-site references moved to
  `verify.agentactioncapsule.org` across README, SECURITY, the demo and
  docs; `_referrer_domain()` now counts same-site navigation on
  `verify.agentactioncapsule.org` as same-origin (both hostnames kept in the
  allowlist).
- Standards status text on the verify site, boundary table fits a 375px
  viewport, and `witness.*` is linked (#58).
- `.gcloudignore` committed so a `--source .` deploy keeps `viewer/dist`
  (#55).

### Tests and CI

- `tests/test_mmr_js_parity.py`/`tests/test_cll.py` gain the full range
  vector set generated by `scripts/generate_mmr_range_vectors.py` (ported
  1:1 from checkpointed-local-log's own vectors): positive cases
  (single-leaf, three-leaf, first-leaf i.e. `from_seq=1`, cross-peak) and
  negative cases (replaced-interior-record, deleted-interior-record,
  sparse-selection-wrong-window, mismatched-checkpoint-root) — the exact
  bug class a two-boundary-inclusion proof could never catch (#46).
- Hostname lint (`.github/hostname_lint.py`, `hostname-lint` workflow) fails
  CI on a stale verify/witness hostname (#51).
- Internal-leak lint (`.github/leak_lint.py`, `leak-lint` workflow),
  fail-closed with an exact-text allowlist and a mutant-tested suite; the
  existing tree was cleaned to pass it (#52). Attribute-selector exemption
  and line-end handling synced (#54).
- CI builds, tests and clippy-lints the Rust crate and requires the Rust
  cross-language check (#50).

## [0.3.0] — 2026-09-08

### Added

- **`ReceiptResult.iat`** (`int | None`) — surfaces the `iat` (issued-at)
  integer from the protected header's CWT claims map (COSE label 15, CWT
  claim 6 per RFC 8392 §3.1.6) when present; `None` when absent. Read-only;
  no interpretation is applied by this library.

- **`ReceiptResult.protected_header_ext`** (`dict`) — exposes every protected-
  header label that is not actively processed by this verifier (alg/1, crit/2,
  vds/395, CWT_Claims/15) as a plain `{label: decoded_value}` map. This gives
  any caller transparent access to profile-specific or private-use labels
  (e.g. negative label numbers) that were integrity-protected by the receipt
  signature, without the neutral library ascribing meaning to any specific label.
  An empty dict when no unrecognized labels are present.

- Exported constants `HDR_CWT_CLAIMS` (15) and `CWT_CLAIM_IAT` (6) from
  `scitt_cose.receipt`.

- `HDR_CWT_CLAIMS` (15) added to `_RECEIPT_UNDERSTOOD` so receipts that mark
  it critical are accepted by the verifier (RFC 9052 §3.1 compliance).

### Changed

- Version bumped `0.2.2 → 0.3.0` (minor bump: additive API surface).

### Compatibility

- Fully backward-compatible. Existing call sites receive two additional fields
  (`iat=None`, `protected_header_ext={}`) when verifying receipts that carry no
  CWT claims or unrecognized protected labels. The byte-for-byte verification
  logic and `ok/root/tree_size/leaf_index/errors` semantics are unchanged.

- This library carries **no** vocabulary for private-use labels or application
  profiles. Surfacing `-65537` or any other private label in
  `protected_header_ext` is generic pass-through; the neutral library never
  names or interprets such labels.

## [0.2.2] — prior releases

See git history for earlier changes.
