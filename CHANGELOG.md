# Changelog

All notable changes to this project will be documented in this file.

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
