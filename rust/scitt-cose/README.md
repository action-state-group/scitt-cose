# scitt-cose-receipt (Rust)

An **independent, non-Python, profile-opaque** verifier for generic SCITT
RFC 9162 COSE Receipts. The Rust sibling of the Python `scitt_cose.receipt`
module and the Go `scitt-cose-go-verify` tool — **receipt-only**: it never
reads a Signed Statement.

Verifies, offline, with no network code and no receipt issuance:

1. COSE_Sign1 signature over the receipt's (detached) payload, under a
   caller-supplied pinned public key (EdDSA or ES256).
2. RFC 9162 SHA-256 inclusion proof reconstruction (leaf =
   `SHA-256(0x00 || entry-hash)`), clean-room — the log operator is not
   trusted.
3. Two protected-header labels beyond the base proof: `iat` (CWT Claims,
   protected header label 15, RFC 9597 → claim 6, RFC 8392 §3.1.6) and the
   private-use grade label `-65537`. Both surface as `Option`s plus two
   derived booleans, `witness_time_established` and
   `grade_cryptographically_bound`, that are `true` **only** when the value
   is present *and* the receipt's signature verifies — never inferred.

`vds=2` (CCF `ccf.v1`) is **out of scope** and rejected the same way any
other unsupported vds is (never silently mis-verified) — see
`src/receipt.rs`'s module docs. `cll`/MMR checkpoint bytes are never read
here: receipts are SCITT, not CLL.

## Why a cross-language check exists

Round-tripping through the same library that produced the bytes can be
*self-consistently wrong*. A clean-room implementation in a different
language, with its own CBOR/COSE/Merkle stack, is the strongest guard: if our
bytes verify here **and** the reconstructed Merkle root matches, the artifact
is genuinely conformant, not just internally consistent. This check runs in
CI (`SCITT_REQUIRE_RUST=1` in the Python suite; `cargo test` on its own) so
it can never silently disappear.

## Usage (library)

```rust
let result = scitt_cose_receipt::verify_receipt(&receipt_bytes, &leaf_entry, &log_public_key_pem);
if result.ok {
    println!("root={:?} witness_time_established={}", result.root, result.witness_time_established);
}
```

## Usage (CLI)

```bash
cargo build --bin scitt-cose-rust-verify

./target/debug/scitt-cose-rust-verify \
  --receipt        receipt.cose \
  --log-pubkey     log.pem \
  --leaf-entry-hex 02
```

Prints one JSON object to stdout and exits `0` iff the receipt verifies:

```json
{
  "ok": true,
  "root": "fe14…",
  "tree_size": 5,
  "leaf_index": 2,
  "iat": 1700000000,
  "grade": "mmr-verified",
  "witness_time_established": true,
  "grade_cryptographically_bound": true,
  "errors": []
}
```

## Tests

```bash
cargo test                              # unit tests (merkle) + tests/vectors.rs
cargo clippy --all-targets -- -D warnings
```

`tests/vectors.rs` runs both `../../test-vectors/v1/` (shared with Python/Go;
`valid-ccf-vds2` is intentionally asserted *rejected*, not `VALID`, here — see
above) and `../../test-vectors/receipt-v1/` (the `iat`/`grade` set).

## Dependencies

- [`coset`](https://crates.io/crates/coset) — COSE_Sign1 CBOR structure
- [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — EdDSA signature verification
- [`p256`](https://crates.io/crates/p256) / [`ecdsa`](https://crates.io/crates/ecdsa) — ES256 (P-256 ECDSA) signature verification
- [`sha2`](https://crates.io/crates/sha2) — the Merkle fold's SHA-256

`publish = false`: this crate is consumed by git-tag pin, the same discipline
as `cll` (`checkpointed-local-log`) — bump the tag deliberately, never
`branch = "main"`.
