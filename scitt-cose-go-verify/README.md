# scitt-cose-go-verify

An **independent, non-Python, profile-opaque** verifier for **generic** SCITT
`COSE_Sign1` Signed Statements *and* RFC 9162 COSE Receipts.

This is the durable *external second opinion* on the COSE/SCITT bytes the Python
`scitt_cose` library produces. It uses
[`veraison/go-cose`](https://github.com/veraison/go-cose) — the established Go
COSE implementation — to verify signatures, reads CWT_Claims directly from the
protected-header bytes with `fxamacker/cbor`, and reconstructs the Merkle
inclusion proof **clean-room** (RFC 6962 / RFC 9162 §2.1.1) so a receipt is
verified *without trusting the log operator*.

It is deliberately **payload-opaque**: it knows nothing about any application
profile (no agent-action-profile awareness). It verifies the envelope and the
receipt's cryptographic claims, and surfaces any profile claims **verbatim**
under `string_claims` without interpreting them. That neutrality is the point —
this is ecosystem plumbing, not a vendor's tool.

## Why a *cross-language* check exists

Round-tripping through the same library that produced the bytes can be
*self-consistently wrong* — emitter and reader can agree on a mistake (e.g.
reading CWT_Claims at the wrong integer label: python-cwt's `CWT_CLAIMS` enum is
`13`, while the conformant label is `15`). A clean-room implementation in a
*different language*, with its own CBOR/COSE/Merkle stack, is the strongest
guard: if our bytes verify here **and** the reconstructed Merkle root matches,
the artifact is genuinely conformant, not just internally consistent. This check
runs in CI (`SCITT_REQUIRE_GO=1`) so it can never silently disappear.

## Usage

```bash
go build -o scitt-cose-go-verify .

# Verify a Signed Statement signature:
./scitt-cose-go-verify \
  --statement statement.cose \   # COSE_Sign1 (CBOR tag 18) bytes
  --pubkey    issuer.pem \        # PEM SubjectPublicKeyInfo public key
  --alg       EdDSA              # EdDSA | ES256

# Verify a Receipt (inclusion proof + log signature over the reconstructed root):
./scitt-cose-go-verify \
  --receipt       receipt.cose \
  --log-pubkey    log.pem \
  --leaf-entry-hex 02
```

It prints a JSON object to stdout and exits `0` iff everything requested
verifies. Generic (profile-opaque) output:

```json
{
  "valid": true,
  "alg": "EdDSA",
  "content_type": "application/widget+json",
  "iss": "https://issuer.example",
  "sub": "urn:anything:goes",
  "string_claims": { "profile_thing": "abc" },
  "receipt": { "ok": true, "root": "fe14…", "tree_size": 5, "leaf_index": 2 }
}
```

On any failure it exits non-zero with `"valid": false` and an `"error"` (and, for
receipts, `receipt.error`).

## What it reads, and where

| Field            | Source                                                            |
|------------------|-------------------------------------------------------------------|
| signature        | COSE_Sign1 Sig_structure, `nil` external AAD                      |
| `content_type`   | protected header label **3**                                      |
| `kid`            | protected header label **4** (hex)                               |
| `iss`            | CWT_Claims (protected label **15**, RFC 9597) → claim **1**       |
| `sub`            | CWT_Claims → claim **2**                                          |
| `string_claims`  | every string-keyed/string-valued CWT claim, **verbatim**          |
| `receipt.root`   | clean-room RFC 6962 fold of leaf + inclusion proof                |
| receipt sig      | go-cose verify of the log's COSE_Sign1 over the reconstructed root|

The CWT_Claims map is read by re-decoding the **raw protected bstr** with
`fxamacker/cbor`, with defensive lookups across `int64`/`uint64`/`int` key
encodings — label **15** is the conformant value (NOT `13` / `kcwt`). The
receipt's `vds` (verifiable-data-structure) is read **only** from the
integrity-protected header (label 395); a `vds` placed in the unprotected header
is ignored, defeating that downgrade.

## Draft-tracking

The receipt structure tracks two IETF documents that are **Active Internet-Drafts
(Work in Progress)**, currently in the **RFC Editor Queue** and **NOT yet
published RFCs** (status per the IETF Datatracker at ship date):
`draft-ietf-cose-merkle-tree-proofs-18` (COSE Receipts / COSE Merkle Tree Proofs)
and `draft-ietf-scitt-architecture-22` (SCITT Architecture). The Merkle
primitives follow the published **RFC 9162 / RFC 6962**
(SHA-256); CWT Claims are at **label 15** (RFC 9597). ML-DSA COSE code points
referenced elsewhere are per the published **RFC 9964** (*ML-DSA for JOSE and
COSE*).

## Dependencies

- `github.com/veraison/go-cose` — COSE_Sign1 decode + signature verification
- `github.com/fxamacker/cbor/v2` — robust CBOR decode of the headers/proofs
