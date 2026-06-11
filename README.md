<!-- SPDX-License-Identifier: Apache-2.0 -->
# scitt-cose

A generic, **payload-agnostic** IETF **SCITT + COSE Receipts** substrate for Python:
build/verify COSE_Sign1 **Signed Statements**, verify **Receipts** and RFC 9162
**inclusion / consistency proofs**, with the **Merkle + receipt-signing
primitives**.

It is **NOT a transparency service** (operating a log — a hosted registration
endpoint — is a separate concern), and it carries **NO application profile** —
bring your own statement semantics. The only third-party dependencies anywhere
in the package are [`cbor2`](https://pypi.org/project/cbor2/) and
[`cryptography`](https://pypi.org/project/cryptography/), plus the standard
library. COSE_Sign1 (RFC 9052) is implemented here from scratch — it does **not**
use `python-cwt` or any other COSE library.

> **Name note.** `scitt-cose` is the finalized package name, claimed on PyPI
> and GitHub (`action-state-group/scitt-cose`) in the same pass.

## What this does / does not do

**Does:**

- Verify a SCITT **Signed Statement** (`COSE_Sign1`) signature against a supplied
  key — EdDSA and ES256 — and report its issuer / subject / content-type / alg.
- Verify a **COSE Receipt** whose verifiable data structure is
  **`RFC9162_SHA256`** (vds = 1, the tree algorithm registered by
  draft-ietf-cose-merkle-tree-proofs): the RFC 9162 SHA-256 inclusion proof
  *and* the log's signature over the reconstructed root — i.e. *"this statement
  is provably in the log"* — **without trusting the log operator**. The vds value
  is read from the protected header only and anything other than
  `RFC9162_SHA256` is rejected, not silently accepted.
- Provide the RFC 9162 **Merkle primitives** (root, inclusion, consistency) and a
  `build_receipt` primitive.

**Does NOT:**

- **Operate a Transparency Service.** It never registers statements, issues
  receipts, anchors, or stores anything. Running a log is a separate concern with
  its own operational trust obligations.
- **Validate any application profile's payload semantics.** The statement payload
  is treated as **opaque bytes**. There is no application-profile awareness —
  SBOMs, agent actions, or anything else; that neutrality is deliberate, and is
  what makes this reusable by *anyone* in the SCITT ecosystem.
- **Depend on a COSE library for wire values.** `COSE_Sign1` is implemented from
  scratch over `cbor2` + `cryptography`; code points are pinned to the IANA
  registries, not to a library's enum.

## Why this exists

This is a **standalone, profile-opaque, cross-validated** generic SCITT/COSE
verifier: it verifies *anyone's* SCITT Signed Statements and COSE Receipts, treats
the payload as opaque bytes, and its conformance is checked against independent,
external references (the published RFC 6962/9162 Merkle vectors, a third-party
COSE library, and a separate Go implementation — see
[Correctness & cross-implementation evidence](#correctness--cross-implementation-evidence)).

It is intended to be useful as **neutral substrate**: the parts that exist today
don't fit that gap cleanly — `python-cwt` is COSE-only (no SCITT/Receipts), and a
transparency-service emulator is a server, not a verification library you depend
on. So this is the small building block — a second, independent implementation
you can verify against, with no profile baked in. (No primacy is claimed; the
value is neutrality + verifiable conformance, not being "first".)

An agent-action profile is **one** example consumer that builds its
statement/claim semantics *on top of* this substrate — but nothing
profile-specific lives here.

## Provenance, neutrality & governance

Three things an adopter should know up front:

1. **Built by [Action State Group](https://actionstate.ai).** We built this for
   our own SCITT use and publish it as community substrate under Apache-2.0.
2. **Neutral by design.** No application profile, no vendor coupling,
   payload-opaque. The package imports only `cbor2`, `cryptography`, and the
   standard library — it does not import any Action State code, and a test
   gate (`tests/test_iana_codepoints.py`) enforces that this stays true.
3. **Foundation intent.** We intend to contribute this project to a neutral
   open-source foundation so its governance does not rest with any single
   vendor. Which foundation is deliberately not yet decided; until then it is
   governed in the open under DCO + Apache-2.0 (see
   [CONTRIBUTING.md](CONTRIBUTING.md)).

## Scope

In scope (library plumbing):

- Build / parse / verify **Signed Statements** and **Transparent Statements**.
- Verify **Receipts** + RFC 9162 **inclusion** and **consistency** proofs.
- RFC 9162 SHA-256 **Merkle primitives** and the **receipt-signing** primitive
  (`build_receipt`) — so you *can* mint receipts as a building block.

Out of scope (documented, deliberately not built):

- **Operating a transparency log / service.** A hosted registration endpoint,
  log storage, monitoring, witnessing, gossip — none of that is here. The
  primitives needed to build one (Merkle tree, receipt signing) **are** included.

## Install

```bash
pip install cbor2 cryptography          # runtime deps
# from a checkout (package root):
pip install -e .
```

## Quick start

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from scitt_cose import (
    build_signed_statement, parse_signed_statement,
    merkle_root, inclusion_proof, verify_inclusion,
    consistency_proof, verify_consistency,
    build_receipt, verify_receipt,
    attach_receipts, extract_receipts,
)

# --- a key (caller supplies everything) ---
sk = ed25519.Ed25519PrivateKey.generate()
priv = sk.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption())
pub = sk.public_key().public_bytes(serialization.Encoding.PEM,
                                    serialization.PublicFormat.SubjectPublicKeyInfo)

# --- Signed Statement (generic; no profile) ---
stmt = build_signed_statement(
    b'{"hello":"world"}',
    alg="EdDSA", private_key_pem=priv,
    issuer="https://issuer.example",
    subject="my-artifact",
    content_type="application/json",
    extra_cwt_claims={"my_claim": "x", 99: 1},  # str- or int-keyed
)
parsed = parse_signed_statement(stmt, public_key_pem=pub)
assert parsed["signature_verified"] is True
assert parsed["issuer"] == "https://issuer.example"

# --- Merkle (RFC 9162 SHA-256; hex in/out) ---
entries = [b"a".hex(), b"b".hex(), b"c".hex(), b"d".hex()]
root = merkle_root(entries)
path = inclusion_proof(entries, 2)
assert verify_inclusion(entries[2], 2, len(entries), path, root)

cproof = consistency_proof(entries, 2, 4)
assert verify_consistency(merkle_root(entries[:2]), root, 2, 4, cproof)

# --- Receipt (primitive) + verify ---
receipt = build_receipt(
    leaf_entry_hex=entries[2], leaf_index=2, tree_entries_hex=entries,
    alg="EdDSA", log_private_key_pem=priv,     # here the "log" key is our key
)
res = verify_receipt(receipt, leaf_entry_hex=entries[2], log_public_key_pem=pub)
assert res.ok and res.root == root

# --- Transparent Statement = Signed Statement + Receipts ---
transparent = attach_receipts(stmt, [receipt])
assert extract_receipts(transparent) == [receipt]
```

## CLI

```bash
scitt-cose --statement stmt.cose --statement-pubkey issuer.pem
scitt-cose --receipt receipt.cose --receipt-log-pubkey log.pem --leaf-entry-hex 61
scitt-cose --statement stmt.cose --receipt receipt.cose \
           --receipt-log-pubkey log.pem --leaf-entry-hex 61 --json
```

## Public API

| Area | Functions / types |
|---|---|
| COSE_Sign1 | `sign_sign1`, `verify_sign1`, `Sign1`, `CoseError` |
| Statements | `build_signed_statement`, `parse_signed_statement`, `attach_receipts`, `extract_receipts` |
| Merkle | `leaf_hash`, `merkle_root`, `inclusion_proof`, `verify_inclusion`, `consistency_proof`, `verify_consistency` |
| Receipts | `build_receipt`, `verify_receipt`, `ReceiptResult` |
| Status | `DRAFT_TRACKING_NOTICE`, `DRAFT_SCITT_ARCHITECTURE`, `DRAFT_COSE_MERKLE_TREE_PROOFS`, `SUBSTRATE_RFCS` |

### Algorithms

`sign_sign1` / statements support `"EdDSA"` (code point −8) and `"ES256"`
(−7). For ES256, COSE carries the signature as **raw `r || s`** (64 bytes), not
DER; the conversion happens at the `cryptography` boundary. ML-DSA code points
(RFC 9964) are *recognized* in the status notice but signing is **not**
implemented here.

### Why CWT Claims at label 15 (not 13)

Signed-Statement CWT Claims are placed in the protected header at **label 15**,
the "CWT Claims" header parameter registered by **RFC 9597 §2**. Label **13** is
a different parameter (`kcwt`, RFC 9528) and is sometimes mistakenly used for the
claims map; this library always reads and writes the claims at **15**.

### Receipt vdp encoding (honest caveat)

The Receipt's verifiable-data-proof shape tracks
**draft-ietf-cose-merkle-tree-proofs-18**:

- protected `1` = alg, protected `395` = vds (`1` = `RFC9162_SHA256`);
- unprotected `396` = vdp map with key `-1` → array of inclusion-proof bstrs;
- each inclusion-proof bstr = `cbor([tree_size, leaf_index, [audit_path bstrs]])`;
- payload = the Merkle root (detached by default).

`verify_receipt` reads **vds from the protected header only** (it is
security-relevant and must be integrity-protected), reconstructs the root from
the proof, and verifies the COSE_Sign1 over that root with the log key. Because
the underlying documents are **drafts, not RFCs**, this exact CBOR shape is
**validated by round-trip in this library's own tests**, not against a frozen
RFC. Treat the wire shape as draft-tracking.

## Draft-tracking / standards honesty

This library tracks two IETF documents that are **Active Internet-Drafts (Work in
Progress)** — they have been approved and are in the **RFC Editor Queue**, but are
**NOT yet published RFCs** (status audited against the IETF Datatracker at ship
date; re-verify at publish time, since RFC-Ed-Queue documents can be published at
any point):

- `draft-ietf-scitt-architecture-22` — *SCITT Architecture* (Datatracker:
  Active Internet-Draft, RFC Ed Queue)
- `draft-ietf-cose-merkle-tree-proofs-18` — *COSE Receipts / COSE Merkle Tree
  Proofs* (Datatracker: Active Internet-Draft, RFC Ed Queue)

No unassigned RFC number is claimed anywhere (enforced by a test that scans
shipped source + docs).

Published RFCs whose mechanisms this library implements / relies on (titles
verified against the RFC Editor / IANA registries):

- **RFC 9052** — *CBOR Object Signing and Encryption (COSE): Structures and
  Process* (COSE_Sign1, Sig_structure).
- **RFC 9053** — *COSE: Initial Algorithms* (EdDSA −8, ES256 −7).
- **RFC 9162** — *Certificate Transparency Version 2* (SHA-256 Merkle tree;
  inclusion and consistency proofs; reuses the RFC 6962 tree hash).
- **RFC 9597** — *CBOR Web Token (CWT) Claims in COSE Headers* — the **CWT Claims**
  header parameter at **label 15** (IANA COSE Header Parameters registry). Label
  **13** is `kcwt` and **14** is `kccs`, both from **RFC 9528** (EDHOC) — *not* the
  CWT Claims map; using 13 for claims is the python-cwt bug this library avoids.
- **RFC 9964** — *ML-DSA for JOSE and COSE* (code points recognized; ML-DSA
  signing not implemented here).

## Independence

`scitt_cose/` imports **only** `cbor2`, `cryptography`, and the standard library.
It does **not** import `cwt` / `python-cwt`, `pycose`, or any consuming
product/profile package. Verify:

```bash
grep -rnE 'import (cwt|pycose)\b' scitt_cose/   # → nothing
```

Two tests keep this true: the COSE-library import guard and the
no-downstream-code neutrality gate (both in `tests/test_iana_codepoints.py`).

## Correctness & cross-implementation evidence

For a *community* verifier, "trust me, it's conformant" is worthless. The
correctness story rests on agreement with things **outside this library**, not on
self-consistency:

- **Cross-language agreement (in CI).** An independent Go verifier
  (the `scitt-cose-go-verify` directory, built on `veraison/go-cose` + `fxamacker/cbor`,
  with a clean-room Merkle fold) verifies the statements *and receipts* this
  library emits, agrees on the reconstructed Merkle root, and rejects tampered
  inputs. CI runs it with `SCITT_REQUIRE_GO=1`, so the cross-check can never
  silently skip. (`tests/test_crosslang_go.py`)
- **The standard's own test vectors.** The Merkle code is checked against the
  published RFC 6962 / RFC 9162 reference vectors (8-leaf root `5dc9da79…`, the
  canonical inclusion/consistency proofs) — external values, not ours.
  (`tests/test_rfc9162_vectors.py`)
- **A third-party COSE library.** `pycose` (independent of us, and *not*
  `python-cwt`) both verifies our statements and emits statements *we* verify —
  so the round-trip isn't self-referential. (`tests/test_thirdparty_cose.py`)
- **The COSE standard's own reference-signed vector.** We verify the canonical
  COSE_Sign1 the COSE WG published (RFC 9052 §C.2.1, ES256, from the
  `cose-wg/Examples` corpus) — anchoring the *signature* layer to the spec's
  reference output, just as the RFC 6962 vectors anchor the Merkle layer.
  (`tests/test_cose_wg_vectors.py`)
- **A real Transparency-Service verifier.** A downstream Transparency
  Service's own verifier — written independently of this package, on a
  *different* COSE stack (`python-cwt`, vs this package's from-scratch
  `cbor2`/`cryptography`) — cross-verifies the same Signed Statements and the
  same TS-issued Receipts and agrees on the reconstructed Merkle root, in both
  directions. This exercises the real register→issue→verify shape; the
  integration test lives in the consuming repo (so this package stays
  standalone). This is **not** the hosted verify endpoint: that endpoint runs
  this package unchanged (a convenience deployment, deliberately the *same*
  library), so it is not an independent oracle — the python-cwt verifier is.
- **IANA values, not library enums.** Every wire code point is asserted against
  its registry/RFC number (CWT Claims **15**, not python-cwt's `13`).
  (`tests/test_iana_codepoints.py`)
- **Spec-driven negative suite.** The MUST-reject conditions — alg confusion,
  critical-header (`crit`) handling, `vds` downgrade, wrong-leaf/wrong-log
  receipts, Merkle edge cases, malformed CBOR — each have a test.
  (`tests/test_negative_conformance.py`)

> **Evaluated and not used: the SCITT API emulator.** The `scitt-community/`
> `scitt-api-emulator` was considered as an ecosystem oracle and rejected: it is
> archived/unmaintained (final "pre-archive" tag, Nov 2024) and emits the
> *obsolete* pre-standard receipt format (`draft-birkholz-scitt-receipts` —
> string labels `service_id`/`tree_alg`, not a COSE_Sign1 receipt, not the
> `vds`=395 / `vdp`=396 RFC 9162 structure this library verifies); its statements
> use `pycose`, already covered above. Pinning a non-conformant, drift-prone
> implementation would be a *misleading* oracle, so the COSE WG spec vector is
> used in its place.

## Hosted verification — a standalone SCITT-only verifier

`scitt_cose.hosted` is a **stateless, read-only** wrapper over the *same* verify
functions, so you can offer verification without anyone installing anything — and
without the submitter having to trust the operator with their data (nothing
stored, nothing logged, payload-opaque; the receipt path needs only the leaf
*digest*, never the payload). `tests/test_hosted_parity.py` asserts the hosted
verdict equals the local verdict on a fixture set, including the ASGI path.

**This is a SCITT-*only* verifier, and it is NOT a Transparency Service.** It
verifies statements and receipts; it never registers, issues receipts, or
anchors. Running a Transparency Service is a **separate** offering with its own
operational trust obligations — deliberately out of scope here.

Run it standalone (no other service involved):

```bash
# Zero extra deps — stdlib HTTP server:
scitt-cose-serve                                  # 127.0.0.1:8080

# Or under a production ASGI server (pip install "scitt-cose[serve]"):
uvicorn scitt_cose.hosted:make_asgi_app --factory --host 0.0.0.0 --port 8080

# Or containerized (Dockerfile ships with the package):
docker build -t scitt-verifier . && docker run -p 8080:8080 scitt-verifier
```

```
GET  /         -> capabilities (what it does / does not do)
POST /verify   -> {valid, statement, receipt, reasons}   # JSON body, see below
```

`GET /` is content-negotiated: browsers (`Accept: text/html`) get a static
landing **page that renders the verifier-vs-Transparency-Service boundary table
on the page itself** — not buried in docs — while API clients get the same data
as JSON (including a `boundary` field). Both are generated from the same
constants (`scitt_cose.hosted.BOUNDARY_TABLE`), so page and API can't drift;
`tests/test_hosted_page.py` pins the table's presence on both.

It can also **ride along** inside an existing ASGI app via
`app.mount("/scitt-verify", scitt_cose.hosted.make_asgi_app())` — same logic,
shared deployment, still standalone code. The full design, submitter-safety
constraints, and proposed deployment shape are in
[`docs/hosted-verifier-design.md`](docs/hosted-verifier-design.md). The package
is ready to run privately today; a **public** endpoint is a coordinated launch,
not shipped reflexively.

## Tests

```bash
python3 -m pytest -q                     # unit + conformance suite (package root)
SCITT_REQUIRE_GO=1 python3 -m pytest -q  # also forces the Go cross-check
python3 -m ruff check .
```

## License & contributing

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions are
accepted under the Developer Certificate of Origin (sign your commits with
`git commit -s`); scope rules and the standards-honesty gates are in
[CONTRIBUTING.md](CONTRIBUTING.md).
