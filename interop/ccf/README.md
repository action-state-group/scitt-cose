# CCF Interop Artifacts — IETF 126

Cross-TS interop proof: a COSE_Sign1 Signed Statement anchored on two independent
Transparency Services (our RFC9162_SHA256 log + Microsoft's CCF SCITT dev node),
both receipts verified by `scitt_cose.verify_receipt`.

## Files

| File | Purpose |
|------|---------|
| `shared-vector.json` | All interop artifacts: statements, receipts, verify results, status table |
| `DRAFT-amaury-note.md` | **GATED** — draft note for Steven to send to Amaury (historical; exchange complete) |

## Status

| Claim | Status |
|-------|--------|
| Our EdDSA statement on our RFC9162 TS | ✅ closed — ok=True, root `470c3e3d…` |
| Amaury's ES256 statement on CCF dev node | ✅ closed — ok=True, vds=2, txid 2.15 (dev node — not production) |
| Amaury's ES256 statement on our RFC9162 TS | ✅ closed — ok=True, leaf_index 151, root `68541343…` |
| Same-statement-two-TS (CCF-format statement) | ✅ **CLOSED** — both B1+B2 verify ok=True |
| Our Ed25519 statement on CCF | ⏳ open — CCF policy required ES256; pending CCF Ed25519 support |

## Verify all three receipts

```python
import base64, hashlib, json
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scitt_cose import verify_receipt

v = json.load(open("interop/ccf/shared-vector.json"))

# Direction A: our EdDSA statement, our receipt
stmt_a = bytes.fromhex(v["statement"]["bytes_hex"])
r_a = base64.b64decode(v["our_receipt"]["bytes_base64"])
result_a = verify_receipt(r_a,
    leaf_entry_hex=hashlib.sha256(stmt_a).hexdigest(),
    log_public_key_pem=v["our_receipt"]["ts_public_key_pem"])
print("A  (EdDSA/our TS):", result_a.ok, result_a.errors)

# Direction B1: Amaury's ES256 statement, CCF receipt
stmt_b = base64.b64decode(v["direction_flip"]["statement_bytes_base64"])
r_b1 = base64.b64decode(v["ccf_receipt"]["receipt_bytes_base64"])
cert = x509.load_pem_x509_certificate(v["ccf_receipt"]["ts_cert_pem"].encode())
ccf_pub = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
result_b1 = verify_receipt(r_b1,
    leaf_entry_hex=hashlib.sha256(stmt_b).hexdigest(),
    log_public_key_pem=ccf_pub)
print("B1 (ES256/CCF):  ", result_b1.ok, result_b1.errors)

# Direction B2: Amaury's ES256 statement, our receipt (direction flip)
r_b2 = base64.b64decode(v["direction_flip"]["our_receipt"]["bytes_base64"])
result_b2 = verify_receipt(r_b2,
    leaf_entry_hex=hashlib.sha256(stmt_b).hexdigest(),
    log_public_key_pem=v["direction_flip"]["our_receipt"]["ts_public_key_pem"])
print("B2 (ES256/our TS):", result_b2.ok, result_b2.errors)
```

Expected output (verbatim from 2026-07-19 run):
```
A  (EdDSA/our TS): True []
B1 (ES256/CCF):   True []
B2 (ES256/our TS): True []
```
