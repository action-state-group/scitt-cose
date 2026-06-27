# CCF Interop Artifacts — IETF 126

Two-party interop proof: the same COSE_Sign1 Signed Statement registered to two
independent Transparency Services (our RFC9162_SHA256 log + Microsoft's CCF
SCITT node), both receipts verified by `scitt_cose.verify_receipt`.

## Files

| File | Purpose |
|------|---------|
| `shared-vector.json` | The shared test vector: statement bytes, our receipt, leaf entry, expected verify result |
| `DRAFT-amaury-note.md` | **GATED** — draft note for Steven to send to Amaury (Microsoft) requesting CCF registration |

## Status

| Step | Status |
|------|--------|
| Signed Statement (our side) | ✅ generated |
| Our RFC9162_SHA256 receipt | ✅ verified (ok=True, root confirmed) |
| CCF receipt (Microsoft side) | ⏳ pending — awaiting Amaury registration |
| Two-receipt verify | ⏳ pending — runs once CCF receipt is received |

## Verify our receipt

```bash
python3 - <<'EOF'
import json, base64
from scitt_cose import verify_receipt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

v = json.load(open("interop/ccf/shared-vector.json"))
receipt = base64.b64decode(v["our_receipt"]["bytes_base64"])
ts_pub_pem = v["our_receipt"]["ts_public_key_pem"].encode()
entry_hex = v["leaf_entry"]["hex"]

result = verify_receipt(receipt, leaf_entry_hex=entry_hex, log_public_key_pem=ts_pub_pem)
print(f"ok={result.ok}  root={result.root}  tree_size={result.tree_size}")
EOF
```

## Once CCF receipt is received from Amaury

Add the CCF receipt bytes and TS public key to `shared-vector.json` under
`ccf_receipt.bytes_base64` and `ccf_receipt.ts_public_key_pem`, then run:

```bash
python3 - <<'EOF'
import json, base64
from scitt_cose import verify_receipt

v = json.load(open("interop/ccf/shared-vector.json"))
ccf_receipt = base64.b64decode(v["ccf_receipt"]["bytes_base64"])
ccf_ts_pub = v["ccf_receipt"]["ts_public_key_pem"].encode()
entry_hex = v["leaf_entry"]["hex"]

result = verify_receipt(ccf_receipt, leaf_entry_hex=entry_hex, log_public_key_pem=ccf_ts_pub)
assert result.ok, f"CCF receipt did not verify: {result.errors}"
print(f"CCF receipt verified: ok={result.ok}  root={result.root}  tree_size={result.tree_size}")
EOF
```

## Local CCF node (Docker, alternative to waiting for Amaury)

See `tests/test_ccf_interop.py` for the integration test. With Docker + colima:

```bash
cd /path/to/scitt-ccf-ledger
DOCKER_HOST=unix:///~/.colima/default/docker.sock \
  DOCKER_BUILDKIT=1 docker build --platform linux/amd64 -t scitt -f docker/Dockerfile .
./docker/run-dev.sh   # serves https://localhost:8000
SCITT_CCF_URL=https://localhost:8000 SCITT_CCF_TLS_VERIFY=0 \
  pytest -m integration tests/test_ccf_interop.py::test_ccf_sandbox_live
```
