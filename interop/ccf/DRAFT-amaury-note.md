<!-- GATED — Steven to review and send. Do NOT transmit without Steven's approval. -->
<!-- Recipient: Amaury Chamayou (Microsoft / ietf-wg-scitt) -->
<!-- Context: IETF 126 / Vienna — CCF interop proof for the Agent Action Capsule spec -->

---

Hi Amaury,

Following up on the CCF interop offer — we've built our half of the proof and have a shared test vector ready. The goal is a two-party, byte-identical-statement interop artifact for IETF 126: the same Signed Statement registered to both our RFC9162_SHA256 log and your CCF SCITT node, with both receipts verifying independently.

**Our half (done):**

- One COSE_Sign1 Signed Statement (EdDSA, `application/agent-action-capsule+json`, 390 bytes)
- Registered to our RFC9162_SHA256 transparency log
- Receipt verified by our `scitt-cose` verifier: **ok=True**

**What we need from you:**

Register the following Signed Statement bytes on a CCF SCITT node and return:
1. The COSE Receipt bytes (binary / base64)
2. The TS public key — either the DID document (`/.well-known/did.json`) URL or the raw PEM

**The Signed Statement (base64, 390 bytes):**

```
0oRYgqMDeCVhcHBsaWNhdGlvbi9hZ2VudC1hY3Rpb24tY2Fwc3VsZStqc29uD6IBeCpodHRwczov
L2ludGVyb3AuYWN0aW9uLXN0YXRlLWdyb3VwLmV4YW1wbGUCeCV1cm46YXNnOnNjaXR0OmNjZi1p
bnRlcm9wOmlldGYxMjY6MDAxASegWLt7ImFjdGlvbl90eXBlIjoid3JpdGVfb3JkZXIiLCJjYXBz
dWxlX2lkIjoiaWV0ZjEyNi1jY2YtaW50ZXJvcC0wMDEiLCJub3RlIjoiQ0NGIGludGVyb3AgdGVz
dCB2ZWN0b3IgXHUyMDE0IElFVEYgMTI2IC8gVmllbm5hIDIwMjYtMDciLCJvcGVyYXRvciI6ImFj
dGlvbi1zdGF0ZS1ncm91cCIsInZlcmRpY3QiOiJleGVjdXRlZCJ9WECtTW9C68eh1xvOCNXXBPIW
b3cf5yMmGLvtB41IrrjoSPp6Lx1+jXSu2t6JW8aUnW8mRIWUKq2E8NFAxDC4PkAA
```

**Leaf entry (SHA-256 of the statement bytes, hex):**

```
3a7a4d068161666b576c1df40718915a57c17c0321adabb2ffe460aafdf1c654
```

This is what both our log and CCF use as the leaf entry — CCF defines it as SHA-256 of the COSE_Sign1 statement bytes, same as we do.

**Decode + register:**

```bash
# From the shared-vector.json (jq required):
jq -r '.statement.bytes_base64' shared-vector.json | base64 -d > statement.cose

# Or decode the base64 block above directly:
# (paste the base64 block, remove newlines, then: base64 -d > statement.cose)

# Register on your CCF node:
curl -X POST https://<your-ccf-node>/entries \
     -H "Content-Type: application/cose" \
     --data-binary @statement.cose
```

**Verification (once we have your receipt + TS public key):**

We'll run our verifier against the CCF receipt:

```python
from scitt_cose import verify_receipt
result = verify_receipt(ccf_receipt_bytes, leaf_entry_hex=LEAF_HEX, log_public_key_pem=ccf_ts_pub_pem)
assert result.ok  # both receipts, one statement
```

**The full shared vector** (our receipt included) is in `interop/ccf/shared-vector.json` in the `action-state-group/scitt-cose` repo.

Happy to do the verification live at IETF 126 if that makes a better demo. Let us know what CCF node you'd like to use.

Thanks,
Steven

---
<!-- END DRAFT -->
<!-- After Steven approves: send as email or GitHub comment on ietf-wg-scitt/architecture -->
