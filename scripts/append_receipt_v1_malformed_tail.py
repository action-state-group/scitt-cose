#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME append of ``fail-malformed-tail-proof`` to receipt-v1
(action-state-group/scitt-cose#91).

The receipt is genuine under ``log-key.pub``: its first inclusion proof is
valid and its signature verifies. A second proof, ``[0, 0, []]``, is appended
to the unprotected proof array. Every proof is checked before any is used, so
the receipt fails before the signature step and ``returned`` pins that no
root, tree_size or leaf_index is reported, even though the first proof would
rebuild one.

The script refuses to run if the vector exists, and appends to
``manifest.json`` and ``SHA256SUMS`` without touching an existing line. It then
self-checks the vector against this repo's verifier.
"""
from __future__ import annotations

import hashlib
import json
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from generate_receipt_grade_vectors import OUT, VERSION, _entries, _write_vector

from scitt_cose import build_receipt
from scitt_cose.receipt import HDR_VDP, VDP_INCLUSION_PROOFS, verify_receipt

ENTRIES = _entries(4)
LEAF_INDEX = 1
VID = "fail-malformed-tail-proof"
NEEDLE = "invalid tree size or leaf index"


def main() -> int:
    root_dir = OUT / VERSION
    if (root_dir / VID).exists():
        print(f"refusing to overwrite published {root_dir / VID} -- receipt-v1 is append-only")
        return 1
    key = ed25519.Ed25519PrivateKey.generate()
    genuine = build_receipt(
        leaf_entry_hex=ENTRIES[LEAF_INDEX], leaf_index=LEAF_INDEX, tree_entries_hex=ENTRIES,
        alg="EdDSA",
        log_private_key_pem=key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    protected, unprotected, payload, signature = cbor2.loads(genuine).value
    proofs = list(unprotected[HDR_VDP][VDP_INCLUSION_PROOFS]) + [cbor2.dumps([0, 0, []])]
    receipt = cbor2.dumps(cbor2.CBORTag(
        18, [protected, {HDR_VDP: {VDP_INCLUSION_PROOFS: proofs}}, payload, signature]
    ))
    log_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    _write_vector(
        VID,
        description=(
            "Genuine receipt whose valid inclusion proof is followed by a malformed one, "
            "[0, 0, []]. Every proof is checked before any is used, so it fails before the "
            "signature step; no root, tree_size or leaf_index is reported."
        ),
        alg="EdDSA", leaf_entry_hex=ENTRIES[LEAF_INDEX], tree_size=len(ENTRIES),
        leaf_index=LEAF_INDEX, receipt=receipt, log_pub=log_pub, expect_ok=False,
        expect_iat=None, expect_grade=None, expect_witness_time=False,
        expect_grade_bound=False, expect_root=None, failure_contains=NEEDLE,
    )
    expected_path = root_dir / VID / "expected.json"
    expected = json.loads(expected_path.read_text())
    expected["returned"] = {"root": None, "tree_size": None, "leaf_index": None}
    expected_path.write_text(json.dumps(expected, indent=2) + "\n")

    manifest_path = root_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["vectors"].append({"id": VID, "dir": f"{VERSION}/{VID}", "ok": False})
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with (root_dir / "SHA256SUMS").open("a") as fh:
        fh.write("".join(
            f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(root_dir)}\n"
            for f in sorted((root_dir / VID).iterdir())
        ))
    print(f"appended {VID} under {root_dir}")

    # Self-check: the receipt without the tail verifies; with it, nothing.
    if not verify_receipt(genuine, leaf_entry_hex=ENTRIES[LEAF_INDEX], log_public_key_pem=log_pub).ok:
        print("SELF-CHECK FAILED: the untampered receipt does not verify")
        return 1
    res = verify_receipt(receipt, leaf_entry_hex=ENTRIES[LEAF_INDEX], log_public_key_pem=log_pub)
    if res.ok or not any(NEEDLE in e for e in res.errors) or (res.root, res.tree_size, res.leaf_index) != (None, None, None):
        print(f"SELF-CHECK FAILED {VID}: ok={res.ok} root={res.root} errors={res.errors}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
