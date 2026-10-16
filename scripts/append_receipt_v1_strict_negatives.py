#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME append of the attached-payload and alg/key-pairing negatives to
receipt-v1 (action-state-group/scitt-cose#87).

Every receipt here carries a valid inclusion proof and a signature that is
genuine under ``log-key.pub``; each must still be rejected:

* ``fail-attached-payload``: the payload slot carries bytes other than the
  root, and the log key signed those bytes. A verifier that checks the
  signature over the attached payload binds nothing to the proven leaf.
* ``fail-attached-payload-root``: the payload slot carries the root itself,
  signed. A verifier that ignores the slot accepts it; a Receipt's payload is
  detached, so it must not.
* ``fail-es256-secp256k1-key``: alg ES256 (-7) signed under a secp256k1 key.
  ES256 is ECDSA over P-256 (RFC 9053 §2.1). (A P-384 key cannot stand in
  here: its r and s do not fit ES256's 64-byte signature.)
* ``fail-es384-p256-key``: alg ES384 (-35) signed under a P-256 key, r and s
  left-padded to ES384's 96 bytes.
* ``fail-eddsa-p256-key``: alg EdDSA (-8) with a P-256 log key. The signature
  is an ECDSA one, so this pins only that the key type is checked.

The signatures are made here by hand, not with ``sign_sign1``, which refuses
these pairings. The script refuses to run if any of the vectors exists, and
appends to ``manifest.json`` and ``SHA256SUMS`` without touching an existing
line. It then self-checks each vector against this repo's verifier.
"""
from __future__ import annotations

import hashlib
import json
import sys

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from generate_receipt_grade_vectors import OUT, VERSION, _entries, _write_vector

from scitt_cose import inclusion_proof, merkle_root
from scitt_cose.receipt import HDR_VDP, HDR_VDS, VDP_INCLUSION_PROOFS, verify_receipt

ENTRIES = _entries(4)
LEAF_INDEX = 1


def _pub_pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _receipt(alg_code: int, key, payload: bytes, *, attached: bool, hash_alg=None, width=0) -> bytes:
    """A receipt over ``ENTRIES[LEAF_INDEX]`` whose signature covers ``payload``."""
    path = inclusion_proof(ENTRIES, LEAF_INDEX)
    proof = cbor2.dumps([len(ENTRIES), LEAF_INDEX, [bytes.fromhex(h) for h in path]])
    protected = cbor2.dumps({1: alg_code, HDR_VDS: 1})
    tbs = cbor2.dumps(["Signature1", protected, b"", payload])
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(tbs)
    else:
        r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(hash_alg)))
        signature = r.to_bytes(width, "big") + s.to_bytes(width, "big")
    unprotected = {HDR_VDP: {VDP_INCLUSION_PROOFS: [proof]}}
    return cbor2.dumps(
        cbor2.CBORTag(18, [protected, unprotected, payload if attached else None, signature])
    )


def main() -> int:
    root_dir = OUT / VERSION
    root = bytes.fromhex(merkle_root(ENTRIES))
    ed = ed25519.Ed25519PrivateKey.generate()
    k1 = ec.generate_private_key(ec.SECP256K1())
    p256 = ec.generate_private_key(ec.SECP256R1())
    vectors = [
        ("fail-attached-payload", "EdDSA", ed,
         _receipt(-8, ed, b"not the merkle root", attached=True), "attached",
         "Payload slot carries bytes other than the root, signed by the log key. "
         "The signature binds nothing to the proven leaf; must be rejected as attached."),
        ("fail-attached-payload-root", "EdDSA", ed,
         _receipt(-8, ed, root, attached=True), "attached",
         "Payload slot carries the root itself, signed. A Receipt's payload is detached; "
         "must be rejected as attached even though the bytes match."),
        ("fail-es256-secp256k1-key", "ES256", k1,
         _receipt(-7, k1, root, attached=False, hash_alg=hashes.SHA256(), width=32), "public key",
         "alg ES256 (-7) with a genuine signature under a secp256k1 log key. "
         "ES256 is ECDSA over P-256 (RFC 9053 §2.1); must be rejected."),
        ("fail-es384-p256-key", "ES384", p256,
         _receipt(-35, p256, root, attached=False, hash_alg=hashes.SHA384(), width=48), "-35",
         "alg ES384 (-35) with a genuine SHA-384 signature under a P-256 log key, r and s "
         "padded to 48 bytes. ES384 is ECDSA over P-384; must be rejected."),
        ("fail-eddsa-p256-key", "EdDSA", p256,
         _receipt(-8, p256, root, attached=False, hash_alg=hashes.SHA256(), width=32), "public key",
         "alg EdDSA (-8) with a P-256 log key. EdDSA here is Ed25519; must be rejected."),
    ]
    for vid, *_ in vectors:
        if (root_dir / vid).exists():
            print(f"refusing to overwrite published {root_dir / vid} -- receipt-v1 is append-only")
            return 1

    manifest_path = root_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    sums = []
    for vid, alg, key, receipt, needle, description in vectors:
        _write_vector(
            vid, description=description, alg=alg, leaf_entry_hex=ENTRIES[LEAF_INDEX],
            tree_size=len(ENTRIES), leaf_index=LEAF_INDEX, receipt=receipt,
            log_pub=_pub_pem(key), expect_ok=False, expect_iat=None, expect_grade=None,
            expect_witness_time=False, expect_grade_bound=False, expect_root=None,
            failure_contains=needle,
        )
        manifest["vectors"].append({"id": vid, "dir": f"{VERSION}/{vid}", "ok": False})
        sums += [
            f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(root_dir)}"
            for f in sorted((root_dir / vid).iterdir())
        ]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with (root_dir / "SHA256SUMS").open("a") as fh:
        fh.write("\n".join(sums) + "\n")
    print(f"appended {len(vectors)} vectors under {root_dir}")

    failed = 0
    for vid, _alg, _key, receipt, needle, _ in vectors:
        exp = json.loads((root_dir / vid / "expected.json").read_text())
        res = verify_receipt(receipt, leaf_entry_hex=exp["leaf_entry_hex"],
                             log_public_key_pem=(root_dir / vid / "log-key.pub").read_bytes())
        if res.ok or not any(needle in e for e in res.errors):
            failed += 1
            print(f"SELF-CHECK FAILED {vid}: ok={res.ok} errors={res.errors}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
