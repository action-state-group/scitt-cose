#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME append of the failure-shape vectors to receipt-v1
(action-state-group/scitt-cose#91).

Each vector fails, and its ``expected.json`` carries ``returned``: the
``root``, ``tree_size`` and ``leaf_index`` every verifier must report for it.

* ``fail-wrong-log-key``: a well-formed receipt signed by an Ed25519 key other
  than ``log-key.pub``. It fails in the signature step, so the verifier reports
  the first proof's root and coordinates as an unauthenticated diagnostic.
* ``fail-unsupported-alg``: a well-formed receipt whose protected alg is
  ES512 (-36), which no verifier here supports. That is also a failure in the
  signature step, so the diagnostic is reported.
* ``fail-malformed-proof``: the inclusion proof's leaf index is outside its
  tree. It fails before the signature step, so nothing is reported.

The script refuses to run if any of the vectors exists, and appends to
``manifest.json`` and ``SHA256SUMS`` without touching an existing line. It then
self-checks each vector against this repo's verifier.
"""
from __future__ import annotations

import hashlib
import json
import sys

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from generate_receipt_grade_vectors import OUT, VERSION, _entries, _write_vector

from scitt_cose import build_receipt, inclusion_proof, merkle_root
from scitt_cose.receipt import HDR_VDP, HDR_VDS, VDP_INCLUSION_PROOFS, verify_receipt

ENTRIES = _entries(4)
LEAF_INDEX = 1


def _priv_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _pub_pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _hand_receipt(alg_code: int, proof: list, signature: bytes) -> bytes:
    """A detached receipt over ``ENTRIES[LEAF_INDEX]`` with the given proof and
    signature bytes; nothing here needs the signature to verify."""
    protected = cbor2.dumps({1: alg_code, HDR_VDS: 1})
    unprotected = {HDR_VDP: {VDP_INCLUSION_PROOFS: [cbor2.dumps(proof)]}}
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, None, signature]))


def main() -> int:
    root_dir = OUT / VERSION
    root = merkle_root(ENTRIES)
    path = [bytes.fromhex(h) for h in inclusion_proof(ENTRIES, LEAF_INDEX)]
    signer = ed25519.Ed25519PrivateKey.generate()
    holder = ed25519.Ed25519PrivateKey.generate()
    p256 = ec.generate_private_key(ec.SECP256R1())
    diagnostic = {"root": root, "tree_size": len(ENTRIES), "leaf_index": LEAF_INDEX}
    nothing = {"root": None, "tree_size": None, "leaf_index": None}
    vectors = [
        ("fail-wrong-log-key", "EdDSA", holder,
         build_receipt(leaf_entry_hex=ENTRIES[LEAF_INDEX], leaf_index=LEAF_INDEX,
                       tree_entries_hex=ENTRIES, alg="EdDSA",
                       log_private_key_pem=_priv_pem(signer)),
         "signature", diagnostic,
         "Well-formed receipt signed by an Ed25519 key other than log-key.pub. Fails in the "
         "signature step; the first proof's root, tree_size and leaf_index are reported as an "
         "unauthenticated diagnostic."),
        ("fail-unsupported-alg", "ES512", p256,
         _hand_receipt(-36, [len(ENTRIES), LEAF_INDEX, path], bytes(132)),
         "unsupported alg code point", diagnostic,
         "Well-formed receipt whose protected alg is ES512 (-36), which no verifier here "
         "supports. Fails in the signature step; the first proof's values are reported."),
        ("fail-malformed-proof", "EdDSA", signer,
         _hand_receipt(-8, [len(ENTRIES), len(ENTRIES) + 3, path], bytes(64)),
         "invalid tree size or leaf index", nothing,
         "Inclusion proof whose leaf_index lies outside its tree. Fails before the signature "
         "step; no root, tree_size or leaf_index is reported."),
    ]
    for vid, *_ in vectors:
        if (root_dir / vid).exists():
            print(f"refusing to overwrite published {root_dir / vid} -- receipt-v1 is append-only")
            return 1

    manifest_path = root_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    sums = []
    for vid, alg, key, receipt, needle, returned, description in vectors:
        _write_vector(
            vid, description=description, alg=alg, leaf_entry_hex=ENTRIES[LEAF_INDEX],
            tree_size=len(ENTRIES), leaf_index=LEAF_INDEX, receipt=receipt,
            log_pub=_pub_pem(key), expect_ok=False, expect_iat=None, expect_grade=None,
            expect_witness_time=False, expect_grade_bound=False, expect_root=None,
            failure_contains=needle,
        )
        expected_path = root_dir / vid / "expected.json"
        expected = json.loads(expected_path.read_text())
        expected["returned"] = returned
        expected_path.write_text(json.dumps(expected, indent=2) + "\n")
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
    for vid, _alg, _key, receipt, needle, returned, _ in vectors:
        exp = json.loads((root_dir / vid / "expected.json").read_text())
        res = verify_receipt(receipt, leaf_entry_hex=exp["leaf_entry_hex"],
                             log_public_key_pem=(root_dir / vid / "log-key.pub").read_bytes())
        got = {"root": res.root, "tree_size": res.tree_size, "leaf_index": res.leaf_index}
        if res.ok or not any(needle in e for e in res.errors) or got != returned:
            failed += 1
            print(f"SELF-CHECK FAILED {vid}: ok={res.ok} returned={got} errors={res.errors}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
