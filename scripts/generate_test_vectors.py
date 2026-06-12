#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME generator for the v1 cross-implementation test-vector set.

This script minted the bytes committed under ``test-vectors/v1/``. It is kept
for provenance and for building FUTURE versions (v2, ...) — it must NOT be
re-run over a published version: v1 is append-only, and regenerating would
produce new keys and new bytes, silently breaking every implementation that
pinned the published set. The script refuses to overwrite an existing
version directory for exactly that reason.

Tree construction (documented contract — see test-vectors/README.md):

* The transparency log's **leaf entry** for a registered Signed Statement is
  the **SHA-256 digest of the complete COSE_Sign1 statement bytes**.
* Each vector's log has ``tree_size = 8`` leaves. The statement under test sits
  at ``leaf_index = 2``; every other leaf i is the deterministic filler
  ``SHA-256(b"scitt-cose test vectors v1 :: <vector-id> :: filler leaf <i>")``.
* Leaf order is index order (0..7). Anyone can rebuild the exact log state
  from this description and the committed statement bytes.

Keys are freshly generated for this set, committed alongside the vectors, and
named ``*.test-private`` — TEST-ONLY, never used anywhere else.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scitt_cose import (  # noqa: E402
    build_receipt,
    build_signed_statement,
    inclusion_proof,
    merkle_root,
)
from scitt_cose.cose_sign1 import sign_sign1  # noqa: E402
from scitt_cose.receipt import HDR_VDP, HDR_VDS, VDP_INCLUSION_PROOFS, verify_receipt  # noqa: E402
from scitt_cose.statement import parse_signed_statement  # noqa: E402

VERSION = "v1"
TREE_SIZE = 8
LEAF_INDEX = 2
OUT = REPO / "test-vectors"

ALG_CODES = {"EdDSA": -8, "ES256": -7}


def _keys(alg: str) -> tuple[bytes, bytes]:
    sk = ed25519.Ed25519PrivateKey.generate() if alg == "EdDSA" else ec.generate_private_key(
        ec.SECP256R1()
    )
    priv = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub


def _tree_entries(vector_id: str, statement_bytes: bytes) -> list[str]:
    """The deterministic 8-leaf log for one vector (see module docstring)."""
    entries = []
    for i in range(TREE_SIZE):
        if i == LEAF_INDEX:
            entries.append(hashlib.sha256(statement_bytes).hexdigest())
        else:
            filler = f"scitt-cose test vectors v1 :: {vector_id} :: filler leaf {i}".encode()
            entries.append(hashlib.sha256(filler).hexdigest())
    return entries


def _flip_byte(data: bytes, offset: int = 0) -> bytes:
    b = bytearray(data)
    b[offset] ^= 0x01
    return bytes(b)


def _mint(vector_id: str, alg: str) -> dict:
    """Mint one self-contained set of artifacts (keys, statement, log, receipt)."""
    issuer_priv, issuer_pub = _keys(alg)
    log_priv, log_pub = _keys(alg)
    payload = json.dumps(
        {
            "vector": vector_id,
            "note": "opaque payload — scitt-cose treats these bytes as opaque",
        },
        sort_keys=True,
    ).encode()
    statement = build_signed_statement(
        payload,
        alg=alg,
        private_key_pem=issuer_priv,
        issuer="https://test-vectors.scitt-cose.invalid",
        subject=f"urn:scitt-cose:test-vectors:v1:{vector_id}",
        content_type="application/json",
    )
    entries = _tree_entries(vector_id, statement)
    leaf = entries[LEAF_INDEX]
    receipt = build_receipt(
        leaf_entry_hex=leaf,
        leaf_index=LEAF_INDEX,
        tree_entries_hex=entries,
        alg=alg,
        log_private_key_pem=log_priv,
    )
    return {
        "alg": alg,
        "issuer_priv": issuer_priv,
        "issuer_pub": issuer_pub,
        "log_priv": log_priv,
        "log_pub": log_pub,
        "payload": payload,
        "statement": statement,
        "entries": entries,
        "leaf": leaf,
        "path": inclusion_proof(entries, LEAF_INDEX),
        "root": merkle_root(entries),
        "receipt": receipt,
    }


def _tamper_inclusion_path(receipt: bytes) -> bytes:
    """Flip one byte of the first audit-path node inside the (unprotected) vdp."""
    tag = cbor2.loads(receipt)
    protected, unprotected, payload, sig = list(tag.value)
    unprotected = {k: v for k, v in unprotected.items()}
    vdp = {k: v for k, v in unprotected[HDR_VDP].items()}
    tree_size, leaf_index, path = cbor2.loads(bytes(vdp[VDP_INCLUSION_PROOFS][0]))
    path = [bytes(p) for p in path]
    path[0] = _flip_byte(path[0])
    vdp[VDP_INCLUSION_PROOFS] = [cbor2.dumps([tree_size, leaf_index, path])]
    unprotected[HDR_VDP] = vdp
    return cbor2.dumps(cbor2.CBORTag(tag.tag, [protected, unprotected, payload, sig]))


def _tamper_signature(statement: bytes) -> bytes:
    """Flip the last byte of the COSE_Sign1 signature."""
    tag = cbor2.loads(statement)
    protected, unprotected, payload, sig = list(tag.value)
    sig = _flip_byte(bytes(sig), -1)
    return cbor2.dumps(cbor2.CBORTag(tag.tag, [protected, unprotected, payload, sig]))


def _mint_unsupported_vds_receipt(minted: dict) -> bytes:
    """A receipt that is structurally fine but pins vds=2 in the protected header.

    The proof and signature are otherwise honest (signed over the true root), so
    the ONLY conformant reason to reject is the unsupported verifiable data
    structure — which a verifier MUST read from the protected header.
    """
    inclusion_blob = cbor2.dumps(
        [TREE_SIZE, LEAF_INDEX, [bytes.fromhex(h) for h in minted["path"]]]
    )
    return sign_sign1(
        bytes.fromhex(minted["root"]),
        alg=minted["alg"],
        private_key_pem=minted["log_priv"],
        protected={HDR_VDS: 2},  # NOT RFC9162_SHA256
        unprotected={HDR_VDP: {VDP_INCLUSION_PROOFS: [inclusion_blob]}},
        detached=True,
    )


def _expected(vector_id: str, description: str, minted: dict, *, result: str,
              failure_code: str | None, statement_sig_valid: bool,
              receipt_valid: bool, receipt_vds: int = 1,
              inclusion_path: list[str] | None = None) -> dict:
    exp = {
        "description": description,
        "payload_sha256": hashlib.sha256(minted["payload"]).hexdigest(),
        # Every protected-header field a verifier needs, decoded, for BOTH
        # COSE_Sign1 envelopes in the vector.
        "protected_header": {
            "statement": {
                "alg": minted["alg"],
                "alg_code": ALG_CODES[minted["alg"]],
                "content_type": "application/json",
                "cwt_claims_label": 15,
                "issuer": "https://test-vectors.scitt-cose.invalid",
                "subject": f"urn:scitt-cose:test-vectors:v1:{vector_id}",
            },
            "receipt": {
                "alg": minted["alg"],
                "alg_code": ALG_CODES[minted["alg"]],
                "vds_label": 395,
                "vds": receipt_vds,
            },
        },
        "leaf_entry": minted["leaf"],
        "leaf_index": LEAF_INDEX,
        "tree_size": TREE_SIZE,
        "inclusion_path": inclusion_path if inclusion_path is not None else minted["path"],
        "reconstructed_root": minted["root"] if result == "VALID" else None,
        "statement_signature_valid": statement_sig_valid,
        "receipt_valid": receipt_valid,
        "result": result,
    }
    if failure_code:
        exp["failure_code"] = failure_code
    return exp


def _write_vector(dirname: str, minted: dict, statement: bytes, receipt: bytes,
                  expected: dict) -> None:
    d = OUT / VERSION / dirname
    d.mkdir(parents=True)
    (d / "statement.cose").write_bytes(statement)
    (d / "payload.bin").write_bytes(minted["payload"])
    (d / "receipt.cose").write_bytes(receipt)
    (d / "issuer-key.pub").write_bytes(minted["issuer_pub"])
    (d / "log-key.pub").write_bytes(minted["log_pub"])
    (d / "issuer-key.test-private").write_bytes(minted["issuer_priv"])
    (d / "log-key.test-private").write_bytes(minted["log_priv"])
    (d / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")


def main() -> int:
    if (OUT / VERSION).exists():
        print(f"refusing to overwrite published {OUT / VERSION} — versions are append-only")
        return 1

    manifest_vectors = []

    def register(vid: str, description: str, expected: dict) -> None:
        entry = {
            "id": vid,
            "dir": f"{VERSION}/{vid}",
            "description": description,
            "expected_result": expected["result"],
        }
        if "failure_code" in expected:
            entry["failure_code"] = expected["failure_code"]
        manifest_vectors.append(entry)

    # --- valid-eddsa / valid-es256: happy path ------------------------------
    for alg in ("EdDSA", "ES256"):
        vid = f"valid-{alg.lower()}"
        desc = f"Happy path: {alg} Signed Statement + RFC9162_SHA256 receipt; everything verifies."
        m = _mint(vid, alg)
        exp = _expected(vid, desc, m, result="VALID", failure_code=None,
                        statement_sig_valid=True, receipt_valid=True)
        _write_vector(vid, m, m["statement"], m["receipt"], exp)
        register(vid, desc, exp)

    # --- fail-tampered-path: one flipped byte in the inclusion path ---------
    vid = "fail-tampered-path"
    desc = ("Inclusion path with one flipped byte (first audit-path node). The "
            "reconstructed root no longer matches what the log signed; a verifier "
            "MUST reject. Statement is honest — the failure is receipt-only.")
    m = _mint(vid, "EdDSA")
    tampered_receipt = _tamper_inclusion_path(m["receipt"])
    tampered_path = [_flip_byte(bytes.fromhex(m["path"][0])).hex()] + m["path"][1:]
    exp = _expected(vid, desc, m, result="INVALID", failure_code="TAMPERED_INCLUSION_PATH",
                    statement_sig_valid=True, receipt_valid=False,
                    inclusion_path=tampered_path)
    _write_vector(vid, m, m["statement"], tampered_receipt, exp)
    register(vid, desc, exp)

    # --- fail-unsupported-vds: vds is not RFC9162_SHA256 --------------------
    vid = "fail-unsupported-vds"
    desc = ("Receipt whose protected vds (label 395) is 2, not 1 (RFC9162_SHA256). "
            "Proof and signature are otherwise honest, so the ONLY conformant "
            "rejection reason is the unsupported verifiable data structure — read "
            "from the protected header, never the unprotected one.")
    m = _mint(vid, "EdDSA")
    bad_vds_receipt = _mint_unsupported_vds_receipt(m)
    exp = _expected(vid, desc, m, result="INVALID", failure_code="UNSUPPORTED_VDS",
                    statement_sig_valid=True, receipt_valid=False, receipt_vds=2)
    _write_vector(vid, m, m["statement"], bad_vds_receipt, exp)
    register(vid, desc, exp)

    # --- fail-bad-statement-sig: statement signature invalid ----------------
    vid = "fail-bad-statement-sig"
    desc = ("Signed Statement whose signature byte was flipped. The receipt is "
            "minted over the digest of the TAMPERED bytes and verifies — isolating "
            "the failure to the statement signature alone.")
    alg = "EdDSA"
    issuer_priv, issuer_pub = _keys(alg)
    log_priv, log_pub = _keys(alg)
    payload = json.dumps({"vector": vid, "note": "opaque payload"}, sort_keys=True).encode()
    good = build_signed_statement(
        payload, alg=alg, private_key_pem=issuer_priv,
        issuer="https://test-vectors.scitt-cose.invalid",
        subject=f"urn:scitt-cose:test-vectors:v1:{vid}",
        content_type="application/json",
    )
    tampered_stmt = _tamper_signature(good)
    entries = _tree_entries(vid, tampered_stmt)  # log registered the tampered bytes
    m = {
        "alg": alg, "issuer_priv": issuer_priv, "issuer_pub": issuer_pub,
        "log_priv": log_priv, "log_pub": log_pub, "payload": payload,
        "entries": entries, "leaf": entries[LEAF_INDEX],
        "path": inclusion_proof(entries, LEAF_INDEX), "root": merkle_root(entries),
    }
    receipt = build_receipt(
        leaf_entry_hex=m["leaf"], leaf_index=LEAF_INDEX, tree_entries_hex=entries,
        alg=alg, log_private_key_pem=log_priv,
    )
    exp = _expected(vid, desc, m, result="INVALID", failure_code="BAD_STATEMENT_SIGNATURE",
                    statement_sig_valid=False, receipt_valid=True)
    # receipt_valid is true here, so the root IS reconstructable — document it.
    exp["reconstructed_root"] = m["root"]
    _write_vector(vid, m, tampered_stmt, receipt, exp)
    register(vid, desc, exp)

    # --- manifest ------------------------------------------------------------
    manifest = {
        "version": VERSION,
        "stability": "append-only",
        "leaf_entry_definition": (
            "SHA-256 digest of the complete Signed Statement (COSE_Sign1) bytes, hex-encoded"
        ),
        "tree_construction": (
            f"tree_size={TREE_SIZE}; statement digest at leaf_index={LEAF_INDEX}; "
            "filler leaf i = SHA-256('scitt-cose test vectors v1 :: <vector-id> :: "
            "filler leaf <i>'); leaves in index order; RFC 9162 SHA-256 tree"
        ),
        "vectors": manifest_vectors,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    # --- sanity: every vector must behave as expected before we commit ------
    failures = []
    for v in manifest_vectors:
        d = OUT / v["dir"]
        exp = json.loads((d / "expected.json").read_text())
        parsed = parse_signed_statement(
            (d / "statement.cose").read_bytes(),
            public_key_pem=(d / "issuer-key.pub").read_bytes(),
        )
        if parsed["signature_verified"] is not exp["statement_signature_valid"]:
            failures.append(f"{v['id']}: statement sig mismatch")
        res = verify_receipt(
            (d / "receipt.cose").read_bytes(),
            leaf_entry_hex=exp["leaf_entry"],
            log_public_key_pem=(d / "log-key.pub").read_bytes(),
        )
        if res.ok is not exp["receipt_valid"]:
            failures.append(f"{v['id']}: receipt mismatch ({res.errors})")
        if exp["receipt_valid"] and res.root != exp["reconstructed_root"]:
            failures.append(f"{v['id']}: root mismatch")
    if failures:
        print("GENERATION FAILED SELF-CHECK:", *failures, sep="\n  ")
        return 1
    print(f"minted {len(manifest_vectors)} vectors under {OUT / VERSION} — self-check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
