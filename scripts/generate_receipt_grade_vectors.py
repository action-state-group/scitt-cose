#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME generator for the receipt-v1 iat/grade test-vector set.

This script minted the bytes committed under ``test-vectors/receipt-v1/``. It
is kept for provenance and for building FUTURE versions — it must NOT be
re-run over a published version: receipt-v1 is append-only, and regenerating
would produce new keys and new bytes, silently breaking every implementation
that pinned the published set. The script refuses to overwrite an existing
version directory for exactly that reason.

Scope: RECEIPT-ONLY vectors (no Signed Statement) exercising the two protected
labels a receipt-only, profile-opaque verifier reads beyond the base RFC 9162
proof:

* ``iat`` -- CWT Claims (protected header label 15, RFC 9597) claim 6
  (RFC 8392 §3.1.6): the witness-observed registration time.
* ``grade`` -- private-use protected-header label ``-65537``: a witness-issued
  qualitative grade string.

Both labels are placed directly with :func:`scitt_cose.cose_sign1.sign_sign1`
(NOT the not-yet-merged ``build_receipt(iat=, grade=)`` kwargs from open PR
action-state-group/scitt-cose#44) -- this script constructs the exact same
wire shape PR #44 documents (and which the independent TRACE registry
consumer, ``trace_registry``'s ``verify_witness_receipt.py``, already reads),
without depending on that PR merging first. Current ``main``'s
``scitt_cose.receipt.verify_receipt`` already reads ``iat`` (0.3.0) and
surfaces ``-65537`` generically via ``protected_header_ext`` -- both are used
below for the self-check.

One vector (``trace-sept7-witness``) is not synthetic: it is the REAL COSE
Receipt bytes from the Action State Group's live TRACE-registry witness,
captured 2026-09-07 and already published as public evidence at
``agentrust-io/trace-registry``'s ``docs/evidence/witness-2026-09-07/``. It
carries neither label (pre-dates both), so it is the canonical
"both booleans permanently false" fixture -- a real receipt, not a
constructed one.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import TypedDict

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scitt_cose import inclusion_proof, merkle_root  # noqa: E402
from scitt_cose.cose_sign1 import sign_sign1  # noqa: E402
from scitt_cose.receipt import HDR_VDP, HDR_VDS, VDP_INCLUSION_PROOFS, verify_receipt  # noqa: E402
from scitt_cose.statement import HDR_CWT_CLAIMS  # noqa: E402

# RFC 8392 §3.1.6 "iat" claim number. Not yet exported by scitt_cose.statement
# on this branch's base (open PR action-state-group/scitt-cose#44 adds it) --
# defined locally so this generator does not depend on that PR merging first.
CWT_IAT = 6


class VectorExpected(TypedDict, total=False):
    """Exact shape of one vector's ``expected.json`` -- see
    ``test-vectors/receipt-v1/README.md``'s field table."""

    description: str
    alg: str
    leaf_entry_hex: str
    tree_size: int
    leaf_index: int
    ok: bool
    root: str | None
    iat: int | None
    grade: str | None
    witness_time_established: bool
    grade_cryptographically_bound: bool
    failure_contains: str
    provenance: str


VERSION = "receipt-v1"
OUT = REPO / "test-vectors"
HDR_GRADE = -65537  # private-use, see module docstring; matches PR #44 exactly.

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


def _entries(n: int) -> list[str]:
    return [bytes([i]).hex() for i in range(n)]


def _build_receipt(
    *, leaf_entry_hex: str, leaf_index: int, tree_entries_hex: list[str],
    alg: str, log_private_key_pem: bytes,
    iat: int | None = None, grade: str | None = None,
) -> bytes:
    """Same construction as ``scitt_cose.receipt.build_receipt``, but with the
    protected header built by hand so ``iat``/``grade`` can be set without
    depending on the unmerged PR #44 kwargs -- see module docstring."""
    root_hex = merkle_root(tree_entries_hex)
    audit_path = inclusion_proof(tree_entries_hex, leaf_index)
    inclusion_blob = cbor2.dumps(
        [len(tree_entries_hex), leaf_index, [bytes.fromhex(h) for h in audit_path]]
    )
    protected = {HDR_VDS: 1}
    if iat is not None:
        protected[HDR_CWT_CLAIMS] = {CWT_IAT: iat}
    if grade is not None:
        protected[HDR_GRADE] = grade
    unprotected = {HDR_VDP: {VDP_INCLUSION_PROOFS: [inclusion_blob]}}
    return sign_sign1(
        bytes.fromhex(root_hex), alg=alg, private_key_pem=log_private_key_pem,
        protected=protected, unprotected=unprotected, detached=True,
    )


def _tamper_protected_field(receipt: bytes, label: int, new_value: int | str) -> bytes:
    """Flip one protected-header value AFTER signing (never re-signs) -- the
    exact shape of PR #44's own `test_tampered_iat_fails_signature` /
    `test_tampered_grade_fails_signature`."""
    tag = cbor2.loads(receipt)
    protected_bstr, unprotected, payload, sig = tag.value
    protected = dict(cbor2.loads(protected_bstr))
    if label == HDR_CWT_CLAIMS:
        claims = dict(protected[HDR_CWT_CLAIMS])
        claims[CWT_IAT] = new_value
        protected[HDR_CWT_CLAIMS] = claims
    else:
        protected[label] = new_value
    return cbor2.dumps(
        cbor2.CBORTag(tag.tag, [cbor2.dumps(protected), unprotected, payload, sig])
    )


def _write_vector(vid: str, *, description: str, alg: str, leaf_entry_hex: str,
                   tree_size: int, leaf_index: int, receipt: bytes, log_pub: bytes,
                   expect_ok: bool, expect_iat: int | None, expect_grade: str | None,
                   expect_witness_time: bool, expect_grade_bound: bool,
                   expect_root: str | None, failure_contains: str | None = None,
                   provenance: str | None = None) -> VectorExpected:
    d = OUT / VERSION / vid
    d.mkdir(parents=True)
    (d / "receipt.cose").write_bytes(receipt)
    (d / "log-key.pub").write_bytes(log_pub)
    expected = {
        "description": description,
        "alg": alg,
        "leaf_entry_hex": leaf_entry_hex,
        "tree_size": tree_size,
        "leaf_index": leaf_index,
        "ok": expect_ok,
        "root": expect_root,
        "iat": expect_iat,
        "grade": expect_grade,
        "witness_time_established": expect_witness_time,
        "grade_cryptographically_bound": expect_grade_bound,
    }
    if failure_contains:
        expected["failure_contains"] = failure_contains
    if provenance:
        expected["provenance"] = provenance
    (d / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    return expected


def _self_check(vid: str, expected: VectorExpected) -> list[str]:
    d = OUT / VERSION / vid
    receipt = (d / "receipt.cose").read_bytes()
    log_pub = (d / "log-key.pub").read_bytes()
    res = verify_receipt(receipt, leaf_entry_hex=expected["leaf_entry_hex"], log_public_key_pem=log_pub)
    mismatches = []
    if res.ok is not expected["ok"]:
        mismatches.append(f"ok={res.ok} != expected {expected['ok']} (errors: {res.errors})")
    if expected["ok"]:
        if res.root != expected["root"]:
            mismatches.append(f"root={res.root} != expected {expected['root']}")
        if res.iat != expected["iat"]:
            mismatches.append(f"iat={res.iat} != expected {expected['iat']}")
        grade = res.protected_header_ext.get(HDR_GRADE)
        if grade != expected["grade"]:
            mismatches.append(f"grade={grade!r} != expected {expected['grade']!r}")
        witness_time = res.ok and res.iat is not None
        grade_bound = res.ok and grade is not None
        if witness_time != expected["witness_time_established"]:
            mismatches.append(f"witness_time_established={witness_time} != expected {expected['witness_time_established']}")
        if grade_bound != expected["grade_cryptographically_bound"]:
            mismatches.append(f"grade_cryptographically_bound={grade_bound} != expected {expected['grade_cryptographically_bound']}")
    elif expected.get("failure_contains"):
        if not any(expected["failure_contains"] in e for e in res.errors):
            mismatches.append(f"errors {res.errors} do not contain {expected['failure_contains']!r}")
    return mismatches


def main() -> int:
    if (OUT / VERSION).exists():
        print(f"refusing to overwrite published {OUT / VERSION} -- versions are append-only")
        return 1

    manifest_vectors = []
    all_expected: dict[str, VectorExpected] = {}

    def register(vid: str, expected: VectorExpected) -> None:
        manifest_vectors.append({"id": vid, "dir": f"{VERSION}/{vid}", "ok": expected["ok"]})
        all_expected[vid] = expected

    # --- trace-sept7-witness: REAL captured receipt, pre-dates iat/grade ----
    b64 = (
        "0oRHogEnGQGLAaEZAYyhIIFYsoMZA6kZA6iFWCAz1ZVi9KJwkiudCjwJfEVsa5yXHuYHIehF0hXWa0bUv1ggzP7HMXobD8c5"
        "JCJPVUckNJUeqFrwuAvZiPODAJPum5BYIIuvRhzB4KYVf0018WqWKuPXmID52ajbJ6W5F2R5WV+kWCDW8Y3hgjCBWMYOTbPE"
        "ChOPfhcLuYHcNZZgs3cbLaZHK1ggThrU6rDIZVPc96uBoMn92tBWqrEArQFOcIp8NBUAp+X2WEBFc7or7nsRjLF9DFd0Rc7N"
        "ENYgPxw08dtzh8dgaUcOUtMXgBMpk+1QN46VeFyNzYmXrLF1aYNaqQ3tMn4cH7AK"
    )
    receipt = base64.b64decode(b64)
    witness_key_hex = "39bb654c9dc0afe1c0edef0deffaa69099b8518836c9ba26e0491535840f96b5"
    log_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(witness_key_hex)).public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    leaf_entry_hex = "dee1a92dad155b56f99cf2284e166e3b6b935528e6d27dec8a4f67bbed6dfab6"
    exp = _write_vector(
        "trace-sept7-witness",
        description=(
            "REAL COSE Receipt from the Action State Group TRACE-registry witness, captured "
            "2026-09-07 (agentrust-io/trace-registry docs/evidence/witness-2026-09-07/). Pre-dates "
            "both iat and grade: neither label is present, so both limits are false PERMANENTLY for "
            "this exact receipt, not pending a witness upgrade (see that packet's README)."
        ),
        alg="EdDSA", leaf_entry_hex=leaf_entry_hex, tree_size=937, leaf_index=936,
        receipt=receipt, log_pub=log_pub, expect_ok=True,
        expect_iat=None, expect_grade=None,
        expect_witness_time=False, expect_grade_bound=False,
        expect_root="f8ee69f33629abc413a9b5530f9166230c8efd3b29f052216f22fb2412e1ef91",
        provenance="agentrust-io/trace-registry docs/evidence/witness-2026-09-07/witness-post.json",
    )
    register("trace-sept7-witness", exp)

    # --- synthetic-eddsa-iat-grade: both labels present, both true ----------
    priv, pub = _keys("EdDSA")
    es = _entries(5)
    receipt = _build_receipt(
        leaf_entry_hex=es[2], leaf_index=2, tree_entries_hex=es, alg="EdDSA",
        log_private_key_pem=priv, iat=1700000000, grade="mmr-verified",
    )
    exp = _write_vector(
        "synthetic-eddsa-iat-grade",
        description="Synthetic EdDSA receipt with both iat and grade signed into the protected header.",
        alg="EdDSA", leaf_entry_hex=es[2], tree_size=5, leaf_index=2,
        receipt=receipt, log_pub=pub, expect_ok=True,
        expect_iat=1700000000, expect_grade="mmr-verified",
        expect_witness_time=True, expect_grade_bound=True,
        expect_root=merkle_root(es),
    )
    register("synthetic-eddsa-iat-grade", exp)

    # --- synthetic-es256-iat-grade: alg diversity, both true ----------------
    priv, pub = _keys("ES256")
    es = _entries(6)
    receipt = _build_receipt(
        leaf_entry_hex=es[3], leaf_index=3, tree_entries_hex=es, alg="ES256",
        log_private_key_pem=priv, iat=1700000500, grade="countersigned-observed",
    )
    exp = _write_vector(
        "synthetic-es256-iat-grade",
        description="Synthetic ES256 receipt with both iat and grade signed into the protected header.",
        alg="ES256", leaf_entry_hex=es[3], tree_size=6, leaf_index=3,
        receipt=receipt, log_pub=pub, expect_ok=True,
        expect_iat=1700000500, expect_grade="countersigned-observed",
        expect_witness_time=True, expect_grade_bound=True,
        expect_root=merkle_root(es),
    )
    register("synthetic-es256-iat-grade", exp)

    # --- synthetic-eddsa-iat-only: iat present, grade absent ----------------
    priv, pub = _keys("EdDSA")
    es = _entries(4)
    receipt = _build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA",
        log_private_key_pem=priv, iat=1700000900,
    )
    exp = _write_vector(
        "synthetic-eddsa-iat-only",
        description="Synthetic EdDSA receipt with iat signed but no grade label -- witness_time_established "
                     "true, grade_cryptographically_bound false, independently (never coupled).",
        alg="EdDSA", leaf_entry_hex=es[1], tree_size=4, leaf_index=1,
        receipt=receipt, log_pub=pub, expect_ok=True,
        expect_iat=1700000900, expect_grade=None,
        expect_witness_time=True, expect_grade_bound=False,
        expect_root=merkle_root(es),
    )
    register("synthetic-eddsa-iat-only", exp)

    # --- fail-tampered-iat: iat altered post-signature ----------------------
    priv, pub = _keys("EdDSA")
    es = _entries(4)
    good_receipt = _build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA",
        log_private_key_pem=priv, iat=1700000000,
    )
    tampered = _tamper_protected_field(good_receipt, HDR_CWT_CLAIMS, 1700000001)
    exp = _write_vector(
        "fail-tampered-iat",
        description="iat altered in the PROTECTED header after signing (not re-signed) -- proves iat is "
                     "actually covered by the signature, not just carried alongside it. Must fail signature.",
        alg="EdDSA", leaf_entry_hex=es[1], tree_size=4, leaf_index=1,
        receipt=tampered, log_pub=pub, expect_ok=False,
        expect_iat=None, expect_grade=None, expect_witness_time=False, expect_grade_bound=False,
        expect_root=None, failure_contains="signature",
    )
    register("fail-tampered-iat", exp)

    # --- fail-tampered-grade: grade altered post-signature ------------------
    priv, pub = _keys("EdDSA")
    es = _entries(4)
    good_receipt = _build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es, alg="EdDSA",
        log_private_key_pem=priv, grade="countersigned-observed",
    )
    tampered = _tamper_protected_field(good_receipt, HDR_GRADE, "mmr-verified")
    exp = _write_vector(
        "fail-tampered-grade",
        description="grade altered in the PROTECTED header after signing (not re-signed) -- same proof as "
                     "fail-tampered-iat, for grade. Must fail signature.",
        alg="EdDSA", leaf_entry_hex=es[1], tree_size=4, leaf_index=1,
        receipt=tampered, log_pub=pub, expect_ok=False,
        expect_iat=None, expect_grade=None, expect_witness_time=False, expect_grade_bound=False,
        expect_root=None, failure_contains="signature",
    )
    register("fail-tampered-grade", exp)

    # --- manifest + SHA256SUMS ----------------------------------------------
    manifest = {
        "version": VERSION,
        "stability": "append-only",
        "scope": (
            "Receipt-only vectors (no Signed Statement) exercising the iat (CWT claims label 15, "
            "claim 6) and private-use grade label -65537 in the receipt's PROTECTED header. See "
            "rust/scitt-cose (the receipt-only Rust verifier) and the TRACE registry's "
            "verify_witness_receipt.py, which independently converged on the same two labels."
        ),
        "vectors": manifest_vectors,
    }
    (OUT / VERSION / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    sums_path = OUT / VERSION / "SHA256SUMS"
    lines = []
    for v in manifest_vectors:
        for f in sorted((OUT / v["dir"]).iterdir()):
            digest = hashlib.sha256(f.read_bytes()).hexdigest()
            lines.append(f"{digest}  {f.relative_to(OUT / VERSION)}")
    sums_path.write_text("\n".join(lines) + "\n")

    # --- self-check: every freshly minted vector must verify as expected ----
    failures = []
    for vid, exp in all_expected.items():
        failures.extend(f"{vid}: {m}" for m in _self_check(vid, exp))
    if failures:
        print("GENERATION FAILED SELF-CHECK:", *failures, sep="\n  ")
        return 1
    print(f"minted {len(manifest_vectors)} vectors under {OUT / VERSION} -- self-check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
