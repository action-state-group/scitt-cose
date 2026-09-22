# SPDX-License-Identifier: Apache-2.0
"""Cross-LANGUAGE conformance for COSE Receipt verification: RUST.

Mirrors ``test_crosslang_go.py``. A clean-room **Rust** stack
(``rust/scitt-cose``, on ``coset`` + ``ed25519-dalek``/``p256`` for signature
verification, with a clean-room RFC 9162 Merkle fold — see
``rust/scitt-cose/src/merkle.rs``) independently verifies COSE Receipts the
**generic** ``scitt_cose`` Python library produces, and agrees on
accept/reject, on the reconstructed Merkle root, and — the part this crate
adds beyond the Go tool — on the `iat`/`grade` protected-header labels and
their two derived booleans (`witness_time_established`,
`grade_cryptographically_bound`).

Receipt-only: the Rust crate never reads a Signed Statement (out of its
scope by design — see ``rust/scitt-cose/src/receipt.rs`` docs), so unlike
the Go cross-check this module only exercises the receipt path.

CI gate: by default this module SKIPS gracefully when ``cargo`` is missing or
the crate can't be built. Set ``SCITT_REQUIRE_RUST=1`` (CI does) to turn those
skips into FAILURES.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from scitt_cose import build_receipt, merkle_root
from scitt_cose.cose_sign1 import sign_sign1
from scitt_cose.receipt import HDR_VDP, HDR_VDS, VDP_INCLUSION_PROOFS
from scitt_cose.statement import HDR_CWT_CLAIMS

CWT_IAT = 6  # RFC 8392 §3.1.6 (not yet exported pending PR #44's merge)
HDR_GRADE = -65537


def _rust_crate_dir() -> Path:
    override = os.environ.get("SCITT_RUST_CRATE_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[1] / "rust" / "scitt-cose"


_RUST_CRATE_DIR = _rust_crate_dir()
_REQUIRE_RUST = os.environ.get("SCITT_REQUIRE_RUST") == "1"


def _skip_or_fail(reason: str) -> None:
    if _REQUIRE_RUST:
        pytest.fail(f"SCITT_REQUIRE_RUST=1 but cross-language check unavailable: {reason}")
    pytest.skip(reason)


def _pem(alg: str) -> tuple[bytes, bytes]:
    sk = ed25519.Ed25519PrivateKey.generate() if alg == "EdDSA" else ec.generate_private_key(ec.SECP256R1())
    priv = sk.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


def _build_receipt_with_claims(*, leaf_entry_hex, leaf_index, tree_entries_hex, alg,
                                log_private_key_pem, iat=None, grade=None) -> bytes:
    """Same construction `scripts/generate_receipt_grade_vectors.py` uses --
    builds the protected header by hand so tests don't depend on the
    not-yet-merged `build_receipt(iat=, grade=)` kwargs (PR #44)."""
    from scitt_cose import inclusion_proof

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


@pytest.fixture(scope="session")
def rust_verifier(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Build the Rust verifier binary once per session; SKIP/FAIL if cargo is unavailable."""
    cargo = shutil.which("cargo")
    if cargo is None:
        _skip_or_fail("cargo is not on PATH")
    out_dir = tmp_path_factory.mktemp("rust-target")
    try:
        proc = subprocess.run(
            # No --offline: CI has no pre-warmed cargo cache, so an offline build
            # fails to resolve deps (e.g. coset). The dedicated rust job builds
            # --locked; here we let cargo fetch on demand so the cross-lang gate runs.
            [cargo, "build", "--locked", "--target-dir", str(out_dir), "--bin", "scitt-cose-rust-verify"],
            cwd=str(_RUST_CRATE_DIR),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover - env
        _skip_or_fail(f"could not run `cargo build`: {exc}")
    if proc.returncode != 0:  # pragma: no cover - env
        _skip_or_fail(f"Rust verifier failed to build:\n{proc.stderr}")
    binary = out_dir / "debug" / "scitt-cose-rust-verify"
    if not binary.is_file():  # pragma: no cover - env
        _skip_or_fail(f"built but binary not found at {binary}")
    return str(binary)


def _run_rust(binary: str, receipt_path: str, pubkey_path: str, leaf_entry_hex: str):
    proc = subprocess.run(
        [binary, "--receipt", receipt_path, "--log-pubkey", pubkey_path, "--leaf-entry-hex", leaf_entry_hex],
        capture_output=True, text=True, timeout=60,
    )
    return proc, json.loads(proc.stdout)


def _write(tmp_path: Path, name: str, data) -> str:
    p = tmp_path / name
    if isinstance(data, str):
        p.write_text(data)
    else:
        p.write_bytes(data)
    return str(p)


@pytest.mark.parametrize("alg", ["EdDSA", "ES256"])
def test_receipt_verifies_under_rust(alg, rust_verifier, tmp_path):
    priv, pub = _pem(alg)
    entries = [bytes([i]).hex() for i in range(5)]
    receipt = build_receipt(
        leaf_entry_hex=entries[2], leaf_index=2, tree_entries_hex=entries,
        alg=alg, log_private_key_pem=priv,
    )
    r = _write(tmp_path, "r.cose", receipt)
    k = _write(tmp_path, "log.pem", pub)

    proc, report = _run_rust(rust_verifier, r, k, entries[2])

    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert report["ok"] is True, report
    assert report["tree_size"] == 5
    assert report["leaf_index"] == 2
    assert report["root"] == merkle_root(entries)
    assert report["iat"] is None
    assert report["grade"] is None
    assert report["witness_time_established"] is False
    assert report["grade_cryptographically_bound"] is False


def test_receipt_wrong_leaf_rejected_by_rust(rust_verifier, tmp_path):
    priv, pub = _pem("EdDSA")
    entries = [bytes([i]).hex() for i in range(5)]
    receipt = build_receipt(
        leaf_entry_hex=entries[2], leaf_index=2, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv,
    )
    r = _write(tmp_path, "r.cose", receipt)
    k = _write(tmp_path, "log.pem", pub)

    proc, report = _run_rust(rust_verifier, r, k, entries[3])

    assert proc.returncode != 0
    assert report["ok"] is False, report


def test_iat_and_grade_agree_with_python(rust_verifier, tmp_path):
    """The exact cross-check the acceptance criteria ask for: mint a receipt
    with both labels, verify it with the PYTHON library and the RUST binary,
    and assert they agree on every surfaced field -- not just ok/not-ok."""
    from scitt_cose.receipt import verify_receipt as py_verify_receipt

    priv, pub = _pem("EdDSA")
    entries = [bytes([i]).hex() for i in range(6)]
    receipt = _build_receipt_with_claims(
        leaf_entry_hex=entries[3], leaf_index=3, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv, iat=1700001000, grade="mmr-verified",
    )
    r = _write(tmp_path, "r.cose", receipt)
    k = _write(tmp_path, "log.pem", pub)

    py_res = py_verify_receipt(receipt, leaf_entry_hex=entries[3], log_public_key_pem=pub)
    assert py_res.ok, py_res.errors
    assert py_res.iat == 1700001000
    assert py_res.protected_header_ext.get(HDR_GRADE) == "mmr-verified"

    proc, rust_report = _run_rust(rust_verifier, r, k, entries[3])
    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert rust_report["ok"] is True
    assert rust_report["root"] == py_res.root
    assert rust_report["tree_size"] == py_res.tree_size
    assert rust_report["leaf_index"] == py_res.leaf_index
    assert rust_report["iat"] == py_res.iat
    assert rust_report["grade"] == py_res.protected_header_ext.get(HDR_GRADE)
    assert rust_report["witness_time_established"] is True
    assert rust_report["grade_cryptographically_bound"] is True


def test_tampered_iat_rejected_by_both_python_and_rust(rust_verifier, tmp_path):
    from scitt_cose.receipt import verify_receipt as py_verify_receipt

    priv, pub = _pem("EdDSA")
    entries = [bytes([i]).hex() for i in range(4)]
    receipt = _build_receipt_with_claims(
        leaf_entry_hex=entries[1], leaf_index=1, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv, iat=1700000000,
    )
    tag = cbor2.loads(receipt)
    protected_bstr, unprotected, payload, sig = tag.value
    protected = dict(cbor2.loads(protected_bstr))
    claims = dict(protected[HDR_CWT_CLAIMS])
    claims[CWT_IAT] = claims[CWT_IAT] + 1
    protected[HDR_CWT_CLAIMS] = claims
    tampered = cbor2.dumps(cbor2.CBORTag(tag.tag, [cbor2.dumps(protected), unprotected, payload, sig]))

    py_res = py_verify_receipt(tampered, leaf_entry_hex=entries[1], log_public_key_pem=pub)
    assert not py_res.ok

    r = _write(tmp_path, "r.cose", tampered)
    k = _write(tmp_path, "log.pem", pub)
    proc, rust_report = _run_rust(rust_verifier, r, k, entries[1])
    assert proc.returncode != 0
    assert rust_report["ok"] is False
    assert rust_report["witness_time_established"] is False
