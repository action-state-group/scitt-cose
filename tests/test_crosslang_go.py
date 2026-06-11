# SPDX-License-Identifier: Apache-2.0
"""Cross-LANGUAGE conformance for the GENERIC scitt-cose library.

This is the credibility backbone. A COSE_Sign1 / Receipt that round-trips through
its own emitter can be internally consistent yet non-conformant — e.g. reading
CWT_Claims at the wrong integer label (the python-cwt ``CWT_CLAIMS`` enum bug,
``13`` vs the conformant ``15``). Agreement across two *independent
implementations in different languages* is the cure.

Here a clean-room **Go** stack (``tools/scitt-cose-go-verify`` on
``github.com/veraison/go-cose`` + ``github.com/fxamacker/cbor``, with a
clean-room RFC 9162 Merkle fold) independently verifies the bytes the **generic**
``scitt_cose`` Python library produces — Signed Statements *and* Receipts — and
agrees on accept/reject and on the reconstructed Merkle root.

The Go tool is PROFILE-OPAQUE: it knows nothing about any application profile.
This test therefore asserts only generic SCITT/COSE/CWT fields.

CI gate: by default this module SKIPS gracefully when ``go`` is missing or the
verifier can't be built (e.g. no module-proxy network). Set ``SCITT_REQUIRE_GO=1``
(CI does) to turn those skips into FAILURES — so the cross-language check can
never silently disappear from the credibility story.
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

from scitt_cose import build_receipt, build_signed_statement, merkle_root


def _go_tool_dir() -> Path:
    """Locate the Go verifier across layouts: env override, then the package's
    sibling (monorepo: tools/scitt-cose-go-verify), then a subdir of the package
    root (standalone repo: ./scitt-cose-go-verify)."""
    override = os.environ.get("SCITT_GO_VERIFIER_DIR")
    if override:
        return Path(override)
    pkg_root = Path(__file__).resolve().parents[1]
    for candidate in (pkg_root.parent / "scitt-cose-go-verify",
                      pkg_root / "scitt-cose-go-verify"):
        if candidate.is_dir():
            return candidate
    return pkg_root.parent / "scitt-cose-go-verify"  # default; build will skip/fail


_GO_TOOL_DIR = _go_tool_dir()
_REQUIRE_GO = os.environ.get("SCITT_REQUIRE_GO") == "1"


def _skip_or_fail(reason: str) -> None:
    """SKIP normally; FAIL when SCITT_REQUIRE_GO=1 (the cross-check must run)."""
    if _REQUIRE_GO:
        pytest.fail(f"SCITT_REQUIRE_GO=1 but cross-language check unavailable: {reason}")
    pytest.skip(reason)


def _pem(kind: str) -> tuple[bytes, bytes]:
    if kind == "EdDSA":
        sk = ed25519.Ed25519PrivateKey.generate()
    else:
        sk = ec.generate_private_key(ec.SECP256R1())
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


@pytest.fixture(scope="session")
def go_verifier(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Build the Go verifier once per session; SKIP/FAIL if Go is unavailable."""
    go = shutil.which("go")
    if go is None:
        _skip_or_fail("go is not on PATH")
    out = tmp_path_factory.mktemp("go-bin") / "scitt-cose-go-verify"
    try:
        proc = subprocess.run(
            [go, "build", "-o", str(out), "."],
            cwd=str(_GO_TOOL_DIR),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover - env
        _skip_or_fail(f"could not run `go build`: {exc}")
    if proc.returncode != 0:  # pragma: no cover - env
        _skip_or_fail(f"Go verifier failed to build (likely no module proxy):\n{proc.stderr}")
    return str(out)


def _run_go(binary: str, args: list[str]):
    proc = subprocess.run([binary, *args], capture_output=True, text=True, timeout=60)
    return proc, json.loads(proc.stdout)


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# --- Signed Statement: accept ----------------------------------------------


@pytest.mark.parametrize("alg", ["EdDSA", "ES256"])
def test_generic_statement_verifies_under_go_cose(alg, go_verifier, tmp_path):
    priv, pub = _pem(alg)
    stmt = build_signed_statement(
        b'{"opaque":"bytes"}',
        alg=alg,
        private_key_pem=priv,
        issuer="https://issuer.example",
        subject="urn:anything:goes",
        content_type="application/widget+json",
        extra_cwt_claims={"profile_thing": "abc"},
    )
    s = _write(tmp_path, "stmt.cose", stmt)
    k = _write(tmp_path, "pub.pem", pub)

    proc, report = _run_go(go_verifier, ["--statement", s, "--pubkey", k, "--alg", alg])

    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    assert report["valid"] is True, report
    # Cross-language agreement on the generic envelope fields.
    assert report["alg"] == alg
    assert report["iss"] == "https://issuer.example"
    assert report["sub"] == "urn:anything:goes"
    assert report["content_type"] == "application/widget+json"
    # Profile claims surface verbatim — the Go tool does not interpret them.
    assert report["string_claims"]["profile_thing"] == "abc"


# --- Signed Statement: reject tampered payload ------------------------------


def test_tampered_statement_rejected_by_go_cose(go_verifier, tmp_path):
    priv, pub = _pem("EdDSA")
    stmt = build_signed_statement(
        b"original payload",
        alg="EdDSA",
        private_key_pem=priv,
        issuer="i",
        subject="s",
        content_type="text/plain",
    )
    tag = cbor2.loads(stmt)
    v = list(tag.value)  # cbor2>=6 returns an immutable tuple — rebuild
    payload = bytearray(v[2])
    payload[0] ^= 0x01
    v[2] = bytes(payload)
    s = _write(tmp_path, "tampered.cose", cbor2.dumps(cbor2.CBORTag(tag.tag, v)))
    k = _write(tmp_path, "pub.pem", pub)

    proc, report = _run_go(go_verifier, ["--statement", s, "--pubkey", k, "--alg", "EdDSA"])

    assert proc.returncode != 0
    assert report["valid"] is False, report


# --- Receipt: accept + Merkle-root agreement --------------------------------


@pytest.mark.parametrize("alg", ["EdDSA", "ES256"])
def test_generic_receipt_verifies_under_go(alg, go_verifier, tmp_path):
    priv, pub = _pem(alg)
    entries = [bytes([i]).hex() for i in range(5)]
    receipt = build_receipt(
        leaf_entry_hex=entries[2],
        leaf_index=2,
        tree_entries_hex=entries,
        alg=alg,
        log_private_key_pem=priv,
    )
    r = _write(tmp_path, "r.cose", receipt)
    k = _write(tmp_path, "log.pem", pub)

    proc, report = _run_go(
        go_verifier,
        ["--receipt", r, "--log-pubkey", k, "--leaf-entry-hex", entries[2]],
    )

    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    rc = report["receipt"]
    assert rc["ok"] is True, report
    assert rc["tree_size"] == 5
    assert rc["leaf_index"] == 2
    # The Go tool reconstructs the root clean-room; it must equal Python's root.
    assert rc["root"] == merkle_root(entries)


# --- Receipt: reject wrong leaf ---------------------------------------------


def test_receipt_wrong_leaf_rejected_by_go(go_verifier, tmp_path):
    priv, pub = _pem("EdDSA")
    entries = [bytes([i]).hex() for i in range(5)]
    receipt = build_receipt(
        leaf_entry_hex=entries[2],
        leaf_index=2,
        tree_entries_hex=entries,
        alg="EdDSA",
        log_private_key_pem=priv,
    )
    r = _write(tmp_path, "r.cose", receipt)
    k = _write(tmp_path, "log.pem", pub)

    proc, report = _run_go(
        go_verifier,
        ["--receipt", r, "--log-pubkey", k, "--leaf-entry-hex", entries[3]],
    )

    assert proc.returncode != 0
    assert report["receipt"]["ok"] is False, report
