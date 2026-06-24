# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Action State Group, Inc.
"""CCF interop spike: anchor one Signed Statement to two independent TS instances,
verify both receipts.

**Vienna proof (our half):** the same SCITT Signed Statement can be registered
with two independent Transparency Services and both receipts verify via the same
``verify_receipt()`` call.  The Signed Statement is byte-identical in both logs.
Only the TS key differs; the statement is VDS-agnostic.

Two parts
---------
**Local** (always runs, no network)
    Two :class:`LocalTestTS` instances (``our-log`` and ``peer-log``), each with its
    own Ed25519 key pair.  Both are plain ``RFC9162_SHA256`` logs — neither is a
    real CCF node.  They model *two independent TSes of the same VDS profile* to
    prove statement portability; only ``test_ccf_sandbox_live`` (integration) hits
    CCF.  Three tests:

    * ``test_dual_receipt_same_statement`` — statement portability across same-VDS logs.
    * ``test_cross_receipt_reject`` — sanity: receipts are key-specific.
    * ``test_leaf_hash_determinism`` — ``leaf_hash(entry_hex)`` is a pure function of
      the statement bytes, independent of which TS registered it.

**Integration** (``pytest -m integration``, needs network)
    :class:`CcfSandboxClient` submits the Signed Statement to ``SCITT_CCF_URL``
    (default ``https://scitt.ccf.dev``), polls for the operation, fetches the
    Receipt, resolves CCF's public key from ``/.well-known/did.json``, and verifies
    via ``verify_receipt``.  Skips gracefully when unreachable.

    **Status (2026-06-23):** ``scitt.ccf.dev`` does not resolve from the current
    network.  The integration test is **structurally correct** — it implements the
    CCF SCITT REST API (``POST /app/entries`` → poll → ``GET .../receipt``) and the
    receipt is verified with our ``verify_receipt`` exactly as in production.  This
    is our runnable half; live execution is gated on CCF sandbox access.  On a green
    run, upgrade the wording in ``agent-action-capsule`` README to "verified against
    scitt.ccf.dev on <date>."

Wording note
    Until ``test_ccf_sandbox_live`` passes on a real CCF endpoint, the correct
    claim is: *CCF issues ``vds=1`` (RFC9162_SHA256) receipts per the CCF SCITT
    profile; our verifier is **expected to** handle them when CCF's TS key is
    supplied* — not "already handles CCF receipts today, no change."

Draft tracking
    RFC9162_SHA256 (vds=1) per draft-ietf-cose-merkle-tree-proofs.
    CCF REST API per scitt-ccf-ledger main (2026-06).
"""
from __future__ import annotations

import hashlib
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scitt_cose import build_receipt, build_signed_statement, leaf_hash, verify_receipt

# ---------------------------------------------------------------------------
# Shared payload — a minimal placeholder capsule in AAC content-type
# ---------------------------------------------------------------------------

_CONTENT_TYPE = "application/agent-action-capsule+json"
_ISSUER = "acme-co"
_SUBJECT = "ccf-interop-spike-001"


def _minimal_capsule_payload() -> bytes:
    """Return a tiny JSON payload in the AAC content-type.

    In production this would come from ``capsule_emit.emit()`` (the producer
    library).  Here we inline a minimal dict so the test has no extra dependency —
    the spike is about the SCITT transport layer, not the capsule schema.
    """
    return json.dumps(
        {
            "capsule_id": _SUBJECT,
            "action_type": "write_order",
            "operator": _ISSUER,
            "verdict": "executed",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------


def _ed25519_pair() -> tuple[bytes, bytes]:
    """Generate a throwaway Ed25519 key pair; return (private_pem, public_pem)."""
    sk = ed25519.Ed25519PrivateKey.generate()
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


def _build_signed_statement(issuer_priv_pem: bytes) -> bytes:
    """Build a SCITT Signed Statement (COSE_Sign1) over the placeholder payload."""
    return build_signed_statement(
        _minimal_capsule_payload(),
        alg="EdDSA",
        private_key_pem=issuer_priv_pem,
        issuer=_ISSUER,
        subject=_SUBJECT,
        content_type=_CONTENT_TYPE,
    )


# ---------------------------------------------------------------------------
# Local test Transparency Service — no network, always runnable
# ---------------------------------------------------------------------------


class LocalTestTS:
    """Minimal in-memory TS: registers statements, mints RFC9162_SHA256 receipts.

    Models what any conformant SCITT TS does — maintain an append-only log,
    issue an inclusion receipt for each new entry.  Two instances with distinct
    key pairs stand in for two independent TSes (ours and a CCF-style peer).
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self._priv, self._pub = _ed25519_pair()
        self._log: list[str] = []  # ordered hex SHA-256 of each statement

    @property
    def public_key_pem(self) -> bytes:
        return self._pub

    def register(self, signed_statement: bytes) -> bytes:
        """Append the statement to the log and return a COSE Receipt."""
        entry_hex = hashlib.sha256(signed_statement).hexdigest()
        self._log.append(entry_hex)
        idx = len(self._log) - 1
        return build_receipt(
            leaf_entry_hex=entry_hex,
            leaf_index=idx,
            tree_entries_hex=list(self._log),
            alg="EdDSA",
            log_private_key_pem=self._priv,
            detached=True,
        )


# ---------------------------------------------------------------------------
# Local tests — always run, no network
# ---------------------------------------------------------------------------


def test_dual_receipt_same_statement() -> None:
    """Statement portability: one Signed Statement, two RFC9162_SHA256 logs, both receipts verify.

    This proves the *statement is VDS-agnostic*: ``our-log`` and ``peer-log`` are
    two completely independent in-memory logs, each with a distinct Ed25519 key pair,
    both using RFC9162_SHA256 (vds=1).  Neither is a CCF node — they model any two
    independent TSes of the same profile.  The actual CCF interop proof lives in
    ``test_ccf_sandbox_live`` (integration, requires network).

    Both receipts verify via the same ``verify_receipt`` call.  The leaf-entry hex
    (SHA-256 of the statement bytes) is identical in both logs because it depends
    only on the statement bytes, not on the TS.
    """
    our_ts = LocalTestTS("our-log")
    peer_ts = LocalTestTS("peer-log")

    issuer_priv, _ = _ed25519_pair()
    signed_statement = _build_signed_statement(issuer_priv)

    # Both independent logs register the same statement bytes.
    entry_hex = hashlib.sha256(signed_statement).hexdigest()
    receipt_a = our_ts.register(signed_statement)
    receipt_b = peer_ts.register(signed_statement)

    # Both receipts must verify.
    result_a = verify_receipt(
        receipt_a,
        leaf_entry_hex=entry_hex,
        log_public_key_pem=our_ts.public_key_pem,
    )
    assert result_a.ok, f"our-log receipt failed: {result_a.errors}"

    result_b = verify_receipt(
        receipt_b,
        leaf_entry_hex=entry_hex,
        log_public_key_pem=peer_ts.public_key_pem,
    )
    assert result_b.ok, f"peer-log receipt failed: {result_b.errors}"

    # With one entry each, both single-entry logs hash to the same RFC6962
    # root (leaf hash is content-only).  The TSes are distinguished by their
    # SIGNING KEYS — confirmed by test_cross_receipt_reject.
    assert result_a.root == result_b.root  # same statement → same leaf → same root
    assert result_a.root is not None
    # The receipt bytes differ because each is signed by a different TS key.
    assert receipt_a != receipt_b


def test_cross_receipt_reject() -> None:
    """A receipt from one TS must NOT verify against the other TS's public key."""
    our_ts = LocalTestTS("our-log")
    peer_ts = LocalTestTS("peer-log")

    issuer_priv, _ = _ed25519_pair()
    signed_statement = _build_signed_statement(issuer_priv)
    entry_hex = hashlib.sha256(signed_statement).hexdigest()

    receipt_a = our_ts.register(signed_statement)
    receipt_b = peer_ts.register(signed_statement)

    wrong_a = verify_receipt(
        receipt_a,
        leaf_entry_hex=entry_hex,
        log_public_key_pem=peer_ts.public_key_pem,
    )
    assert not wrong_a.ok, "our receipt should NOT verify against peer_ts key"

    wrong_b = verify_receipt(
        receipt_b,
        leaf_entry_hex=entry_hex,
        log_public_key_pem=our_ts.public_key_pem,
    )
    assert not wrong_b.ok, "peer receipt should NOT verify against our_ts key"


def test_leaf_hash_determinism() -> None:
    """leaf_hash(entry_hex) is a pure function of the statement bytes.

    The leaf hash is the RFC 6962 node value SHA-256(0x00 || SHA-256(statement)).
    It must be the same regardless of which TS registers the statement —
    confirming the statement is the invariant across logs.
    """
    issuer_priv, _ = _ed25519_pair()
    signed_statement = _build_signed_statement(issuer_priv)
    entry_hex = hashlib.sha256(signed_statement).hexdigest()

    lh = leaf_hash(entry_hex)
    assert len(lh) == 64  # 32 bytes → 64 hex chars
    # Calling twice with the same input must give the same result.
    assert leaf_hash(entry_hex) == lh
    # Different statement bytes → different leaf hash.
    other_priv, _ = _ed25519_pair()
    other_hex = hashlib.sha256(_build_signed_statement(other_priv)).hexdigest()
    assert leaf_hash(other_hex) != lh


# ---------------------------------------------------------------------------
# CCF Sandbox HTTP client — integration only
# ---------------------------------------------------------------------------


class CcfSandboxClient:
    """Minimal HTTP client for the CCF SCITT REST API.

    CCF SCITT API (scitt-ccf-ledger main, 2026-06)::

        POST   /app/entries           → 202 {"operationId": "..."}
        GET    /app/operations/{id}   → {"status": "running"|"succeeded", "entryId": "..."}
        GET    /app/entries/{id}/receipt  → COSE Receipt bytes
        GET    /.well-known/did.json  → DID document with the TS's public key

    Pass ``verify_tls=False`` for ephemeral CCF dev sandboxes that use a
    self-signed certificate.
    """

    def __init__(
        self,
        base_url: str = "https://scitt.ccf.dev",
        *,
        verify_tls: bool = True,
        poll_interval: float = 1.0,
        timeout: float = 30.0,
    ) -> None:
        import requests  # noqa: PLC0415 — optional dep

        self._s = requests.Session()
        self._s.verify = verify_tls
        self._base = base_url.rstrip("/")
        self._poll = poll_interval
        self._timeout = timeout

    def submit(self, signed_statement: bytes) -> bytes:
        """Submit a Signed Statement and return the COSE Receipt bytes.

        Blocks (with polling) until the CCF operation completes.
        Raises ``RuntimeError`` on CCF API errors.
        """
        r = self._s.post(
            f"{self._base}/app/entries",
            data=signed_statement,
            headers={"Content-Type": "application/cose"},
            timeout=self._timeout,
        )
        if r.status_code not in (200, 201, 202):
            raise RuntimeError(f"CCF submit failed {r.status_code}: {r.text[:200]}")
        body = r.json()
        if "entryId" in body:
            entry_id = body["entryId"]
        elif "operationId" in body:
            entry_id = self._poll_operation(body["operationId"])
        else:
            raise RuntimeError(f"CCF submit: unexpected body: {body}")
        return self._fetch_receipt(entry_id)

    def _poll_operation(self, op_id: str) -> str:
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            r = self._s.get(
                f"{self._base}/app/operations/{op_id}",
                timeout=self._timeout,
            )
            r.raise_for_status()
            body = r.json()
            status = body.get("status")
            if status == "succeeded":
                return body["entryId"]
            if status == "failed":
                raise RuntimeError(f"CCF operation failed: {body}")
            time.sleep(self._poll)
        raise TimeoutError(f"CCF operation {op_id} timed out after {self._timeout}s")

    def _fetch_receipt(self, entry_id: str) -> bytes:
        r = self._s.get(
            f"{self._base}/app/entries/{entry_id}/receipt",
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.content

    def fetch_ts_public_key_pem(self) -> bytes:
        """Fetch the TS's public key from its DID document.

        CCF publishes its log signing key at ``/.well-known/did.json`` as a JWK
        in the ``assertionMethod`` array.  Returns PEM-encoded public key bytes.
        """
        import base64  # noqa: PLC0415

        r = self._s.get(f"{self._base}/.well-known/did.json", timeout=self._timeout)
        r.raise_for_status()
        did_doc = r.json()

        for key_ref in did_doc.get("assertionMethod", []):
            jwk = (
                key_ref.get("publicKeyJwk", {})
                if isinstance(key_ref, dict)
                else next(
                    (
                        vm.get("publicKeyJwk", {})
                        for vm in did_doc.get("verificationMethod", [])
                        if vm.get("id") == key_ref
                    ),
                    {},
                )
            )
            if not jwk:
                continue
            kty = jwk.get("kty")
            if kty == "OKP" and jwk.get("crv") == "Ed25519":
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
                    Ed25519PublicKey,
                )
                pk = Ed25519PublicKey.from_public_bytes(
                    base64.urlsafe_b64decode(jwk["x"] + "==")
                )
                return pk.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            if kty == "EC" and jwk.get("crv") == "P-256":
                from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
                from cryptography.hazmat.primitives.asymmetric.ec import (  # noqa: PLC0415
                    SECP256R1,
                    EllipticCurvePublicNumbers,
                )
                x = int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big")
                y = int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big")
                pk = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
                return pk.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
        raise RuntimeError("no usable assertionMethod key found in CCF DID doc")

    def is_reachable(self) -> bool:
        try:
            r = self._s.get(f"{self._base}/.well-known/did.json", timeout=5.0)
            return r.status_code < 500
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Integration test — live CCF sandbox
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_ccf_sandbox_live() -> None:
    """Submit one Signed Statement to the live CCF SCITT sandbox and verify.

    **This is our runnable half of the Vienna CCF interop proof.**

    When it passes, upgrade the wording in ``agent-action-capsule`` README to:
    "verified against scitt.ccf.dev on <date>."

    Skip conditions:
    - ``requests`` not installed
    - ``SCITT_CCF_URL`` explicitly set to ``""`` (opt-out)
    - CCF endpoint unreachable (DNS failure, sandbox down, no network)

    Override the endpoint for a local CCF dev instance::

        SCITT_CCF_URL=https://localhost:8000 \\
        SCITT_CCF_TLS_VERIFY=0 \\
        pytest -m integration tests/test_ccf_interop.py::test_ccf_sandbox_live
    """
    pytest.importorskip("requests")

    ccf_url = os.environ.get("SCITT_CCF_URL", "https://scitt.ccf.dev")
    if ccf_url == "":
        pytest.skip("SCITT_CCF_URL is empty — CCF integration opted out")

    verify_tls = os.environ.get("SCITT_CCF_TLS_VERIFY", "1") != "0"
    client = CcfSandboxClient(base_url=ccf_url, verify_tls=verify_tls)

    if not client.is_reachable():
        pytest.skip(f"CCF sandbox unreachable at {ccf_url}")

    issuer_priv, _ = _ed25519_pair()
    signed_statement = _build_signed_statement(issuer_priv)
    entry_hex = hashlib.sha256(signed_statement).hexdigest()

    ccf_receipt = client.submit(signed_statement)
    ccf_pub = client.fetch_ts_public_key_pem()

    result = verify_receipt(
        ccf_receipt,
        leaf_entry_hex=entry_hex,
        log_public_key_pem=ccf_pub,
    )
    assert result.ok, (
        f"CCF receipt did not verify.\nErrors: {result.errors}"
    )
    assert result.root is not None
    assert result.tree_size is not None and result.tree_size >= 1
