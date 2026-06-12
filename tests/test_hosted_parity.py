# SPDX-License-Identifier: Apache-2.0
"""The hosted endpoint runs the IDENTICAL library — proven, not promised.

The credibility link for a hosted verifier is: "it is the same verified logic you
would run locally." This test asserts that on a fixture set, the hosted path's
verdict equals the local library's verdict — for valid statements, tampered
statements, valid/invalid receipts, and malformed input. It checks both the
in-process core (:func:`verify_payload`) and a real HTTP round-trip through the
stdlib handler, so the wire layer is covered too.
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import HTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from scitt_cose import build_receipt, build_signed_statement
from scitt_cose.hosted import make_asgi_app, make_handler, verify_payload
from scitt_cose.receipt import verify_receipt
from scitt_cose.statement import parse_signed_statement


def _keys():
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


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


@pytest.fixture
def fixtures():
    priv, pub = _keys()
    stmt = build_signed_statement(
        b'{"opaque":"bytes"}', alg="EdDSA", private_key_pem=priv,
        issuer="https://issuer.example", subject="urn:x", content_type="application/json",
    )
    # tampered statement (rebuild — cbor2>=6 CBORTag.value is an immutable tuple)
    tag = cbor2.loads(stmt)
    v = list(tag.value)
    body = bytearray(v[2])
    body[0] ^= 0x01
    v[2] = bytes(body)
    tampered = cbor2.dumps(cbor2.CBORTag(tag.tag, v))

    entries = [bytes([i]).hex() for i in range(5)]
    receipt = build_receipt(
        leaf_entry_hex=entries[2], leaf_index=2, tree_entries_hex=entries,
        alg="EdDSA", log_private_key_pem=priv,
    )
    return {
        "priv": priv, "pub": pub, "stmt": stmt, "tampered": tampered,
        "receipt": receipt, "entries": entries,
    }


def _requests(fx):
    """A spread of requests covering valid/invalid statement + receipt + junk."""
    pub = fx["pub"].decode()
    return [
        {"statement_b64": _b64(fx["stmt"]), "statement_pubkey_pem": pub},
        {"statement_b64": _b64(fx["tampered"]), "statement_pubkey_pem": pub},
        {"statement_b64": _b64(fx["stmt"])},  # no key -> not checked
        {
            "receipt_b64": _b64(fx["receipt"]),
            "log_pubkey_pem": pub,
            "leaf_entry_hex": fx["entries"][2],
        },
        {  # wrong leaf
            "receipt_b64": _b64(fx["receipt"]),
            "log_pubkey_pem": pub,
            "leaf_entry_hex": fx["entries"][3],
        },
        {"statement_b64": "!!!not base64!!!", "statement_pubkey_pem": pub},
        {},  # nothing supplied
    ]


def _local_verdict(req, fx) -> dict:
    """Compute the verdict by calling the library DIRECTLY (the parity oracle).

    Mirrors the hosted FAIL-CLOSED rule: a request is valid only when every
    component it carried affirmatively verified (statement signature is True, or
    receipt ok is True), and at least one component was present. A statement with
    no key (signature_verified is None) is NOT a success.
    """
    out = {"statement": None, "receipt": None}
    components = []
    if req.get("statement_b64"):
        try:
            raw = base64.b64decode(req["statement_b64"] + "===")
            pub = req.get("statement_pubkey_pem")
            parsed = parse_signed_statement(
                raw, public_key_pem=pub.encode() if pub else None
            )
            out["statement"] = parsed.get("signature_verified")
            components.append(parsed.get("signature_verified") is True)
        except Exception:  # noqa: BLE001
            out["statement"] = False
            components.append(False)
    if req.get("receipt_b64"):
        if not req.get("log_pubkey_pem") or not req.get("leaf_entry_hex"):
            out["receipt"] = False
            components.append(False)
        else:
            res = verify_receipt(
                base64.b64decode(req["receipt_b64"] + "==="),
                leaf_entry_hex=req["leaf_entry_hex"],
                log_public_key_pem=req["log_pubkey_pem"].encode(),
            )
            out["receipt"] = res.ok
            components.append(res.ok is True)
    out["valid"] = bool(components) and all(components)
    return out


def test_core_parity_hosted_equals_local(fixtures):
    for req in _requests(fixtures):
        hosted = verify_payload(req)
        local = _local_verdict(req, fixtures)
        assert hosted["valid"] == local["valid"], (req, hosted, local)
        if local["statement"] is not None:
            assert hosted["statement"]["signature_verified"] == local["statement"], req
        if local["receipt"] is not None:
            assert hosted["receipt"]["ok"] == local["receipt"], req


def test_http_roundtrip_parity(fixtures):
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    t = threading.Thread(target=httpd.handle_request)  # serve exactly one request
    host, port = httpd.server_address

    for req in _requests(fixtures):
        t = threading.Thread(target=httpd.handle_request)
        t.start()
        data = json.dumps(req).encode()
        http_req = Request(
            f"http://{host}:{port}/verify", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        # Missing-required-input is a 400 (malformed transport); the verdict
        # body is still returned and still mirrors the local library.
        expect_bad = not (req.get("statement_b64") or req.get("receipt_b64"))
        try:
            with urlopen(http_req, timeout=10) as resp:
                assert not expect_bad
                wire = json.loads(resp.read())
        except HTTPError as err:
            assert expect_bad and err.code == 400, (req, err.code)
            wire = json.loads(err.read())
        t.join(timeout=10)

        local = _local_verdict(req, fixtures)
        assert wire["valid"] == local["valid"], (req, wire, local)

    httpd.server_close()


def _drive_asgi(app, method, path, body=b"", root_path=""):
    """Minimal in-process ASGI client: returns (status, json-decoded body)."""
    import asyncio

    async def run():
        scope = {
            "type": "http", "method": method, "path": path,
            "root_path": root_path, "headers": [],
        }
        sent = []
        received = [
            {"type": "http.request", "body": body, "more_body": False},
        ]

        async def receive():
            return received.pop(0)

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        status = next(m["status"] for m in sent if m["type"] == "http.response.start")
        payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return status, json.loads(payload)

    return asyncio.run(run())


def test_asgi_ride_along_parity(fixtures):
    """The mountable ASGI app returns the same verdict as the local library."""
    app = make_asgi_app()
    for req in _requests(fixtures):
        status, wire = _drive_asgi(app, "POST", "/verify", json.dumps(req).encode())
        expect_bad = not (req.get("statement_b64") or req.get("receipt_b64"))
        assert status == (400 if expect_bad else 200)
        local = _local_verdict(req, fixtures)
        assert wire["valid"] == local["valid"], (req, wire, local)

    # Capabilities at root, and it must declare it is NOT a transparency service.
    status, caps = _drive_asgi(app, "GET", "/")
    assert status == 200
    assert "transparency service" in " ".join(caps["does_not"]).lower()


def test_asgi_mounted_under_prefix(fixtures):
    """Routing must work when mounted under a prefix (root_path set, prefix in path).

    This mirrors how Starlette/FastAPI deliver a mounted sub-app: the mount prefix
    stays in scope['path'] and is also in scope['root_path']. Regression guard for
    the ride-along mount (e.g. app.mount('/scitt-verify', make_asgi_app())).
    """
    app = make_asgi_app()
    pub = fixtures["pub"].decode()
    req = {"statement_b64": _b64(fixtures["stmt"]), "statement_pubkey_pem": pub}

    status, caps = _drive_asgi(app, "GET", "/scitt-verify/", root_path="/scitt-verify")
    assert status == 200 and "does_not" in caps

    status, wire = _drive_asgi(
        app, "POST", "/scitt-verify/verify",
        body=json.dumps(req).encode(), root_path="/scitt-verify",
    )
    assert status == 200
    assert wire["valid"] is True
    assert wire["statement"]["signature_verified"] is True


def test_capabilities_endpoint_states_not_a_transparency_service(fixtures):
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    host, port = httpd.server_address
    t = threading.Thread(target=httpd.handle_request)
    t.start()
    with urlopen(f"http://{host}:{port}/", timeout=10) as resp:
        caps = json.loads(resp.read())
    t.join(timeout=10)
    httpd.server_close()

    does_not = " ".join(caps["does_not"]).lower()
    assert "transparency service" in does_not
    assert "store" in does_not or "retain" in does_not
    assert caps["retention"].startswith("nothing retained")
