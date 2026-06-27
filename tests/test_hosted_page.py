# SPDX-License-Identifier: Apache-2.0
"""The boundary table is ON the landing page itself — not buried in docs.

The load-bearing distinction for the hosted offering is *verifier, NOT a
Transparency Service*. These tests pin that the table stating it is rendered by
the endpoint's own root path: HTML for browsers (Accept: text/html), and the
same data as JSON for API clients — on both the stdlib handler and the ASGI app.
"""
from __future__ import annotations

import json
import threading
from http.server import HTTPServer
from urllib.request import Request, urlopen

from scitt_cose.hosted import (
    ATTRIBUTION,
    BOUNDARY_TABLE,
    CAPABILITIES,
    PRIVACY,
    REPO_URL,
    SUMMARY,
    VERIFY_JS,
    make_asgi_app,
    make_handler,
    render_landing_page,
)

# Phrases that must appear verbatim on the human-facing page.
_BOUNDARY_PHRASES = (
    "NOT a Transparency Service",
    "verify only",
    "register statements, issue receipts, anchor",
    "none (stateless)",
    "durable, append-only log",
    "nobody trusts the operator",
    "the ecosystem trusts the log operator",
)


def test_boundary_table_in_json_capabilities():
    """API clients see the same boundary data the page renders."""
    assert CAPABILITIES["boundary"] is BOUNDARY_TABLE
    dims = [r["dimension"] for r in BOUNDARY_TABLE["rows"]]
    assert dims == [
        "Operation", "State", "Trust commitment", "Risk class", "Who must trust whom",
    ]


def test_landing_page_renders_boundary_table():
    html = render_landing_page()
    for phrase in _BOUNDARY_PHRASES:
        assert phrase in html, f"boundary phrase missing from page: {phrase!r}"
    # Every capability statement is on the page too.
    for line in CAPABILITIES["does"] + CAPABILITIES["does_not"]:
        assert line in html
    # Draft-tracking honesty is on the page — stated positively, with no
    # mention of unassigned RFC numbers in any form.
    assert "NOT yet published as RFCs" in html
    assert "9942" not in html
    # Interactive page: no inline scripts (externalized to /static/verify.js);
    # no external stylesheet fetches; no Google Fonts or CDN resources.
    assert '<script src="/static/verify.js">' in html
    assert "<link" not in html
    # No inline script content — the only <script> tag references the external file.
    import re as _re
    assert not _re.search(r"<script[^>]*>[^<]", html)


def test_landing_page_self_hosted_js_no_inline_scripts():
    """New CSP contract: JS is externalized to /static/verify.js (script-src
    'self', no unsafe-inline). No external resource loads (no CDN fonts,
    stylesheets, or asset fetches). External hrefs are allowlisted."""
    import re

    html = render_landing_page()

    # The only script tag must point to the self-hosted file.
    assert '<script src="/static/verify.js">' in html
    # No inline script content — would need unsafe-inline.
    assert not re.search(r"<script[^>]*>[^<]", html)

    # No external resource fetches (fonts, CDN assets).
    assert "<link" not in html        # no external stylesheets/preconnect
    assert "@import" not in html
    assert "url(" not in html         # no CSS background-image or font-url
    assert "@font-face" not in html

    # The only src= attribute is the self-hosted JS (relative path, not http).
    srcs = re.findall(r'<script[^>]+src="([^"]*)"', html)
    assert srcs == ["/static/verify.js"], f"unexpected script srcs: {srcs}"

    # External href allowlist — expanded for the interactive page.
    hrefs = re.findall(r'href="([^"]*)"', html)
    external = {h for h in hrefs if h.startswith("http")}
    allowed = {
        REPO_URL,
        "https://agentactioncapsule.org",
        "https://agentactioncapsule.org/docs/",
        "https://anchor.agentactioncapsule.org",
        "https://verify.actionstate.ai",
        "https://github.com/action-state-group",
        "https://github.com/ietf-wg-scitt/examples",
        "https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/",
    }
    unexpected = external - allowed
    assert not unexpected, f"unexpected external hrefs: {unexpected}"


def test_landing_page_five_items():
    """The page's whole job list, pinned: one-sentence summary, boundary table
    (covered above), interactive tool + "verify locally" stance, privacy
    posture, attribution footer."""
    html = render_landing_page()
    # 1. What it is, one sentence — same constant the JSON serves.
    assert SUMMARY in html
    assert CAPABILITIES["summary"] == SUMMARY
    # 3. How to use it: interactive tool with pip install line, the repo link,
    #    and the explicit "the library is the product" stance.
    assert "pip install scitt-cose" in html
    assert f'href="{REPO_URL}"' in html
    assert "You don't need this service" in html
    # 4. The privacy posture — each item from the constant appears verbatim.
    for line in PRIVACY:
        assert line in html
    assert CAPABILITIES["privacy"] is PRIVACY
    # 5. Attribution footer: named operator, license, foundation intent.
    assert "<footer>" in html
    assert "Action State Group" in html
    assert "Apache-2.0" in html
    assert "open-source foundation" in html
    assert CAPABILITIES["attribution"] is ATTRIBUTION


def _get(url: str, accept: str | None):
    headers = {"Accept": accept} if accept else {}
    req = Request(url, headers=headers, method="GET")
    with urlopen(req, timeout=10) as resp:
        return resp.headers.get("Content-Type", ""), resp.read()


def test_stdlib_handler_content_negotiation():
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    host, port = httpd.server_address
    try:
        # Browser: HTML with the boundary table.
        t = threading.Thread(target=httpd.handle_request)
        t.start()
        ctype, body = _get(f"http://{host}:{port}/", "text/html,application/xhtml+xml")
        t.join(timeout=10)
        assert ctype.startswith("text/html")
        page = body.decode()
        for phrase in _BOUNDARY_PHRASES:
            assert phrase in page

        # API client (no Accept header): JSON, boundary included.
        t = threading.Thread(target=httpd.handle_request)
        t.start()
        ctype, body = _get(f"http://{host}:{port}/", None)
        t.join(timeout=10)
        assert ctype.startswith("application/json")
        assert json.loads(body)["boundary"]["rows"] == BOUNDARY_TABLE["rows"]
    finally:
        httpd.server_close()


def _drive_asgi(app, headers, path="/"):
    import asyncio

    async def run():
        scope = {"type": "http", "method": "GET", "path": path, "root_path": "",
                 "headers": headers}
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        ctype = dict(start["headers"])[b"content-type"].decode()
        return start["status"], ctype, body

    return asyncio.run(run())


def test_asgi_content_negotiation():
    app = make_asgi_app()

    status, ctype, body = _drive_asgi(app, [(b"accept", b"text/html,*/*;q=0.8")])
    assert status == 200 and ctype.startswith("text/html")
    page = body.decode()
    for phrase in _BOUNDARY_PHRASES:
        assert phrase in page

    status, ctype, body = _drive_asgi(app, [(b"accept", b"application/json")])
    assert status == 200 and ctype.startswith("application/json")
    assert json.loads(body)["boundary"]["rows"] == BOUNDARY_TABLE["rows"]


def test_health_stdlib_and_asgi():
    """/health is canonical (Google's frontend eats /healthz on run.app);
    /healthz stays as an alias for other hosts."""
    # ASGI
    app = make_asgi_app()
    for probe in ("/health", "/healthz"):
        status, ctype, body = _drive_asgi(app, [], path=probe)
        assert status == 200 and json.loads(body) == {"ok": True}

    # stdlib
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    host, port = httpd.server_address
    try:
        for probe in ("/health", "/healthz"):
            t = threading.Thread(target=httpd.handle_request)
            t.start()
            ctype, body = _get(f"http://{host}:{port}{probe}", None)
            t.join(timeout=10)
            assert json.loads(body) == {"ok": True}
    finally:
        httpd.server_close()


def _post_asgi(app, body: bytes):
    import asyncio

    async def run():
        scope = {"type": "http", "method": "POST", "path": "/verify",
                 "root_path": "", "headers": []}
        sent = []

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        out = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return start["status"], out

    return asyncio.run(run())


def test_rate_backstop_asgi():
    """In-process anonymous backstop: requests over the per-minute budget get
    429 without the body being read; 0 disables it (edge-only deployments)."""
    app = make_asgi_app(verify_rpm=2)
    req = json.dumps({"statement_b64": ""}).encode()  # missing-input -> 400
    assert _post_asgi(app, req)[0] == 400
    assert _post_asgi(app, req)[0] == 400
    status, body = _post_asgi(app, req)
    assert status == 429
    assert json.loads(body)["valid"] is False

    unlimited = make_asgi_app(verify_rpm=0)
    for _ in range(5):
        assert _post_asgi(unlimited, req)[0] == 400


def test_transport_errors_are_400_verification_failures_are_200():
    """400 is reserved for malformed transport (non-JSON, non-object, missing
    required input); 200 + valid:false is a well-formed verification verdict.
    The 400 body still carries the full capabilities document — self-teaching."""
    app = make_asgi_app(verify_rpm=0)

    # Malformed transport -> 400.
    for bad in (b"not json at all", b'["a","list"]', b"{}"):
        status, body = _post_asgi(app, bad)
        assert status == 400, bad
        verdict = json.loads(body)
        assert verdict["valid"] is False and verdict["bad_request"] is True
    assert "boundary" in json.loads(_post_asgi(app, b"{}")[1])["capabilities"]

    # Well-formed but cryptographically invalid -> 200, valid:false.
    garbage_statement = json.dumps({"statement_b64": "AAAA"}).encode()
    status, body = _post_asgi(app, garbage_statement)
    assert status == 200
    verdict = json.loads(body)
    assert verdict["valid"] is False
    assert "bad_request" not in verdict


def test_security_headers_on_every_response():
    """HSTS, nosniff, frame denial, self-only CSP, no-referrer — on HTML, JSON,
    JS, and verdict responses, from both wrappers. CSP: script-src 'self' (no
    unsafe-inline), connect-src 'self', form-action 'self'."""
    from scitt_cose.hosted import SECURITY_HEADERS

    expected = {k.lower(): v for k, v in SECURITY_HEADERS}
    assert "strict-transport-security" in expected
    assert expected["x-content-type-options"] == "nosniff"
    csp = expected["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp
    assert "unsafe-inline" not in csp.replace("style-src 'unsafe-inline'", "")
    assert expected["referrer-policy"] == "no-referrer"

    # ASGI: landing page (HTML), capabilities (JSON), and a verdict.
    import asyncio

    app = make_asgi_app(verify_rpm=0)

    def headers_of(method, path, body=b"", accept=None):
        async def run():
            hdrs = [(b"accept", accept)] if accept else []
            scope = {"type": "http", "method": method, "path": path,
                     "root_path": "", "headers": hdrs}
            sent = []

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                sent.append(message)

            await app(scope, receive, send)
            start = next(m for m in sent if m["type"] == "http.response.start")
            return {k.decode(): v.decode() for k, v in start["headers"]}

        return asyncio.run(run())

    for hdrs in (
        headers_of("GET", "/", accept=b"text/html"),
        headers_of("GET", "/"),
        headers_of("POST", "/verify", body=b"{}"),
    ):
        for name, value in expected.items():
            assert hdrs.get(name) == value, f"missing/wrong header {name}: {hdrs}"

    # stdlib wrapper: same headers on the landing page and the JSON.
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    host, port = httpd.server_address
    try:
        for accept in ("text/html", None):
            t = threading.Thread(target=httpd.handle_request)
            t.start()
            req = Request(f"http://{host}:{port}/",
                          headers={"Accept": accept} if accept else {}, method="GET")
            with urlopen(req, timeout=10) as resp:
                got = {k.lower(): v for k, v in resp.headers.items()}
            t.join(timeout=10)
            for name, value in expected.items():
                assert got.get(name) == value, f"stdlib missing header {name}"
    finally:
        httpd.server_close()


def test_static_js_route():
    """GET /static/verify.js returns the externalized interaction script with
    correct content-type and the same security headers as every other response.
    The JS content must include the same-origin fetch target and VALID/INVALID
    verdict strings."""
    from scitt_cose.hosted import SECURITY_HEADERS

    # ASGI
    app = make_asgi_app(verify_rpm=0)
    status, ctype, body = _drive_asgi(app, [], path="/static/verify.js")
    assert status == 200
    assert "javascript" in ctype
    js = body.decode()
    assert VERIFY_JS == js
    assert "/verify" in js
    assert "VALID" in js
    assert "INVALID" in js
    assert "fetch" in js

    # ASGI security headers on the JS response
    import asyncio

    async def js_headers():
        scope = {"type": "http", "method": "GET", "path": "/static/verify.js",
                 "root_path": "", "headers": []}
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        return {k.decode(): v.decode() for k, v in start["headers"]}

    hdrs = asyncio.run(js_headers())
    expected = {k.lower(): v for k, v in SECURITY_HEADERS}
    for name, value in expected.items():
        assert hdrs.get(name) == value, f"JS route missing header {name}"

    # stdlib
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    host, port = httpd.server_address
    try:
        t = threading.Thread(target=httpd.handle_request)
        t.start()
        req = Request(f"http://{host}:{port}/static/verify.js", method="GET")
        with urlopen(req, timeout=10) as resp:
            assert resp.status == 200
            assert "javascript" in resp.headers.get("Content-Type", "")
            assert resp.read().decode() == VERIFY_JS
        t.join(timeout=10)
    finally:
        httpd.server_close()
