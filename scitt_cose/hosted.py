# SPDX-License-Identifier: Apache-2.0
"""Stateless, read-only HTTP verification wrapper — the *same* library, hosted.

This is a thin wrapper so someone can verify a SCITT statement / receipt without
installing anything. It is deliberately minimal and carries these properties by
construction:

* **Read-only utility, NOT a Transparency Service.** It verifies and returns a
  verdict. It never registers, never issues a receipt, never anchors, never holds
  trust. Operating a log is a separate, commercial concern — explicitly out of
  scope (see ``docs/hosted-verifier-design.md``).
* **Stateless.** No database, no queue, no persistence. Each request is verified
  in memory and the inputs are discarded when the handler returns.
* **Safe for the submitter.** The endpoint logs only an anonymous request count
  and the boolean verdict — never the submitted statement, payload, or keys. A
  submitter does not have to trust the operator with their data. For the receipt
  path, verification needs only the *leaf digest* + proof, never the payload.
* **Identical logic to the local library.** It calls the exact same
  :func:`scitt_cose.statement.parse_signed_statement` and
  :func:`scitt_cose.receipt.verify_receipt`. ``tests/test_hosted_parity.py``
  asserts hosted verdict == local verdict on a fixture set, so "the hosted
  endpoint runs the identical verified library" is a checked claim, not a promise.

Dependencies: standard library only (``http.server``, ``json``, ``base64``).
No web framework is pulled into the package; the runtime deps stay cbor2 +
cryptography.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from ._status import DRAFT_TRACKING_NOTICE
from .cose_sign1 import CoseError
from .receipt import verify_receipt
from .statement import parse_signed_statement

#: One sentence, the whole offering. Served on the page and in the JSON.
SUMMARY = (
    "A free, stateless verification endpoint for SCITT receipts and signed "
    "statements (RFC9162_SHA256 profile). It verifies; it stores nothing; "
    "it issues nothing."
)

#: The open-source home of the verifier this endpoint runs. The ONLY external
#: link the landing page carries (plain <a href>, no fetched assets) — the
#: endpoint exists to sell the library, not the other way around. Provisional
#: name; the launch checklist's name-claim step updates this in the same pass.
REPO_URL = "https://github.com/action-state-group/scitt-cose"

#: The privacy posture, stated as data so the page and the API can never
#: drift. For a verification service the privacy statement IS the product spec.
PRIVACY = [
    "stateless — nothing persists across requests; no database, no queue",
    "retains nothing — no statement, payload, key, or header is stored",
    "payload-opaque — payload bytes are never parsed for semantics and never "
    "echoed back (the response reports only payload_len)",
    "no accounts, no authentication, no cookies, no analytics",
    "operational logging only: HTTP method + status code + an anonymous "
    "request count — never bodies, query strings, or keys",
]

#: Attribution — a named operator is required for trust; marketing chrome is
#: not. This is the footer, in full.
ATTRIBUTION = {
    "operated_by": "Action State Group",
    "license": "Apache-2.0",
    "source": REPO_URL,
    "foundation_intent": (
        "we intend to contribute this project to an appropriate "
        "open-source foundation"
    ),
}

#: The load-bearing boundary, as data: this service vs. a Transparency Service.
#: Rendered ON the landing page itself (HTML for browsers, JSON for clients) —
#: not buried in docs — so the distinction is unmissable at the URL.
BOUNDARY_TABLE = {
    "this_service": "hosted SCITT-only verifier (read-only, stateless)",
    "is_not": "a SCITT Transparency Service",
    "rows": [
        {
            "dimension": "Operation",
            "verifier": "verify only",
            "transparency_service": "register statements, issue receipts, anchor",
        },
        {
            "dimension": "State",
            "verifier": "none (stateless)",
            "transparency_service": "a durable, append-only log",
        },
        {
            "dimension": "Trust commitment",
            "verifier": "none — verify it yourself",
            "transparency_service": "uptime, integrity, non-equivocation, witnessing",
        },
        {
            "dimension": "Risk class",
            "verifier": "low (read-only utility)",
            "transparency_service": "high (operational trust infrastructure)",
        },
        {
            "dimension": "Who must trust whom",
            "verifier": "nobody trusts the operator",
            "transparency_service": "the ecosystem trusts the log operator",
        },
    ],
}

#: What this endpoint will and will not do — surfaced at the root path and here
#: so the neutrality / not-a-transparency-service stance is unmissable.
CAPABILITIES = {
    "summary": SUMMARY,
    "does": [
        "verify a SCITT COSE_Sign1 Signed Statement signature (if a key is given)",
        "report the statement's issuer / subject / content-type / alg (payload-opaque)",
        "verify a COSE Receipt inclusion proof + log signature (RFC 9162 SHA-256)",
    ],
    "does_not": [
        "operate a Transparency Service (register / issue receipts / anchor)",
        "store, log, or retain submitted statements, payloads, or keys",
        "validate any application profile's payload semantics (payload is opaque)",
        "require authentication or an account (public read-only utility)",
    ],
    "retention": "nothing retained; only an anonymous request count and the verdict",
    "privacy": PRIVACY,
    "boundary": BOUNDARY_TABLE,
    "attribution": ATTRIBUTION,
    "draft_tracking": DRAFT_TRACKING_NOTICE,
}


#: Security headers on every response, both wrappers. The page is static and
#: script-free by construction; these make that posture legible to the header
#: scanners a security audience runs reflexively. CSP allows only the inline
#: <style> block (the page's single styling mechanism) and forbids everything
#: else — there is nothing to load, frame, or submit.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
    ("Referrer-Policy", "no-referrer"),
)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_landing_page() -> str:
    """The human-facing landing page (``GET /`` with ``Accept: text/html``).

    Renders the SAME data the JSON capabilities response carries — including the
    verifier-vs-Transparency-Service **boundary table**, on the page itself, not
    buried in docs. Static, no scripts, no external assets, built from the same
    constants the API serves so the two can never drift apart.
    """
    rows = "\n".join(
        "<tr><th>{d}</th><td>{v}</td><td>{t}</td></tr>".format(
            d=_esc(r["dimension"]),
            v=_esc(r["verifier"]),
            t=_esc(r["transparency_service"]),
        )
        for r in BOUNDARY_TABLE["rows"]
    )
    does = "\n".join(f"<li>{_esc(x)}</li>" for x in CAPABILITIES["does"])
    does_not = "\n".join(f"<li>{_esc(x)}</li>" for x in CAPABILITIES["does_not"])
    privacy = "\n".join(f"<li>{_esc(x)}</li>" for x in PRIVACY)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCITT/COSE verifier — stateless, read-only</title>
<style>
  /* Tokens — "sealed evidence / precision instrument". Paper (light) and warm
     instrument dark; system fonts only, no scripts, no fetched assets.
     --pass / --broken are the shared verdict tokens, reserved for verdict
     surfaces (unused on this static page, kept so the set stays whole). */
  :root {{
    color-scheme: light dark;
    --bg: #FAF9F7; --surface: #FFFFFF; --ink: #1C1917; --muted: #57534E;
    --hairline: #E7E5E4; --seal: #B45309; --pass: #15803D; --broken: #B91C1C;
    --serif: "Iowan Old Style", Palatino, Georgia, serif;
    --sans: system-ui, sans-serif;
    --mono: ui-monospace, "SF Mono", Menlo, monospace;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #16130F; --surface: #1F1B16; --ink: #E8E3DB; --muted: #A8A29E;
      --hairline: #332E27; --seal: #FBBF24; --pass: #4ADE80; --broken: #F87171;
    }}
  }}
  body {{ font: 16px/1.55 var(--sans); max-width: 46rem; margin: 2rem auto; padding: 0 1rem;
         color: var(--ink); background: var(--bg); }}
  h1, h2 {{ font-family: var(--serif); font-weight: 600; }}
  h1 {{ font-size: 1.6rem; }} h2 {{ font-size: 1.2rem; margin-top: 2rem; }}
  a {{ color: var(--seal); text-decoration: underline dotted; text-underline-offset: 2px; }}
  a:hover {{ text-decoration-style: solid; }}
  a:focus-visible {{ outline: 2px solid var(--seal); outline-offset: 2px; border-radius: 2px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0;
          background: var(--surface); border: 1px solid var(--hairline); }}
  th, td {{ padding: .7rem .85rem; text-align: left; vertical-align: top;
           border-bottom: 1px solid var(--hairline); }}
  thead th {{ font-family: var(--serif); font-size: 11px; font-weight: 600;
             text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }}
  tbody th {{ font-family: var(--serif); font-weight: 600; white-space: nowrap; }}
  tbody td {{ font-family: var(--mono); font-size: 13px; }}
  tbody tr:last-child th, tbody tr:last-child td {{ border-bottom: none; }}
  code, pre {{ font-family: var(--mono); font-size: 13px;
              background: var(--surface); border: 1px solid var(--hairline); border-radius: 4px; }}
  code {{ padding: .1rem .3rem; }} pre {{ padding: .75rem; overflow-x: auto; }}
  .notice {{ background: var(--surface); border: 1px solid var(--hairline);
            border-left: 3px solid var(--seal); border-radius: 4px; padding: .75rem 1rem; }}
  footer {{ margin-top: 2.5rem; border-top: 1px solid var(--hairline); padding-top: 1rem;
           font-size: .85rem; color: var(--muted); }}
  footer a {{ color: inherit; }}
</style>
</head>
<body>
<h1>SCITT/COSE verifier</h1>
<p><strong>{_esc(SUMMARY)}</strong></p>
<p>It verifies a SCITT <code>COSE_Sign1</code> Signed Statement and/or a COSE
Receipt (RFC&nbsp;9162 SHA-256 inclusion proof + log signature) and returns
<em>valid / invalid + reasons</em>. Nothing you submit is stored or logged.</p>

<h2>This is a verifier, NOT a Transparency Service</h2>
<table>
<thead><tr><th></th><th>This service: SCITT-only verifier</th><th>A Transparency Service (separate concern)</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<p>A verifier that starts storing submissions, issuing receipts, or anchoring
has silently become a transparency service with all of its obligations. This
one has no write path, no persistence, and no key custody — by construction.</p>

<h2>What it does</h2>
<ul>
{does}
</ul>

<h2>What it does not do</h2>
<ul>
{does_not}
</ul>

<h2>How to use it</h2>
<pre>curl -s -X POST /verify -H 'Content-Type: application/json' -d '{{
  "receipt_b64":    "&lt;base64 COSE Receipt&gt;",
  "log_pubkey_pem": "&lt;PEM public key of the log&gt;",
  "leaf_entry_hex": "&lt;hex leaf digest the receipt proves&gt;"
}}'
-&gt; {{"valid": bool, "statement": …, "receipt": …, "reasons": […]}}</pre>
<p>Statements go in the same request as <code>statement_b64</code> (+
<code>statement_pubkey_pem</code> to check the signature). The receipt path
needs only the <em>leaf digest</em> + proof — never your payload.</p>
<p><strong>You don't need this service.</strong> The verifier is open source
(<code>pip install scitt-cose</code>,
<a href="{REPO_URL}">source</a>) and runs anywhere; this endpoint runs the
identical library and exists for convenience and demos — the result is the
same, so for maximal privacy verify locally.</p>

<h2>Privacy</h2>
<ul>
{privacy}
</ul>

<h2>Standards status</h2>
<p class="notice">{_esc(DRAFT_TRACKING_NOTICE)}</p>

<footer>
<p>Operated by {_esc(ATTRIBUTION["operated_by"])} &middot; verifier is open
source (<a href="{REPO_URL}">{_esc(ATTRIBUTION["license"])}</a>) &middot;
{_esc(ATTRIBUTION["foundation_intent"])}.</p>
<p>Part of Action State Group's open verification tooling.</p>
</footer>
</body>
</html>
"""


def _b64(value: str) -> bytes:
    # Accept standard or URL-safe base64, with or without padding.
    s = value.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:  # noqa: BLE001
        return base64.b64decode(s + pad)


def verify_payload(request: dict[str, Any]) -> dict[str, Any]:
    """Verify a statement and/or receipt described by ``request`` (pure, stateless).

    ``request`` keys (all optional except that at least one of ``statement_b64`` /
    ``receipt_b64`` must be present):

    * ``statement_b64``        — base64 of the COSE_Sign1 Signed Statement
    * ``statement_pubkey_pem`` — PEM public key to check the statement signature
    * ``receipt_b64``          — base64 of the COSE Receipt
    * ``log_pubkey_pem``       — PEM public key of the transparency log
    * ``leaf_entry_hex``       — hex of the leaf the receipt proves

    Returns a JSON-able verdict dict. Never raises for input problems — they land
    in ``reasons`` with ``valid: false``.
    """
    reasons: list[str] = []
    statement_report: dict | None = None
    receipt_report: dict | None = None

    has_statement = bool(request.get("statement_b64"))
    has_receipt = bool(request.get("receipt_b64"))
    if not has_statement and not has_receipt:
        # bad_request marks a malformed *transport* (HTTP wrappers answer 400);
        # 200 + valid:false is reserved for well-formed-but-failed verification.
        return {
            "valid": False,
            "bad_request": True,
            "reasons": ["supply at least one of statement_b64 or receipt_b64"],
            "capabilities": CAPABILITIES,
        }

    if has_statement:
        try:
            stmt = _b64(request["statement_b64"])
            pub = request.get("statement_pubkey_pem")
            pub_bytes = pub.encode() if isinstance(pub, str) else pub
            parsed = parse_signed_statement(stmt, public_key_pem=pub_bytes)
            # Strip the payload bytes from the response — payload-opaque, and we
            # do not echo the submitter's data back.
            payload = parsed.get("payload")
            statement_report = {
                "issuer": parsed.get("issuer"),
                "subject": parsed.get("subject"),
                "content_type": parsed.get("content_type"),
                "alg": parsed.get("alg"),
                "signature_verified": parsed.get("signature_verified"),
                "payload_len": len(payload) if payload is not None else None,
            }
            if parsed.get("signature_verified") is False:
                reasons.append("statement signature did not verify")
            elif parsed.get("signature_verified") is None:
                reasons.append("statement signature not checked (no statement_pubkey_pem)")
        except CoseError as exc:
            statement_report = {"signature_verified": False}
            reasons.append(f"statement: {exc}")
        except Exception as exc:  # noqa: BLE001
            statement_report = {"signature_verified": False}
            reasons.append(f"statement: malformed input ({type(exc).__name__})")

    if has_receipt:
        log_pub = request.get("log_pubkey_pem")
        leaf = request.get("leaf_entry_hex")
        if not log_pub or not leaf:
            receipt_report = {"ok": False}
            reasons.append("receipt requires log_pubkey_pem and leaf_entry_hex")
        else:
            try:
                receipt = _b64(request["receipt_b64"])
                log_bytes = log_pub.encode() if isinstance(log_pub, str) else log_pub
                res = verify_receipt(receipt, leaf_entry_hex=leaf, log_public_key_pem=log_bytes)
                receipt_report = {
                    "ok": res.ok,
                    "root": res.root,
                    "tree_size": res.tree_size,
                    "leaf_index": res.leaf_index,
                    "errors": list(res.errors),
                }
                if not res.ok:
                    reasons.extend(res.errors)
            except Exception as exc:  # noqa: BLE001
                receipt_report = {"ok": False}
                reasons.append(f"receipt: malformed input ({type(exc).__name__})")

    # Fail closed: `valid` is true only when EVERY component the request carried
    # was affirmatively verified, and at least one real check ran. A statement
    # with no key (signature_verified is None) was NOT checked, so it does not
    # count as success — it makes the request invalid, with a reason. This is the
    # M1 fix: the old default-true logic returned valid for an unverified
    # statement that merely happened not to be an explicit False.
    components: list[bool] = []
    if statement_report is not None:
        components.append(statement_report.get("signature_verified") is True)
    if receipt_report is not None:
        components.append(receipt_report.get("ok") is True)
    valid = bool(components) and all(components)

    return {
        "valid": valid,
        "statement": statement_report,
        "receipt": receipt_report,
        "reasons": reasons,
        "draft_tracking": DRAFT_TRACKING_NOTICE,
    }


def verify_request_bytes(body: bytes) -> dict[str, Any]:
    """Parse a JSON request body and verify it. Stateless; nothing is retained."""
    try:
        request = json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return {
            "valid": False,
            "bad_request": True,
            "reasons": [f"request body is not valid JSON ({exc})"],
        }
    if not isinstance(request, dict):
        return {
            "valid": False,
            "bad_request": True,
            "reasons": ["request body must be a JSON object"],
        }
    return verify_payload(request)


# --- Optional stdlib HTTP wrapper (for local/demo; deployment is by design) ---


class _RateGate:
    """Anonymous fixed-window rate backstop for ``POST /verify``.

    The *edge* (gateway / load balancer) is the abuse front line per the design
    doc; this is the in-process backstop so a bare deployment is never wide
    open. Deliberately anonymous: one global counter + window start, no per-IP
    state, no submission data — the only state the design permits.
    """

    def __init__(self, per_minute: int | None = None) -> None:
        import os

        if per_minute is None:
            per_minute = int(os.environ.get("SCITT_VERIFY_RPM", "600"))
        self.per_minute = per_minute
        self._window_start = 0.0
        self._count = 0

    def allow(self) -> bool:
        if self.per_minute <= 0:  # 0 disables the backstop (edge-only setups)
            return True
        import time

        now = time.monotonic()
        if now - self._window_start >= 60.0:
            self._window_start = now
            self._count = 0
        self._count += 1
        return self._count <= self.per_minute


_RATE_LIMITED = {"valid": False, "reasons": ["rate limited; try again shortly"]}


def make_handler(verify_rpm: int | None = None):
    """Build a stdlib ``BaseHTTPRequestHandler`` serving the verifier.

    GET ``/``        -> capabilities (what it does / does not do).
    GET ``/health`` (alias ``/healthz``) -> liveness probe (200, no body
    inspection, no count). ``/health`` is the canonical probe path: Google's
    frontend intercepts ``/healthz`` on run.app domains and 404s it before
    the container ever sees the request.
    POST ``/verify`` -> verify a JSON request body, return the verdict.

    The handler keeps no state across requests and logs only the verdict boolean
    and an anonymous counter (overridable). It never logs request bodies.
    """
    from http.server import BaseHTTPRequestHandler

    gate = _RateGate(verify_rpm)

    class VerifyHandler(BaseHTTPRequestHandler):
        server_version = "scitt-cose-verifier/stateless"
        request_count = 0  # anonymous count only; class-level, no per-request data

        def _send_json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in SECURITY_HEADERS:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, code: int, html: str) -> None:
            body = html.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in SECURITY_HEADERS:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("/health", "/healthz"):
                self._send_json(200, {"ok": True})
            elif self.path.rstrip("/") in ("", "/verify"):
                # Browsers get the landing page (boundary table on the page
                # itself); API clients get the same data as JSON.
                if "text/html" in (self.headers.get("Accept") or ""):
                    self._send_html(200, render_landing_page())
                else:
                    self._send_json(
                        200, {"service": "stateless SCITT/COSE verifier", **CAPABILITIES}
                    )
            else:
                self._send_json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path.rstrip("/") != "/verify":
                self._send_json(404, {"error": "POST /verify"})
                return
            if not gate.allow():
                self._send_json(429, dict(_RATE_LIMITED))
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > 1_000_000:  # cap request size; abuse-surface control
                self._send_json(413, {"valid": False, "reasons": ["request too large"]})
                return
            body = self.rfile.read(length)
            verdict = verify_request_bytes(body)
            type(self).request_count += 1
            self._send_json(400 if verdict.get("bad_request") else 200, verdict)

        def log_message(self, fmt, *args):  # noqa: A003
            # Anonymous: method + status only, NEVER the body/path query/keys.
            pass

    return VerifyHandler


def make_asgi_app(verify_rpm: int | None = None):
    """Build a minimal, framework-free **ASGI** app exposing the verifier.

    ASGI is just an async-callable protocol — no web framework is imported, so the
    package stays stdlib-only. This is the "ride-along" entry point: any ASGI host
    (FastAPI/Starlette/uvicorn) can mount it, e.g.::

        app.mount("/scitt-verify", make_asgi_app())

    so a stateless SCITT/COSE verifier can share an existing service's deployment
    without that service's code leaking into this neutral package. Routes mirror
    the stdlib handler: ``GET /`` -> capabilities, ``GET /health`` (alias
    ``/healthz``; see ``make_handler`` on why) -> liveness, ``POST /verify``
    -> verdict.
    """
    gate = _RateGate(verify_rpm)

    async def app(scope, receive, send):  # noqa: ANN001
        if scope["type"] == "lifespan":
            # Drain lifespan events so hosts that send them don't hang.
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return

        sec_headers = [
            (name.lower().encode(), value.encode()) for name, value in SECURITY_HEADERS
        ]

        async def send_json(status: int, obj: dict) -> None:
            body = json.dumps(obj, default=str).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                    *sec_headers,
                ],
            })
            await send({"type": "http.response.body", "body": body})

        async def send_html(status: int, html: str) -> None:
            await send({
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"text/html; charset=utf-8"),
                    (b"cache-control", b"no-store"),
                    *sec_headers,
                ],
            })
            await send({"type": "http.response.body", "body": html.encode("utf-8")})

        def _accepts_html() -> bool:
            for name, value in scope.get("headers", []):
                if name == b"accept" and b"text/html" in value:
                    return True
            return False

        method = scope.get("method", "GET")
        # When mounted, ASGI hosts (Starlette/FastAPI) leave the mount prefix in
        # scope["path"] and set scope["root_path"] to it; strip it so routing is
        # identical whether mounted or served standalone.
        path = scope.get("path", "/")
        root = scope.get("root_path", "")
        if root and path.startswith(root):
            path = path[len(root):]
        path = path.rstrip("/") or "/"

        if method == "GET" and path in ("/health", "/healthz"):
            await send_json(200, {"ok": True})
            return
        if method == "GET" and path in ("/", "/verify"):
            # Browsers get the landing page (boundary table on the page itself);
            # API clients get the same data as JSON.
            if _accepts_html():
                await send_html(200, render_landing_page())
            else:
                await send_json(200, {"service": "stateless SCITT/COSE verifier", **CAPABILITIES})
            return
        if method != "POST" or path != "/verify":
            await send_json(404, {"error": "POST /verify"})
            return
        if not gate.allow():
            await send_json(429, dict(_RATE_LIMITED))
            return

        # Read (and cap) the request body; nothing is retained beyond this scope.
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if len(body) > 1_000_000:
                await send_json(413, {"valid": False, "reasons": ["request too large"]})
                return
            if not message.get("more_body", False):
                break

        verdict = verify_request_bytes(body)
        await send_json(400 if verdict.get("bad_request") else 200, verdict)

    return app


def serve(host: str = "127.0.0.1", port: int = 8080):  # pragma: no cover - demo only
    """Run the stateless verifier locally. NOT a deployment entry point.

    Deployment is intentionally out of scope for this pass — see
    ``docs/hosted-verifier-design.md`` for the proposed shape.
    """
    from http.server import HTTPServer

    httpd = HTTPServer((host, port), make_handler())
    print(f"stateless SCITT/COSE verifier on http://{host}:{port}  (read-only, retains nothing)")
    httpd.serve_forever()


__all__ = [
    "ATTRIBUTION",
    "SECURITY_HEADERS",
    "BOUNDARY_TABLE",
    "CAPABILITIES",
    "PRIVACY",
    "REPO_URL",
    "SUMMARY",
    "render_landing_page",
    "verify_payload",
    "verify_request_bytes",
    "make_handler",
    "make_asgi_app",
    "serve",
]
