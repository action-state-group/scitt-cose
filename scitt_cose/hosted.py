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


#: Security headers on every response, both wrappers. JS is externalized to
#: /static/verify.js (script-src 'self'); the interactive form POSTs same-origin
#: only (connect-src 'self', form-action 'self'). No unsafe-inline scripts,
#: no external resources, no framing. Inline CSS is the only relaxation.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    (
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; connect-src 'self'; "
        "style-src 'unsafe-inline'; img-src 'none'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ),
    ("Referrer-Policy", "no-referrer"),
)


# ---------------------------------------------------------------------------
# Page assets — separated from the f-string template so CSS braces don't need
# escaping (Python reads these as plain string values, not format slots).
# ---------------------------------------------------------------------------

#: Interactive widget CSS — stored as a plain string so the f-string template
#: can inject it with {_PAGE_CSS} without doubling every CSS brace.
_PAGE_CSS = """
  :root{
    --ink:#0B0E14; --ink-2:#161B25; --paper:#FCFCFA; --paper-2:#F4F4F0;
    --line:#E3E3DC; --line-2:#2A313F;
    --muted:#5C6573; --muted-2:#9AA3B2;
    --accent:#3A5BD9; --accent-soft:#EAEEFC;
    --pass:#127A52; --pass-soft:#E6F2EC;
    --fail:#B3261E; --fail-soft:#FBEAE8;
    --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  }
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:system-ui,sans-serif;background:var(--paper);color:var(--ink);line-height:1.6;-webkit-font-smoothing:antialiased}
  a{color:inherit}
  .wrap{max-width:980px;margin:0 auto;padding:0 32px}
  .mono{font-family:var(--mono)}

  nav{border-bottom:1px solid var(--line)}
  .nav-in{max-width:980px;margin:0 auto;padding:14px 32px;display:flex;align-items:center;justify-content:space-between}
  .brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:15px;letter-spacing:-0.2px}
  .brand .glyph{width:22px;height:22px;border:1.5px solid var(--ink);border-radius:5px;position:relative;flex-shrink:0}
  .brand .glyph::after{content:'';position:absolute;inset:4px;border-left:1.5px solid var(--accent);border-bottom:1.5px solid var(--accent);transform:rotate(-45deg) translate(1px,-1px)}
  .brand .svc{font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:1px;text-transform:uppercase;color:var(--muted);border-left:1px solid var(--line);padding-left:10px;margin-left:2px}
  .nav-links{display:flex;gap:22px;align-items:center}
  .nav-links a{font-size:13.5px;color:var(--muted);text-decoration:none}
  .nav-links a:hover{color:var(--ink)}

  .hero{padding:46px 0 26px}
  .pill{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:var(--pass);background:var(--pass-soft);padding:6px 13px;border-radius:100px;margin-bottom:18px}
  .hero h1{font-size:clamp(26px,3.6vw,38px);letter-spacing:-1px;font-weight:700;line-height:1.12;max-width:22ch;margin-bottom:14px}
  .hero p{font-size:16.5px;color:var(--muted);max-width:64ch}

  .tool{border:1px solid var(--line);border-radius:16px;background:#fff;overflow:hidden;margin:28px 0 8px;box-shadow:0 2px 18px rgba(11,14,20,.04)}
  .tool-head{display:flex;border-bottom:1px solid var(--line)}
  .tab{flex:1;padding:14px 18px;font-size:13.5px;font-weight:500;color:var(--muted);background:var(--paper-2);border:none;cursor:pointer;border-right:1px solid var(--line);font-family:inherit;transition:all .15s}
  .tab:last-child{border-right:none}
  .tab.active{background:#fff;color:var(--ink);box-shadow:inset 0 -2px 0 var(--accent)}
  .tool-body{padding:24px}
  .panel{display:none;flex-direction:column;gap:16px}
  .panel.active{display:flex}
  .field label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
  .field label .opt{font-weight:400;color:var(--muted-2);font-family:var(--mono);font-size:11px;margin-left:6px}
  .field .hint{font-size:12px;color:var(--muted);margin-top:5px}
  textarea{width:100%;min-height:84px;resize:vertical;font-family:var(--mono);font-size:12.5px;line-height:1.5;color:var(--ink);background:var(--paper);border:1px solid var(--line);border-radius:9px;padding:11px 13px;outline:none;transition:border-color .15s}
  textarea:focus{border-color:var(--accent)}
  textarea::placeholder{color:var(--muted-2)}
  .filerow{display:flex;align-items:center;gap:10px;margin-top:7px}
  .fbtn{font-family:var(--mono);font-size:12px;border:1px solid var(--line);background:#fff;border-radius:7px;padding:6px 12px;cursor:pointer;color:var(--ink)}
  .fbtn:hover{border-color:var(--ink)}
  .fname{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .actions{display:flex;align-items:center;gap:14px;margin-top:4px}
  .verify-btn{display:inline-flex;align-items:center;gap:9px;background:var(--ink);color:var(--paper);border:none;font-size:14.5px;font-weight:600;font-family:inherit;padding:13px 26px;border-radius:10px;cursor:pointer;transition:background .15s}
  .verify-btn:hover{background:var(--accent)}
  .verify-btn:disabled{opacity:.55;cursor:default}
  .clear-btn{font-size:13px;color:var(--muted);background:none;border:none;cursor:pointer;font-family:inherit;text-decoration:underline;text-underline-offset:2px}

  .verdict{display:none;margin-top:20px;border-radius:14px;overflow:hidden;border:1px solid var(--line)}
  .verdict.show{display:block}
  .vhead{padding:18px 22px;display:flex;align-items:center;gap:14px}
  .vhead .badge{font-family:var(--mono);font-weight:600;font-size:13px;letter-spacing:.5px;padding:7px 15px;border-radius:8px}
  .vhead .vtext{font-size:15px;font-weight:600}
  .verdict.ok .vhead{background:var(--pass-soft)} .verdict.ok .badge{background:var(--pass);color:#fff} .verdict.ok .vtext{color:var(--pass)}
  .verdict.no .vhead{background:var(--fail-soft)} .verdict.no .badge{background:var(--fail);color:#fff} .verdict.no .vtext{color:var(--fail)}
  .verdict.err .vhead{background:var(--paper-2)} .verdict.err .badge{background:var(--muted);color:#fff} .verdict.err .vtext{color:var(--muted)}
  .vbody{padding:8px 22px 20px;background:#fff}
  .vcard{border-top:1px solid var(--line);padding:16px 0}
  .vcard:first-child{border-top:none}
  .vcard h4{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:10px}
  .kv{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;font-size:13px}
  .kv dt{color:var(--muted);font-family:var(--mono);font-size:12px}
  .kv dd{font-family:var(--mono);font-size:12.5px;word-break:break-all}
  .kv dd.t{color:var(--pass);font-weight:600} .kv dd.f{color:var(--fail);font-weight:600}
  .reasons{list-style:none;display:flex;flex-direction:column;gap:7px}
  .reasons li{font-size:13px;color:var(--ink);padding-left:18px;position:relative;font-family:var(--mono)}
  .reasons li::before{content:'!';position:absolute;left:0;color:var(--fail);font-weight:700}
  .verdict.ok .reasons li::before{content:'✓';color:var(--pass)}

  section.band{padding:48px 0;border-top:1px solid var(--line)}
  .sec-eyebrow{font-family:var(--mono);font-size:12px;font-weight:500;letter-spacing:1.5px;text-transform:uppercase;color:var(--accent);margin-bottom:12px}
  .sec-title{font-size:21px;font-weight:700;letter-spacing:-0.4px;margin-bottom:18px}
  table.boundary{border-collapse:collapse;width:100%;font-size:13.5px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
  table.boundary th,table.boundary td{padding:11px 14px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
  table.boundary thead th{font-family:var(--mono);font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);background:var(--paper-2)}
  table.boundary tbody th{font-weight:600;white-space:nowrap;width:160px}
  table.boundary tbody td{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
  table.boundary tr:last-child th,table.boundary tr:last-child td{border-bottom:none}
  .twocol{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:6px}
  .lst h5{font-size:13px;font-weight:600;margin-bottom:10px}
  .lst ul{list-style:none;display:flex;flex-direction:column;gap:8px}
  .lst li{font-size:13.5px;color:var(--muted);padding-left:18px;position:relative}
  .lst.does li::before{content:'+';position:absolute;left:0;color:var(--pass);font-weight:700}
  .lst.dont li::before{content:'–';position:absolute;left:0;color:var(--muted-2);font-weight:700}
  .note{background:var(--paper-2);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:8px;padding:14px 18px;font-size:14px;color:var(--ink);margin-top:6px}
  .note code{font-family:var(--mono);font-size:12.5px;background:#fff;border:1px solid var(--line);border-radius:5px;padding:1px 6px}
  .privacy-lst{list-style:none;display:flex;flex-direction:column;gap:8px;margin-top:10px}
  .privacy-lst li{font-size:13px;color:var(--muted);padding-left:18px;position:relative;font-family:var(--mono)}
  .privacy-lst li::before{content:'+';position:absolute;left:0;color:var(--pass);font-weight:700}

  footer{padding:36px 0 50px}
  .foot-in{display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap;align-items:center}
  .foot-links{display:flex;gap:22px;flex-wrap:wrap}
  .foot-links a{font-size:13px;color:var(--muted);text-decoration:none;font-family:var(--mono)}
  .foot-links a:hover{color:var(--ink)}
  .foot-note{font-family:var(--mono);font-size:12px;color:var(--muted-2);margin-top:16px}

  @media(max-width:780px){
    .twocol{grid-template-columns:1fr}
    .kv{grid-template-columns:1fr}
    .kv dt{margin-top:6px}
    .nav-links a:not(:last-child){display:none}
  }
"""

#: The interactive widget JavaScript — externalized so script-src 'self' holds
#: without unsafe-inline. Served at GET /static/verify.js.
VERIFY_JS = """\
(function(){
  "use strict";
  var ENDPOINT = "/verify";

  function $(id){ return document.getElementById(id); }

  var tabs = document.querySelectorAll(".tab");
  tabs.forEach(function(t){
    t.addEventListener("click", function(){
      tabs.forEach(function(x){ x.classList.remove("active"); });
      document.querySelectorAll(".panel").forEach(function(p){ p.classList.remove("active"); });
      t.classList.add("active");
      $(t.getAttribute("data-panel")).classList.add("active");
    });
  });

  document.querySelectorAll(".fbtn").forEach(function(btn){
    btn.addEventListener("click", function(){
      var target = btn.getAttribute("data-target");
      var input = document.createElement("input");
      input.type = "file";
      input.accept = ".cose,.cbor,application/cose,application/octet-stream";
      input.addEventListener("change", function(){
        var file = input.files && input.files[0];
        if(!file) return;
        var reader = new FileReader();
        reader.onload = function(){
          var bytes = new Uint8Array(reader.result);
          var bin = "";
          for(var i=0;i<bytes.length;i++){ bin += String.fromCharCode(bytes[i]); }
          $(target).value = btoa(bin);
          $("fn-"+target).textContent = file.name + " (" + bytes.length + " bytes)";
        };
        reader.readAsArrayBuffer(file);
      });
      input.click();
    });
  });

  function val(id){ var el=$(id); return el && el.value.trim() ? el.value.trim() : null; }

  function row(dt, dd, cls){
    var safe = (dd===null||dd===undefined) ? "\\u2014" : String(dd);
    return "<dt>"+dt+"</dt><dd"+(cls?(' class="'+cls+'"'):"")+">"+
      safe.replace(/&/g,"&amp;").replace(/</g,"&lt;")+"</dd>";
  }

  function render(v){
    var verdict=$("verdict"), badge=$("vbadge"), text=$("vtext"), body=$("vbody");
    verdict.classList.remove("ok","no","err");
    var html = "";
    if(v.__transport){
      verdict.classList.add("err"); badge.textContent="ERROR"; text.textContent=v.__transport;
      body.innerHTML="<div class='vcard'><p style='font-size:13px;color:var(--muted)'>The verifier could not be reached. Locally, serve the page from the verifier or run <code class='mono'>scitt-cose</code> directly.</p></div>";
      verdict.classList.add("show"); return;
    }
    if(v.valid){verdict.classList.add("ok");badge.textContent="VALID";text.textContent="Everything submitted verified.";}
    else{verdict.classList.add("no");badge.textContent="INVALID";text.textContent="Did not verify \\u2014 see reasons below.";}
    if(v.statement){
      var s=v.statement, sv=s.signature_verified;
      html+="<div class='vcard'><h4>Signed statement</h4><dl class='kv'>"
        +row("issuer",s.issuer)+row("subject",s.subject)
        +row("content_type",s.content_type)+row("alg",s.alg)
        +row("signature",sv===true?"verified":(sv===false?"NOT verified":"not checked"),sv===true?"t":(sv===false?"f":""))
        +row("payload_len",s.payload_len)+"</dl></div>";
    }
    if(v.receipt){
      var r=v.receipt;
      html+="<div class='vcard'><h4>Receipt \\u00b7 inclusion proof</h4><dl class='kv'>"
        +row("inclusion",r.ok===true?"verified":"NOT verified",r.ok===true?"t":"f")
        +row("root",r.root)+row("tree_size",r.tree_size)+row("leaf_index",r.leaf_index)
        +"</dl></div>";
    }
    var reasons=(v.reasons||[]);
    if(reasons.length){
      html+="<div class='vcard'><h4>"+(v.valid?"Notes":"Reasons")+"</h4><ul class='reasons'>"
        +reasons.map(function(x){return "<li>"+String(x).replace(/&/g,"&amp;").replace(/</g,"&lt;")+"</li>";}).join("")
        +"</ul></div>";
    }
    body.innerHTML=html||"<div class='vcard'><p style='font-size:13px;color:var(--muted)'>No detail returned.</p></div>";
    verdict.classList.add("show");
  }

  $("verifyBtn").addEventListener("click", function(){
    var payload={};
    [["statement_b64","statement_b64"],["statement_pubkey_pem","statement_pubkey_pem"],
     ["receipt_b64","receipt_b64"],["log_pubkey_pem","log_pubkey_pem"],
     ["leaf_entry_hex","leaf_entry_hex"]].forEach(function(p){
       var v=val(p[1]); if(v!==null) payload[p[0]]=v;
     });
    if(!payload.statement_b64 && !payload.receipt_b64){
      render({valid:false,reasons:["Supply at least one of: a signed statement, or a receipt."]});
      return;
    }
    var btn=$("verifyBtn"); btn.disabled=true; var old=btn.innerHTML; btn.innerHTML="Verifying\\u2026";
    fetch(ENDPOINT,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)})
      .then(function(res){return res.json();})
      .then(function(v){render(v);})
      .catch(function(){render({__transport:"Could not reach the verifier."});})
      .finally(function(){btn.disabled=false;btn.innerHTML=old;});
  });

  $("clearBtn").addEventListener("click", function(){
    ["statement_b64","statement_pubkey_pem","receipt_b64","log_pubkey_pem","leaf_entry_hex"].forEach(function(id){$(id).value="";});
    document.querySelectorAll(".fname").forEach(function(f){f.textContent="";});
    $("verdict").classList.remove("show");
  });
})();
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_landing_page() -> str:
    """The human-facing landing page (``GET /`` with ``Accept: text/html``).

    Interactive verify widget: tabbed receipt / statement panels, file-to-base64
    upload, same-origin POST /verify, verdict rendering. JS is served separately
    at /static/verify.js (script-src 'self'; no unsafe-inline). Sections are
    data-driven from the same Python constants the JSON capabilities response
    carries — the page and the API cannot drift apart. Boundary table, privacy
    posture, and "verify locally" honesty are all on the page, not in docs.
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
    draft = _esc(DRAFT_TRACKING_NOTICE)
    summary = _esc(SUMMARY)
    repo = _esc(REPO_URL)
    operated_by = _esc(ATTRIBUTION["operated_by"])
    license_ = _esc(ATTRIBUTION["license"])
    foundation = _esc(ATTRIBUTION["foundation_intent"])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SCITT/COSE Verifier — verify a receipt or signed statement, stateless</title>
<meta name="description" content="A free, stateless verifier for SCITT receipts and signed statements. Paste or upload a receipt or signed statement, get valid/invalid + reasons. Nothing is stored. It verifies; it issues nothing.">
<style>
{_PAGE_CSS}
</style>
</head>
<body>

<nav>
  <div class="nav-in">
    <div class="brand"><span class="glyph"></span> SCITT/COSE <span class="svc">Verifier</span></div>
    <div class="nav-links">
      <a href="#how">How it works</a>
      <a href="https://agentactioncapsule.org">The standard ↗</a>
      <a href="https://anchor.agentactioncapsule.org">Transparency log ↗</a>
      <a href="{repo}">Source ↗</a>
    </div>
  </div>
</nav>

<header class="hero">
  <div class="wrap">
    <div class="pill">Stateless · nothing stored · verifies nothing on faith</div>
    <h1>Verify a SCITT receipt or signed statement.</h1>
    <p>{summary} Your bytes are verified in memory and discarded — nothing is stored or logged.</p>

    <div class="tool">
      <div class="tool-head">
        <button class="tab active" data-panel="p-receipt">Verify a receipt</button>
        <button class="tab" data-panel="p-statement">Verify a signed statement</button>
      </div>
      <div class="tool-body">

        <div class="panel active" id="p-receipt">
          <div class="field">
            <label>COSE Receipt <span class="opt">base64</span></label>
            <textarea id="receipt_b64" placeholder="base64 of the COSE receipt the log returned…"></textarea>
            <div class="filerow"><button class="fbtn" data-target="receipt_b64">Upload .cose…</button><span class="fname" id="fn-receipt_b64"></span></div>
          </div>
          <div class="field">
            <label>Log public key <span class="opt">PEM</span></label>
            <textarea id="log_pubkey_pem" placeholder="-----BEGIN PUBLIC KEY-----&#10;…the transparency log’s public key…&#10;-----END PUBLIC KEY-----"></textarea>
            <div class="hint">From the log’s <code class="mono">/.well-known/did.json</code>. Required to verify a receipt.</div>
          </div>
          <div class="field">
            <label>Leaf entry <span class="opt">hex</span></label>
            <textarea id="leaf_entry_hex" style="min-height:48px" placeholder="hex of the leaf digest the receipt proves (SHA-256 of the statement bytes)"></textarea>
          </div>
        </div>

        <div class="panel" id="p-statement">
          <div class="field">
            <label>Signed Statement <span class="opt">base64</span></label>
            <textarea id="statement_b64" placeholder="base64 of the COSE_Sign1 signed statement…"></textarea>
            <div class="filerow"><button class="fbtn" data-target="statement_b64">Upload .cose…</button><span class="fname" id="fn-statement_b64"></span></div>
          </div>
          <div class="field">
            <label>Statement public key <span class="opt">PEM · optional</span></label>
            <textarea id="statement_pubkey_pem" placeholder="-----BEGIN PUBLIC KEY-----&#10;…issuer’s public key, to check the signature…&#10;-----END PUBLIC KEY-----"></textarea>
            <div class="hint">Without a key the statement’s fields are reported but the signature is not checked (verdict stays invalid until a key verifies it).</div>
          </div>
        </div>

        <div class="actions">
          <button class="verify-btn" id="verifyBtn">Verify <span class="mono">→</span></button>
          <button class="clear-btn" id="clearBtn">Clear</button>
        </div>

        <div class="verdict" id="verdict">
          <div class="vhead"><span class="badge" id="vbadge">—</span><span class="vtext" id="vtext"></span></div>
          <div class="vbody" id="vbody"></div>
        </div>

      </div>
    </div>
    <p style="font-size:12.5px;color:var(--muted-2);font-family:var(--mono)">POST /verify · stateless · max 1 MB · the endpoint retains nothing but an anonymous request count.</p>
  </div>
</header>

<section class="band" id="how">
  <div class="wrap">
    <div class="sec-eyebrow">The boundary</div>
    <h2 class="sec-title">This is a verifier — NOT a Transparency Service.</h2>
    <table class="boundary">
      <thead><tr><th></th><th>This service · verifier</th><th>A Transparency Service · separate concern</th></tr></thead>
      <tbody>
{rows}
      </tbody>
    </table>
    <p style="font-size:14px;color:var(--muted);margin-top:14px">A verifier that starts storing submissions, issuing receipts, or anchoring has silently become a Transparency Service with all of its obligations. This one has no write path, no persistence, and no key custody — by construction. To run a real log, see <a href="https://anchor.agentactioncapsule.org" style="color:var(--accent)">the transparency service ↗</a>.</p>
  </div>
</section>

<section class="band">
  <div class="wrap">
    <div class="twocol">
      <div class="lst does">
        <h5>What it does</h5>
        <ul>
{does}
        </ul>
      </div>
      <div class="lst dont">
        <h5>What it does not do</h5>
        <ul>
{does_not}
        </ul>
      </div>
    </div>
    <div class="note"><strong>You don't need this service.</strong> The verifier is open source — <code>pip install scitt-cose</code> — and runs anywhere. This endpoint runs the identical library; the result is the same. For maximal privacy, verify locally: <a href="{repo}" style="color:var(--accent)">source ↗</a>.</div>
  </div>
</section>

<section class="band">
  <div class="wrap">
    <div class="sec-eyebrow">Privacy posture</div>
    <h2 class="sec-title">What this endpoint retains — and does not retain.</h2>
    <ul class="privacy-lst">
{privacy}
    </ul>
  </div>
</section>

<section class="band">
  <div class="wrap">
    <div class="sec-eyebrow">Standards status</div>
    <div class="note">{draft}</div>
  </div>
</section>

<footer>
  <div class="wrap">
    <div class="foot-in">
      <div class="brand"><span class="glyph"></span> SCITT/COSE <span class="svc">Verifier</span></div>
      <div class="foot-links">
        <a href="https://agentactioncapsule.org">The standard ↗</a>
        <a href="https://anchor.agentactioncapsule.org">Transparency log ↗</a>
        <a href="{repo}">scitt-cose ↗</a>
      </div>
    </div>
    <div class="foot-note">Stateless SCITT/COSE verifier · {license_} · operated by {operated_by} · {foundation}</div>
  </div>
</footer>

<script src="/static/verify.js"></script>
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

        def _send_js(self, code: int, content: str) -> None:
            body = content.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in SECURITY_HEADERS:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("/health", "/healthz"):
                self._send_json(200, {"ok": True})
            elif self.path == "/static/verify.js":
                self._send_js(200, VERIFY_JS)
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

        async def send_js(status: int, content: str) -> None:
            await send({
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/javascript; charset=utf-8"),
                    (b"cache-control", b"no-store"),
                    *sec_headers,
                ],
            })
            await send({"type": "http.response.body", "body": content.encode("utf-8")})

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
        if method == "GET" and path == "/static/verify.js":
            await send_js(200, VERIFY_JS)
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
    "VERIFY_JS",
    "render_landing_page",
    "verify_payload",
    "verify_request_bytes",
    "make_handler",
    "make_asgi_app",
    "serve",
]
