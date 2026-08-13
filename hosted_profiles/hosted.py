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

Dependencies: the ``scitt-cose`` library (``cbor2`` + ``cryptography``) plus
stdlib (``http.server``, ``json``, ``base64``). No web framework is required
for the stdlib path; ``make_asgi_app`` needs an ASGI host (e.g. uvicorn) to run.

This module lives in ``hosted_profiles/`` — a sibling of the ``scitt_cose``
package, deliberately excluded from the published wheel (see
``[tool.setuptools] packages`` in ``pyproject.toml``). The neutral, pip-
installable ``scitt-cose`` package carries no application-profile awareness and
no hosted-surface code; this file, and the AAC/MachineMandate renderers beside
it, exist only in a full repo checkout (the deployed hosted verify surface —
see the Dockerfile, which ``COPY . /app`` then runs this module directly). It
imports the neutral verifier through ``scitt_cose``'s public API, exactly as
any other downstream consumer would.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from scitt_cose._status import DRAFT_TRACKING_NOTICE
from scitt_cose.cose_sign1 import CoseError
from scitt_cose.receipt import verify_receipt
from scitt_cose.statement import parse_signed_statement

# machine_mandate.py is this module's sibling in hosted_profiles/; the
# try/except keeps this file degrading gracefully (stub renderer) if that
# sibling is ever absent, rather than failing the whole hosted surface.
try:
    from .machine_mandate import MM_RENDER_JS as _MM_RENDER_JS
except ImportError:
    _MM_RENDER_JS = (
        'function renderMachineMandate(data){'
        'var el=document.getElementById("graphContent");if(!el)return;'
        'el.innerHTML="<div style=\'color:var(--muted)\'>'
        'MachineMandate renderer not available in this deployment.</div>";'
        'document.getElementById("graphSection").style.display="block";'
        '}'
    )

#: One sentence, the whole offering. Served on the page and in the JSON.
SUMMARY = (
    "A free, stateless verification endpoint for SCITT receipts and signed "
    "statements (RFC9162_SHA256 vds=1 or CCF ccf.v1 vds=2). It verifies; it "
    "stores nothing; it issues nothing."
)

#: The open-source home of the verifier this endpoint runs. The ONLY external
#: link the landing page carries (plain <a href>, no fetched assets). Provisional
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
        "verify a COSE Receipt inclusion proof + log signature "
        "(RFC 9162 SHA-256 vds=1, or CCF ccf.v1 vds=2)",
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

  nav{position:sticky;top:0;z-index:50;background:rgba(252,252,250,0.9);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
  .nav-in{max-width:980px;margin:0 auto;padding:14px 32px;display:flex;align-items:center;justify-content:space-between;gap:18px}
  .brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:15px;letter-spacing:-0.2px;text-decoration:none;color:var(--ink)}
  .brand .glyph{width:22px;height:22px;border:1.5px solid var(--ink);border-radius:5px;position:relative;flex-shrink:0}
  .brand .glyph::after{content:'';position:absolute;inset:4px;border-left:1.5px solid var(--accent);border-bottom:1.5px solid var(--accent);transform:rotate(-45deg) translate(1px,-1px)}
  .brand .svc{font-family:var(--mono);font-size:11px;font-weight:500;letter-spacing:1px;text-transform:uppercase;color:var(--muted);border-left:1px solid var(--line);padding-left:10px;margin-left:2px}
  .nav-links{display:flex;gap:22px;align-items:center}
  .nav-links a{font-size:13.5px;color:var(--muted);text-decoration:none;transition:color .15s;white-space:nowrap}
  .nav-links a:hover{color:var(--ink)}
  .nav-links a.active{color:var(--ink);font-weight:600}
  .nav-ghost{font-family:var(--mono);font-size:13px;border:1px solid var(--line);padding:7px 14px;border-radius:7px;color:var(--ink)!important}
  .nav-ghost:hover{border-color:var(--ink)}

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

  footer{padding:48px 0 56px}
  .foot-in{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap;align-items:flex-start}
  .foot-brand{max-width:38ch}
  .foot-brand p{font-size:13px;color:var(--muted);margin-top:12px}
  .foot-cols{display:flex;gap:48px;flex-wrap:wrap}
  .foot-col h5{font-family:var(--mono);font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted-2);margin-bottom:14px}
  .foot-col a{display:block;font-size:13.5px;color:var(--muted);text-decoration:none;margin-bottom:9px}
  .foot-col a:hover{color:var(--ink)}
  .foot-note{margin-top:40px;padding-top:24px;border-top:1px solid var(--line);font-size:12.5px;color:var(--muted-2);font-family:var(--mono)}

  @media(max-width:780px){
    .twocol{grid-template-columns:1fr}
    .kv{grid-template-columns:1fr}
    .kv dt{margin-top:6px}
    .nav-in{gap:12px}
    .nav-links{gap:16px;overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}
    .nav-links::-webkit-scrollbar{display:none}
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


# ---------------------------------------------------------------------------
# AAC Capsule Verification Surface — P1
# ---------------------------------------------------------------------------

#: Live transparency service this surface queries for inclusion proofs.
_ANCHOR_BASE = "https://anchor.agentactioncapsule.org"

#: Same vocabulary as agent_action_capsule.history's inclusion-proof visibility
#: mapping. An inclusion response with no (or an unrecognised) visibility hint
#: is NOT covered here on purpose — the caller defaults that case to
#: "publicly-anchored" because _ANCHOR_BASE is itself a public transparency
#: service, unlike the library which has no such single-anchor context and so
#: defaults conservatively to "local-anchored" instead. See docs/ledger-grade.md §4.
_VISIBILITY_TO_RUNG = {
    "local": "local-anchored",
    "counterparty": "counterparty-visible",
    "public": "publicly-anchored",
}

#: Privacy-safe aggregate instrumentation — no content retention.
#: Counter is list so closure mutation works without ``nonlocal``.
_CAPSULE_VIEW_COUNTER: list[int] = [0]   # total capsule-page views
_REFERRER_COUNTER: dict[str, int] = {}   # eTLD+1 → view count

#: Publishable instrumentation policy stub (surfaced at /instrumentation-policy).
INSTRUMENTATION_POLICY = {
    "what_we_count": [
        "total capsule-page views (integer counter, resets on restart)",
        "distinct referrer eTLD+1 domain counts (e.g. 'github.com': 3)",
    ],
    "what_we_do_not_store": [
        "capsule content, digests, or payload",
        "IP addresses or user identifiers",
        "referrer paths or query strings — domain only",
    ],
    "retention": "in-memory only; resets on process restart; not persisted",
    "publishable": True,
}

#: Additional CSS for the capsule verification page (graph + privilege-log).
_CAPSULE_CSS = """
.anchor-banner{padding:12px 18px;border-radius:10px;font-size:13.5px;margin-bottom:20px;border:1px solid var(--line)}
.anchor-banner.anchor-ok{background:var(--pass-soft);border-color:var(--pass);color:var(--pass)}
.anchor-banner.anchor-none{background:var(--paper-2);color:var(--muted)}
.anchor-banner.anchor-offline{background:var(--paper-2);color:var(--muted);border-style:dashed}
.anchor-banner.anchor-loading{color:var(--muted);background:var(--paper-2)}
.anchor-banner.anchor-fail{background:var(--fail-soft);border-color:var(--fail);border-width:2px;color:var(--fail);font-weight:700}
.anchor-banner.rung-standalone{background:var(--paper-2);color:var(--muted)}
.anchor-banner.rung-countersigned{background:var(--paper-2);color:var(--muted)}
.anchor-banner.rung-local-anchored{background:var(--pass-soft);border-color:var(--pass);color:var(--pass)}
.anchor-banner.rung-counterparty-visible{background:var(--pass-soft);border-color:var(--pass);color:var(--pass)}
.anchor-banner.rung-publicly-anchored{background:var(--pass-soft);border-color:var(--pass);color:var(--pass)}
.anchor-ok{color:var(--pass);font-weight:700}
.anchor-offline{color:var(--muted);font-weight:600}
.anchor-none{color:var(--muted)}
.anchor-fail{color:var(--fail);font-weight:700}
.anchor-fail-detail{font-family:var(--mono);font-size:11.5px;color:var(--fail);margin-top:6px;word-break:break-all;font-weight:400}
.ritual-stages{border:1px solid var(--line);border-radius:12px;overflow:hidden}
.ritual-stage{display:flex;align-items:baseline;gap:10px;padding:10px 16px;border-bottom:1px solid var(--line);font-size:13px}
.ritual-stage:last-child{border-bottom:none}
.ritual-mark{width:16px;height:16px;border-radius:4px;display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0}
.ritual-pass .ritual-mark{background:var(--pass);color:#fff}
.ritual-fail .ritual-mark{background:var(--fail);color:#fff}
.ritual-skip .ritual-mark{background:transparent;border:1.5px solid var(--line);color:var(--muted-2)}
.ritual-name{font-weight:600;width:110px;flex-shrink:0}
.ritual-detail{color:var(--muted);font-weight:400}
.ritual-fail .ritual-detail{color:var(--fail)}
.finding-panel{margin-top:16px;border-radius:12px;padding:14px 18px;border:1px solid var(--line)}
.finding-panel.finding-fail{background:var(--fail-soft);border-color:var(--fail)}
.finding-panel.finding-gap{background:var(--fail-soft);border-color:var(--fail)}
.finding-panel.finding-summary{background:transparent;border-color:var(--line)}
.finding-summary .finding-label{color:var(--muted)}
.finding-label{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:1px;text-transform:uppercase;color:var(--fail);margin-bottom:6px}
.finding-text{font-size:13.5px;color:var(--ink);margin-bottom:6px}
.finding-meta{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.records-table{border-collapse:collapse;width:100%;font-size:12.5px}
.records-table th,.records-table td{padding:8px 10px;border:1px solid var(--line);text-align:left}
.records-table th{background:var(--paper-2);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.rec-row.rec-altered{background:var(--fail-soft)}
.rec-row.rec-flagged{background:rgba(179,38,30,0.03)}
.rec-row.rec-gap{background:var(--fail-soft);font-style:italic;color:var(--muted)}
.g-nodes{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:20px}
.gn{border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:200px;max-width:340px;background:#fff}
.gn-capsule{border-color:var(--accent);background:var(--accent-soft)}
.gn-offer_terms{border-color:var(--pass);background:var(--pass-soft)}
.gn-wicket_manifest{border-color:#f59e0b;background:#fffbeb}
.gn-opaque{border-style:dashed;opacity:.85}
.gn-type{display:block;font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.gn-digest{display:block;font-size:11px;word-break:break-all;color:var(--ink)}
.opaque-badge{font-size:10px;font-weight:700;letter-spacing:.5px;background:var(--muted);color:#fff;padding:1px 6px;border-radius:4px;vertical-align:middle}
.opaque-note{font-size:12px;color:var(--muted);margin-top:6px;font-style:normal}
.g-edges{margin-top:4px}
.etable{border-collapse:collapse;width:100%;font-size:12.5px;margin-bottom:20px}
.etable th,.etable td{padding:6px 10px;border:1px solid var(--line);text-align:left}
.etable th{background:var(--paper-2);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.etype{font-family:var(--mono);font-weight:600}
.etype-attests_over{color:var(--pass)}
.etype-chains_to{color:var(--accent)}
.etype-commits_to{color:#f59e0b}
.etype-effect_response{color:var(--muted)}
.pltable{border-collapse:collapse;width:100%;font-size:12.5px}
.pltable th,.pltable td{padding:7px 10px;border:1px solid var(--line);text-align:left;vertical-align:top}
.pltable th{background:var(--paper-2);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.pl-withheld{color:#f59e0b;font-weight:700;font-family:var(--mono);font-size:12px}
.pl-revealed{color:var(--pass);font-weight:600;font-family:var(--mono);font-size:12px}
.pl-match{color:var(--pass);font-weight:700;font-family:var(--mono);font-size:12px}
.pl-mismatch{color:var(--fail);font-weight:700;font-family:var(--mono);font-size:12px}
.pl-ctx{color:var(--muted);font-family:var(--mono);font-size:11px}
.pl-payload{max-width:340px}
.pl-payload-details summary{cursor:pointer;color:var(--muted);font-family:var(--mono);font-size:11.5px}
.pl-payload-details summary code{color:var(--ink)}
.pl-payload-full{margin-top:6px}
.pl-payload-full pre{white-space:pre-wrap;word-break:break-word;background:var(--paper-2);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:11.5px;max-height:280px;overflow:auto;margin:0}
.pl-payload-truncated{color:#f59e0b;font-size:11px;margin:6px 0 0}
.pl-payload-digests{display:flex;flex-direction:column;gap:2px;margin-top:6px;font-size:11px;color:var(--muted);font-family:var(--mono)}
.pl-payload-digests code{color:var(--ink)}
.chain-table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:16px}
.chain-table th,.chain-table td{padding:8px 12px;border:1px solid var(--line);text-align:left;vertical-align:middle}
.chain-table th{background:var(--paper-2);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.chain-table tr.chain-row{cursor:pointer}
.chain-table tr.chain-active td{background:var(--accent-soft);font-weight:600}
.chain-table tr.chain-row:hover td{background:var(--paper-2)}
.chain-nav-btns{display:flex;align-items:center;gap:16px;margin-top:12px}
.chain-pos{font-size:13px;color:var(--muted);flex:1;text-align:center}
.gn-capsule-prev .gn-digest{color:var(--accent);text-decoration:underline;cursor:pointer}
.reg-panel{margin:24px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.reg-panel summary{padding:14px 18px;cursor:pointer;font-size:14px;font-weight:600;background:var(--paper-2);list-style:none;display:flex;align-items:center;gap:10px;user-select:none}
.reg-panel summary::-webkit-details-marker{display:none}
.reg-panel summary::before{content:'▶';font-size:10px;color:var(--muted);transition:transform .15s;flex-shrink:0}
.reg-panel[open] summary::before{transform:rotate(90deg)}
.reg-panel-body{padding:16px 18px}
.reg-disclaimer{font-size:12.5px;color:var(--muted);font-style:italic;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.reg-table{border-collapse:collapse;width:100%;font-size:12.5px}
.reg-table th,.reg-table td{padding:8px 10px;border:1px solid var(--line);text-align:left;vertical-align:top}
.reg-table th{background:var(--paper-2);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.reg-prop{font-family:var(--mono);font-size:11px;background:var(--paper-2);border:1px solid var(--line);border-radius:4px;padding:1px 5px;white-space:nowrap;display:inline-block;margin-bottom:2px}
"""

#: JS for the capsule verification page (served at /static/capsule.js).
CAPSULE_JS = r"""
/* Agent Action Capsule — P1 verification surface client.
 * Profile plug-point: add entries to PROFILE_RENDERERS for new profiles.
 * Capsule JSON goes in the URL fragment (#base64) — never sent to this server.
 */
(function(){"use strict";
var capsuleId=document.body.getAttribute("data-capsule-id");
var _capsuleLoaded=false;
var _activeIntegrityPromise=Promise.resolve(null);
var KNOWN_TYPES={"capsule":1,"offer_terms":1,"wicket_manifest":1,"response":1,
  "gate_checks":1,"subject":1,"bilateral_subject":1,"compute_attestation":1,
  "agent_input":1,"agent_output":1};

/* ---------- capsule_id recompute (RFC 8785 JCS + SHA-256) ----------
 * Faithful port of agent-action-capsule's
 * python/agent_action_capsule/canonical.py (normalize / jcs / json_digest /
 * compute_capsule_id -- draft-mih-scitt-agent-action-capsule S2, S5.1). The
 * capsule JSON never leaves the browser (URL-fragment-only), so this is the
 * only place capsule_id<->body integrity is ever checked for what this page
 * actually renders. A capsule whose body does not hash to its own stated
 * capsule_id has been altered after the id was assigned; see
 * verifyCapsuleId, below, and its callers.
 * Known, accepted gap (matches upstream docs): a JSON float that happens to
 * be integer-valued (e.g. 1.0) parses in JS as the Number 1, indistinguishable
 * from the JSON integer 1 -- the reference Python implementation instead
 * rejects ANY float in a digest-bearing field (S5.1 forbids floats there
 * entirely), so a capsule that follows the spec never contains one. Out of scope here.
 * NOTE: this lives in the file's raw Python string segment deliberately --
 * everything after the _MM_RENDER_JS splice below is a NON-raw Python
 * string, which silently halves literal backslashes. Do not move this block
 * past that splice point. */
var CHAIN_LINKAGE_FIELDS={"capsule_id":1,"chain":1};

function CapsuleIdError(msg){this.message=msg;this.name="CapsuleIdError";}

function _capIdNormalize(v){
  if(Array.isArray(v))return v.map(_capIdNormalize);
  if(v&&typeof v==="object"){
    var out={};
    Object.keys(v).forEach(function(k){
      var nv=_capIdNormalize(v[k]);
      if(nv===null||nv===undefined)return;
      if(Array.isArray(nv)&&nv.length===0)return;
      if(nv&&typeof nv==="object"&&!Array.isArray(nv)&&Object.keys(nv).length===0)return;
      out[k]=nv;
    });
    return out;
  }
  return v;
}

function _capIdJcsString(s){
  var out=['"'];
  for(var ch of s){
    var o=ch.codePointAt(0);
    if(ch==='"')out.push('\\"');
    else if(ch==="\\")out.push("\\\\");
    else if(o===0x08)out.push("\\b");
    else if(o===0x09)out.push("\\t");
    else if(o===0x0A)out.push("\\n");
    else if(o===0x0C)out.push("\\f");
    else if(o===0x0D)out.push("\\r");
    else if(o<0x20)out.push("\\u"+o.toString(16).padStart(4,"0"));
    else out.push(ch);
  }
  out.push('"');
  return out.join("");
}

function _capIdJcsValue(v){
  if(v===null||v===undefined)return"null";
  if(v===true)return"true";
  if(v===false)return"false";
  if(typeof v==="string")return _capIdJcsString(v);
  if(typeof v==="number"){
    if(!Number.isInteger(v))throw new CapsuleIdError("float in digest-bearing field");
    if(v>Number.MAX_SAFE_INTEGER||v<-Number.MAX_SAFE_INTEGER)throw new CapsuleIdError("integer outside safe range");
    return String(v);
  }
  if(Array.isArray(v))return"["+v.map(_capIdJcsValue).join(",")+"]";
  if(typeof v==="object"){
    var keys=Object.keys(v).sort();
    return"{"+keys.map(function(k){return _capIdJcsString(k)+":"+_capIdJcsValue(v[k]);}).join(",")+"}";
  }
  throw new CapsuleIdError("value not JSON-serializable: "+typeof v);
}

async function _capIdSha256Hex(bytes){
  var buf=await crypto.subtle.digest("SHA-256",bytes);
  return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
}

async function computeCapsuleId(capsule){
  if(!capsule||typeof capsule!=="object"||Array.isArray(capsule))throw new CapsuleIdError("capsule must be a JSON object");
  var canonical={};
  Object.keys(capsule).forEach(function(k){if(!CHAIN_LINKAGE_FIELDS[k])canonical[k]=capsule[k];});
  var jcsStr=_capIdJcsValue(_capIdNormalize(canonical));
  return await _capIdSha256Hex(new TextEncoder().encode(jcsStr));
}

async function verifyCapsuleId(cap){
  var c=unwrapEnvelope(cap);
  var stated=(c&&c.capsule_id)||"";
  if(!isH64(stated))return{ok:null,stated:stated,recomputed:null};
  if(typeof crypto==="undefined"||!crypto.subtle)return{ok:null,stated:stated,recomputed:null};
  try{
    var recomputed=await computeCapsuleId(c);
    return{ok:recomputed===stated,stated:stated,recomputed:recomputed};
  }catch(ex){
    return{ok:false,stated:stated,recomputed:null,error:ex.message};
  }
}

/* ---------- profile renderers plug-point ---------- */
/* MachineMandate renderer inserted here — Tyche Institute vocabulary only.
 * Source: tyche-institute/machine-mandate@524e6a3. Not an endorsement. */
""" + _MM_RENDER_JS + """
var PROFILE_RENDERERS={"aac":renderAac,"machine-mandate":renderMachineMandate};

/* _mmIsPinnedAepOrEar: fixture-scoped detection for AEP/EAR types.
 * Generic eat_profile/action_hash shapes are NOT claimed (neutrality boundary:
 * those patterns would attribute third-party payloads to MachineMandate without
 * the profile owner's consent). Only these three exact pinned files are recognised.
 * Identified by unique field combinations that cannot match any other fixture.
 * Source: tyche-institute/machine-mandate@524e6a3 */
function _mmIsPinnedAepOrEar(d){
  /* demo.aep.json — nonce + action_id combination is unique to this file */
  if(d.nonce==="a9f3c21e88b04d17"&&d.action_id==="review-clause-4.3-gdpr-art22")return true;
  /* ear-A_good_fresh.json — eat_nonce unique to this file */
  if(d.eat_nonce==="jcw5yPcdEW_JM_QrRekL18i5FFjBFr2o-_txjW_AGO0=")return true;
  /* ear-B_outcome_swapped.json — eat_nonce unique to this file */
  if(d.eat_nonce==="aiWKHMeQ4uPUMkXwzlQjR5k6syZwgsWpwZEBQcPTsgo=")return true;
  return false;
}
function detectProfile(d){
  if(d&&(d.capsule_id||d.buyer_capsule||(d.capsule&&typeof d.capsule==="object"&&d.capsule.capsule_id)))return"aac";
  /* MachineMandate: owner-controlled VCT URI (run credential or mint record) */
  if(d&&d.vct==="https://vocab.tyche.institute/vct/machine-mandate")return"machine-mandate";
  /* MachineMandate: mint record has credential_claims.vct */
  if(d&&d.credential_claims&&d.credential_claims.vct==="https://vocab.tyche.institute/vct/machine-mandate")return"machine-mandate";
  /* MachineMandate: fixture-scoped AEP/EAR (exact pinned files only) */
  if(d&&_mmIsPinnedAepOrEar(d))return"machine-mandate";
  return"unknown";
}

/* ---------- helpers ---------- */
function isH64(s){return typeof s==="string"&&s.length===64&&/^[0-9a-f]+$/i.test(s);}
/* Disclosure Envelope unwrap: {"capsule":{...unmodified...},"disclosures":{...}} ->
 * the unmodified capsule. A bare capsule (no "capsule" wrapper key, or a
 * bilateral binding with buyer_capsule/seller_capsule) passes through unchanged. */
function unwrapEnvelope(item){return(item&&typeof item==="object"&&item.capsule&&typeof item.capsule==="object")?item.capsule:item;}
function sh(d){return d.slice(0,8)+"…"+d.slice(-4);}
function safe(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}

/* ---------- disclosed-payload rendering (shared helper — same canonicalization as
 * the digest recompute; see test_bundle_js_shared_helpers_match_capsule_js). The
 * bytes hashed against the committed digest and the bytes shown to the reader MUST
 * come from the same function -- a display that re-serializes by a different rule
 * than JSON.stringify(p, Object.keys(p).sort()) could show content that doesn't
 * match what was actually verified. */
var PAYLOAD_TRUNCATE_BYTES=8192;
function canonicalPayloadText(payload){
  return typeof payload==="string"?payload:JSON.stringify(payload,Object.keys(payload).sort());
}
function payloadPreview(payload){
  var t=canonicalPayloadText(payload);
  return t.length>80?t.slice(0,80)+"…":t;
}
function payloadCellHtml(entry,recomputedDigest){
  if(entry.withheld||entry._revPayload==null||entry.matchOk!==true)return"";
  var full=typeof entry._revPayload==="string"
    ?entry._revPayload
    :JSON.stringify(entry._revPayload,Object.keys(entry._revPayload).sort(),2);
  var bytes=new TextEncoder().encode(full);
  var truncated=bytes.length>PAYLOAD_TRUNCATE_BYTES;
  var shown=truncated?new TextDecoder("utf-8").decode(bytes.slice(0,PAYLOAD_TRUNCATE_BYTES)):full;
  var note=truncated?"<p class='pl-payload-truncated'>truncated for display, full payload is in the URL fragment</p>":"";
  return"<details class='pl-payload-details'><summary><code>"+safe(payloadPreview(entry._revPayload))+"</code></summary>"
    +"<div class='pl-payload-full'><pre>"+safe(shown)+"</pre>"+note
    +"<div class='pl-payload-digests'><div>committed <code>"+safe(entry.digest)+"</code></div>"
    +"<div>recomputed <code>"+safe(recomputedDigest||"")+"</code></div></div></div></details>";
}

function $(id){return document.getElementById(id);}

/* ---------- anchoring-evidence rung (docs/ledger-grade.md §4 twin) ----------
   Same five-value vocabulary as agent_action_capsule.history.RUNGS. This
   surface talks to ONE anchor and reports what IT sees at that anchor — it
   does not claim to know a capsule's full cross-party state (that is the
   library's job). "standalone" here means "not found at this anchor", not
   "no evidence exists anywhere". */
var RUNG_INFO={
  "standalone":{cls:"rung-standalone",innerCls:"anchor-none",label:"Standalone — not found at this anchor"},
  "countersigned":{cls:"rung-countersigned",innerCls:"anchor-none",label:"Countersigned — no transparency-service receipt at this anchor"},
  "local-anchored":{cls:"rung-local-anchored",innerCls:"anchor-ok",label:"Local-anchored"},
  "counterparty-visible":{cls:"rung-counterparty-visible",innerCls:"anchor-ok",label:"Counterparty-visible anchor"},
  "publicly-anchored":{cls:"rung-publicly-anchored",innerCls:"anchor-ok",label:"Publicly anchored"}
};
function rungInfo(rung){return RUNG_INFO[rung]||RUNG_INFO.standalone;}

/* ---------- AAC graph parser ---------- */
function parseAac(data){
  var nodes=[],edges=[],privlog=[],unk=[],seen={};
  var isB=!!(data.buyer_capsule&&data.seller_capsule);

  function addN(id,type,label,withheld,payload){
    if(seen[id])return false;seen[id]=true;
    var k=!!KNOWN_TYPES[type];
    if(!k&&unk.indexOf(type)<0)unk.push(type);
    nodes.push({id:id,type:type,label:label,digest:id,isKnown:k,withheld:withheld!==false,payload:payload||null});
    return true;
  }
  function addArt(digest,type,label,ctx){
    if(!isH64(digest)||!addN(digest,type,label,true,null))return;
    privlog.push({id:label,type:type,digest:digest,withheld:true,isKnown:!!KNOWN_TYPES[type],matchOk:null,ctx:ctx});
  }
  function addEdge(f,t,lbl){
    var k="_e_"+f+"_"+t+"_"+lbl;if(seen[k])return;seen[k]=true;
    edges.push({from:f,to:t,label:lbl});
  }
  /* disclosures: the Disclosure Envelope's out-of-band {agent_input, agent_output}
   * object for this capsule (draft-mih-scitt-agent-action-capsule-disclosure-envelope-00).
   * NEVER read from cap.model_attestation.compute_attestation — that region is
   * digest-committed, so embedding a payload there would change capsule_id. */
  function extractCap(cap,capId,pfx,disclosures){
    disclosures=disclosures||{};
    var p=pfx?pfx+".":"";
    var chain=cap.chain||{};
    var prior=chain.parent_capsule_id||"";
    if(isH64(prior)&&addN(prior,"capsule","prior capsule "+sh(prior),false,null))
      addEdge(capId,prior,"chains_to");
    var ma=cap.model_attestation||{},ca=ma.compute_attestation||{},subj=ca.subject_digest||"";
    if(isH64(subj)){addArt(subj,"subject","subject",p+"compute_attestation.subject_digest");addEdge(capId,subj,"attests_over");}
    var _actxW=p+"compute_attestation — payload not carried in the record";
    var _actxR="payload carried in fragment; recomputed against committed digest";
    var ai=ca.agent_input_digest||"",aiPre=disclosures.agent_input,aiRev=aiPre!=null;
    if(isH64(ai)&&addN(ai,"agent_input","agent input "+sh(ai),!aiRev,aiRev?aiPre:null)){
      privlog.push({id:"agent input",type:"agent_input",digest:ai,withheld:!aiRev,isKnown:true,matchOk:null,
                    ctx:aiRev?_actxR:_actxW,_revPayload:aiRev?aiPre:null});addEdge(capId,ai,"attests_over");}
    var ao=ca.agent_output_digest||"",aoPre=disclosures.agent_output,aoRev=aoPre!=null;
    if(isH64(ao)&&addN(ao,"agent_output","agent output "+sh(ao),!aoRev,aoRev?aoPre:null)){
      privlog.push({id:"agent output",type:"agent_output",digest:ao,withheld:!aoRev,isKnown:true,matchOk:null,
                    ctx:aoRev?_actxR:_actxW,_revPayload:aoRev?aoPre:null});addEdge(capId,ao,"attests_over");}
    var eff=cap.effect||{},resp=eff.response_digest||"";
    if(isH64(resp)){addArt(resp,"response","response",p+"effect.response_digest");addEdge(capId,resp,"effect_response");}
    (cap.constraints||[]).forEach(function(c){
      var ev=c.evidence_digest||"",cid=c.id||"constraint";
      if(isH64(ev)){addArt(ev,"wicket_manifest","manifest ["+cid+"]",p+"constraints["+cid+"].evidence_digest");addEdge(capId,ev,"commits_to");}
    });
  }

  if(isB){
    var bc=data.buyer_capsule||{},sc=data.seller_capsule||{};
    var bid=bc.capsule_id||"",sid=sc.capsule_id||"",sth=data.sealed_terms_hash||"",terms=data.terms;
    var bDisc=(data.disclosures&&data.disclosures.buyer)||{},sDisc=(data.disclosures&&data.disclosures.seller)||{};
    if(isH64(bid))addN(bid,"capsule","buyer capsule "+sh(bid),false,null);
    if(isH64(sid))addN(sid,"capsule","seller capsule "+sh(sid),false,null);
    if(isH64(sth)){
      var rev=terms!=null;
      addN(sth,"offer_terms","offer terms "+sh(sth),!rev,rev?terms:null);
      privlog.push({id:"sealed_terms_hash",type:"offer_terms",digest:sth,withheld:!rev,
                    isKnown:true,matchOk:null,ctx:"binding.sealed_terms_hash",_revPayload:rev?terms:null});
      if(isH64(bid))addEdge(bid,sth,"attests_over");
      if(isH64(sid))addEdge(sid,sth,"attests_over");
    }
    if(isH64(bid)&&isH64(sid))addEdge(sid,bid,"chains_to");
    if(isH64(bid))extractCap(bc,bid,"buyer",bDisc);
    if(isH64(sid))extractCap(sc,sid,"seller",sDisc);
  }else{
    /* Disclosure Envelope wrapper: {"capsule":{...unmodified...},"disclosures":{...}}.
     * A bare capsule (no "capsule" wrapper key) is the legacy/WITHHELD-only shape —
     * still fully supported, just with no disclosures to read. */
    var envCap=(data.capsule&&typeof data.capsule==="object")?data.capsule:data;
    var envDisc=(data.capsule&&typeof data.capsule==="object")?(data.disclosures||{}):{};
    var cid=envCap.capsule_id||"";
    if(isH64(cid)){addN(cid,"capsule","capsule "+sh(cid),false,null);extractCap(envCap,cid,"",envDisc);}
  }
  return{nodes:nodes,edges:edges,privlog:privlog,unk:unk,isB:isB};
}

/* ---------- renderers ---------- */
function renderGraph(g){
  var el=$("graphContent");if(!el)return;
  var h="<div class='g-nodes'><h4>Nodes ("+g.nodes.length+")</h4>";
  g.nodes.forEach(function(n){
    var cls="gn gn-"+n.type.replace(/[^a-z_]/g,"_")+(n.isKnown?"":(" gn-opaque"));
    h+="<div class='"+cls+"'>";
    h+="<span class='gn-type'>"+safe(n.type)+(n.isKnown?"":' <em class="opaque-badge">OPAQUE</em>')+"</span>";
    h+="<code class='gn-digest'>"+safe(n.digest)+"</code>";
    if(!n.isKnown)h+="<div class='opaque-note'>Unknown type — verified cryptographically; rendering opaque.</div>";
    h+="</div>";
  });
  h+="</div>";
  if(g.edges.length){
    h+="<div class='g-edges'><h4>Edges ("+g.edges.length+")</h4><table class='etable'><thead><tr><th>from</th><th>relation</th><th>to</th></tr></thead><tbody>";
    g.edges.forEach(function(e){
      h+="<tr><td><code>"+safe(e.from.slice(0,12))+"…</code></td>";
      h+="<td class='etype etype-"+safe(e.label)+"'>"+safe(e.label)+"</td>";
      h+="<td><code>"+safe(e.to.slice(0,12))+"…</code></td></tr>";
    });
    h+="</tbody></table></div>";
  }
  el.innerHTML=h;$("graphSection").style.display="block";
}

function renderPrivlog(g){
  var el=$("privlogContent");if(!el)return;
  var h="<table class='pltable'><thead><tr><th>artifact</th><th>type</th><th>digest</th><th>status</th><th>payload</th><th>context</th></tr></thead><tbody>";
  g.privlog.forEach(function(e){
    var st=e.withheld?"<span class='pl-withheld'>WITHHELD</span>":
            e.matchOk===true?"<span class='pl-match'>REVEALED · ✓ match</span>":
            e.matchOk===false?"<span class='pl-mismatch'>REVEALED · ✗ MISMATCH</span>":
            "<span class='pl-revealed'>REVEALED</span>";
    h+="<tr data-dig='"+safe(e.digest)+"'><td>"+safe(e.id)+"</td><td>"+safe(e.type)+(e.isKnown?"":' <em class="opaque-badge">OPAQUE</em>')+"</td>";
    h+="<td><code>"+safe(e.digest.slice(0,16))+"…</code></td><td class='pl-st'>"+st+"</td>";
    h+="<td class='pl-payload'>"+payloadCellHtml(e,null)+"</td><td class='pl-ctx'>"+safe(e.ctx)+"</td></tr>";
  });
  h+="</tbody></table>";
  if(g.unk.length)h+="<p class='opaque-note' style='margin-top:12px'>Unknown types (verified-but-opaque): "+g.unk.map(safe).join(", ")+"</p>";
  el.innerHTML=h;$("privlogSection").style.display="block";
  /* async SHA-256 recompute for revealed rows -- canonicalPayloadText is the SAME
   * helper payloadCellHtml (above) uses for display, so the bytes that get hashed
   * and the bytes that get shown can never diverge. e.matchOk is persisted here
   * (not just a local var) so the payload cell can gate on it once resolved. */
  if(crypto&&crypto.subtle){
    g.privlog.forEach(function(e){
      if(!e._revPayload||e.withheld)return;
      var _bytes=new TextEncoder().encode(canonicalPayloadText(e._revPayload));
      crypto.subtle.digest("SHA-256",_bytes).then(function(buf){
        var hex=Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
        e.matchOk=(hex===e.digest);
        var row=el.querySelector("tr[data-dig='"+e.digest+"']");
        if(!row)return;
        var stCell=row.querySelector("td.pl-st");
        if(stCell)stCell.innerHTML=e.matchOk?"<span class='pl-match'>REVEALED · ✓ match</span>":
                                       "<span class='pl-mismatch'>REVEALED · ✗ MISMATCH</span>";
        var payloadCell=row.querySelector("td.pl-payload");
        if(payloadCell)payloadCell.innerHTML=payloadCellHtml(e,hex);
      });
    });
  }
}

function renderAac(data){
  var g=parseAac(data);renderGraph(g);renderPrivlog(g);
}

/* ---------- regulatory-context panel ----------
 * Property-driven: rows appear only for structural properties detected in
 * the capsule or the anchor status.  No scores, no checkmarks.
 * Called from loadCapsule (initial, hasReceipt=false) and again after
 * anchor status resolves if the capsule is anchored.
 */
var REG_ROWS=[
  /* tamper-evident-log */
  ["EU AI Act Art 12(1)","Automatic logging capabilities for high-risk AI systems","tamper-evident-log"],
  ["EU AI Act Art 12(2)","Level of traceability appropriate to the system's purpose","tamper-evident-log"],
  ["DORA Art 9(4)","ICT security policies — logging and monitoring","tamper-evident-log"],
  ["DORA Art 10(1)-(2)","Detection of anomalous activity","tamper-evident-log"],
  ["DORA Art 17(3)(b)","ICT incident records","tamper-evident-log"],
  ["SEC Rule 17a-4(f)(2)(ii)(A)","Non-rewriteable, non-erasable electronic records","tamper-evident-log"],
  ["FINRA Rule 4511(c)","17a-4 format compliance","tamper-evident-log"],
  ["NSA CSI U/OO/6030316-26 (May 2026)","Structured audit records of all MCP tool interactions","tamper-evident-log"],
  ["ASD ACSC et al. (May 2026)","Comprehensive logging and audit trails for all agent actions and decisions","tamper-evident-log"],
  /* human-oversight-record */
  ["EU AI Act Art 50(2)/(3)","Notice and disclosure to persons subject to AI interaction","human-oversight-record"],
  ["MAS SAFR (Jul 2026)","Human oversight and decision review","human-oversight-record"],
  ["FCA AI accountability (FS23/5)","Transparency of AI decision-making","human-oversight-record"],
  ["NIST AI RMF MANAGE 1.3","High-priority risk response planning and documentation","human-oversight-record"],
  ["NSA CSI U/OO/6030316-26 (May 2026)","Approval workflows for agentic capability and data-access changes","human-oversight-record"],
  ["ASD ACSC et al. (May 2026)","Mandatory human approval for high-impact agentic decisions","human-oversight-record"],
  /* disclosure-transparency-record */
  ["EU AI Act Art 50(1)","Machine-readable AI-content marking","disclosure-transparency-record"],
  ["NIST AI RMF MEASURE 2.8","Transparency and accountability risks","disclosure-transparency-record"],
  ["prEN 18229-1","Transparency documentation requirements for AI systems","disclosure-transparency-record"],
  ["NSA CSI U/OO/6030316-26 (May 2026)","Filter and validate tool output before downstream consumption","disclosure-transparency-record"],
  ["ASD ACSC et al. (May 2026)","Trust classification of all external and tool-provided content","disclosure-transparency-record"],
  /* per-action-attribution — always shown */
  ["EU AI Act Art 26(6)","Deployer log retention","per-action-attribution"],
  ["DORA Art 17(3)(b)","ICT incident records — attribution","per-action-attribution"],
  ["NIST AI RMF GOVERN 1.1","Risk management policies and practices","per-action-attribution"],
  ["FCA AI accountability (FS23/5)","Accountability and audit trails","per-action-attribution"],
  ["NSA CSI U/OO/6030316-26 (May 2026)","Message signing, expiration timestamps, and replay-protection metadata","per-action-attribution"],
  ["ASD ACSC et al. (May 2026)","Cryptographically anchored per-agent identity and delegation chain traceability","per-action-attribution"]
];
var REG_CROSSWALK_URL="https://github.com/action-state-group/agent-action-capsule/blob/main/docs/regulatory-crosswalk.md";

var _regLastData=null;
var _regHasReceipt=false;

function renderRegPanel(data,hasReceipt){
  _regLastData=data;_regHasReceipt=hasReceipt;
  var sec=$("regPanelSection");var mount=$("regPanelMount");
  if(!sec||!mount)return;

  /* Disclosure Envelope unwrap: for a {"capsule":{...},"disclosures":{...}}
     fragment, disposition/model_attestation/sealed_terms_hash/etc. live at
     data.capsule.*, not at the top level — same unwrap parseAac already does
     for the graph/privilege-log path. Without this, every property detector
     below silently undercounts on a disclosed capsule (data is the envelope,
     not the capsule, so data.disposition is undefined even though the
     underlying capsule has one). */
  var envCap=unwrapEnvelope(data);

  /* detect properties from capsule data */
  var activeProps={"per-action-attribution":1};
  if(hasReceipt)activeProps["tamper-evident-log"]=1;
  /* human-oversight: disposition.human_disposed on any capsule (§5.4/5.5 —
     the flag lives INSIDE the disposition block, not at the capsule top level) */
  function checkHitl(cap){
    return cap&&cap.disposition&&(cap.disposition.human_disposed===true||cap.disposition.approver==="human");
  }
  if(checkHitl(envCap)||checkHitl(envCap&&envCap.buyer_capsule)||checkHitl(envCap&&envCap.seller_capsule))
    activeProps["human-oversight-record"]=1;
  /* disclosure: withheld_commitments or sealed_terms_hash with no terms */
  function checkSd(cap){
    var _ca=cap&&((cap.model_attestation||{}).compute_attestation)||{};
    return cap&&(cap.withheld_commitments
      ||(cap.constraints&&cap.constraints.some(function(c){return c.evidence_digest;}))
      ||isH64(_ca.agent_input_digest)||isH64(_ca.agent_output_digest));
  }
  if((envCap&&envCap.sealed_terms_hash&&!envCap.terms)||checkSd(envCap)||checkSd(envCap&&envCap.buyer_capsule)||checkSd(envCap&&envCap.seller_capsule))
    activeProps["disclosure-transparency-record"]=1;

  var propsShown=Object.keys(activeProps).sort().join(", ");
  var rows="";
  REG_ROWS.forEach(function(r){
    if(!activeProps[r[2]])return;
    rows+="<tr><td>"+safe(r[0])+"</td><td>"+safe(r[1])+"</td><td><span class='reg-prop'>"+safe(r[2])+"</span></td></tr>";
  });

  mount.innerHTML="<details class='reg-panel' id='regPanelDetails' open>"
    +"<summary>Regulatory context (informational) "
    +"<span style='font-weight:400;font-size:12px;color:var(--muted);margin-left:8px'>properties detected: "+safe(propsShown)+"</span></summary>"
    +"<div class='reg-panel-body'>"
    +"<p class='reg-disclaimer'>This panel identifies structural properties of this record. It is not legal advice. "
    +"Consult the <a href='"+safe(REG_CROSSWALK_URL)+"' target='_blank' rel='noopener noreferrer'>full crosswalk</a> for instrument citations and limits.</p>"
    +"<table class='reg-table'><thead><tr><th>Regulation / Article</th><th>Summary</th><th>Property</th></tr></thead>"
    +"<tbody>"+rows+"</tbody></table>"
    +"</div></details>";
  sec.style.display="block";
}

/* ---------- ritual evaluation (Integrity / Sequence / Authenticity / Witness) ----------
 * Mirrors scitt_cose/aac.py's find_chain_gaps / evaluate_ritual / annotate_records —
 * kept in JS because the capsule JSON never leaves the browser (fragment-only).
 * A record that fails a check by name; everything that still verifies keeps its
 * verdict. Unreachable is never rendered as disproven.
 */
var _bundleWitness=null;
var _fragData=null;

function _capMismatched(cap){
  var g=parseAac(cap);
  return g.privlog.some(function(e){return e.matchOk===false;});
}

function findChainGaps(capsules){
  /* Unwrap first: a Disclosure-Envelope-wrapped bundle item carries capsule_id
   * and chain nested under "capsule", not at the top level — without this,
   * every envelope-wrapped item is invisible to gap detection. */
  var caps=capsules.map(unwrapEnvelope);
  var ids={};
  caps.forEach(function(c){if(isH64(c.capsule_id))ids[c.capsule_id]=true;});
  var gaps=[];
  for(var i=1;i<caps.length;i++){
    var parent=((caps[i].chain)||{}).parent_capsule_id||"";
    if(isH64(parent)&&!ids[parent])gaps.push({beforeIdx:i-1,afterIdx:i,missingParent:parent});
  }
  return gaps;
}

function annotateRecords(capsules,integrity){
  /* Same unwrap as findChainGaps — _capMismatched still receives the raw
   * (possibly enveloped) item, since parseAac needs the sibling "disclosures"
   * key to check revealed-payload digests. */
  var caps=capsules.map(unwrapEnvelope);
  var alteredIds={};
  capsules.forEach(function(c,i){
    var cid=caps[i].capsule_id||"";
    if(!isH64(cid))return;
    var idr=integrity&&integrity[i];
    if((idr&&idr.ok===false)||_capMismatched(c))alteredIds[cid]=true;
  });
  var byId={};
  caps.forEach(function(c){if(isH64(c.capsule_id))byId[c.capsule_id]=c;});
  return caps.map(function(cap){
    var cid=cap.capsule_id||"";
    if(alteredIds[cid])return{note:"digest_mismatch",isAltered:true,citesAltered:false};
    var cites=false,seen={},cur=cap;
    while(true){
      var parent=((cur.chain)||{}).parent_capsule_id||"";
      if(!isH64(parent)||seen[parent])break;
      seen[parent]=true;
      if(alteredIds[parent]){cites=true;break;}
      cur=byId[parent];if(!cur)break;
    }
    return{note:cites?"cites an altered record":"verifies",isAltered:false,citesAltered:cites};
  });
}

/* Capsule bundles carry no COSE bytes by default (JSON in the URL fragment
 * only) and this page ships no client-side COSE verifier — that logic runs
 * server-side, at POST /verify. So Authenticity is honestly "not checked"
 * here rather than a fabricated pass; verifying an embedded signed statement
 * for real is scitt_cose.aac.evaluate_ritual's job (see tests). */
function checkAuthenticity(capsules){
  var has=capsules.some(function(c){return !!c.signed_statement;});
  if(!has)return{status:"skip",detail:"not checked — no signed statement provided for this bundle"};
  return{status:"skip",detail:"signed statement present — not verified in the browser; use the Verify a signed statement tool"};
}

function checkWitness(w,total){
  /* `total` is the number of records in this bundle. The anchor-status call
   * checks only the FOCAL capsule (the one named in the URL path), so
   * w.configured is the number CHECKED, not the number present. Reporting
   * "witnessed 1 of 1" inside a 2-record bundle read as full coverage when one
   * record had never been checked at all; the denominator now always names the
   * bundle, and partial coverage can never render as a pass. */
  if(!w)return{status:"skip",detail:"no witness data provided"};
  if(w.verified===false)return{status:"fail",detail:"inclusion proof did not verify"};
  if(w.reachable===false)return{status:"skip",detail:"independent-witness check skipped (unreachable) — everything else verified; reconnect any time to complete it"};
  var held=w.held||0;
  var checked=w.configured||0;
  var n=(typeof total==="number"&&total>0)?total:(checked||1);
  if(checked<n){
    return{status:"skip",
      detail:"witnessed "+held+" of "+n+" — only "+checked+" record"+(checked===1?"":"s")+" in this bundle "+(checked===1?"was":"were")+" checked against the log; the rest are unchecked, not unwitnessed"};
  }
  if(held<n)return{status:"skip",detail:"witnessed "+held+" of "+n+" · retrying — rung held"};
  return{status:"pass",detail:"witnessed "+held+" of "+n};
}


/* ---------- plain-language summary (renders on EVERY bundle) ----------
 * The ritual answers "does this verify". It does not answer "what happened",
 * and until now a clean bundle said almost nothing — four terse stage lines and
 * no prose. A stranger handed a permalink could see green checks without ever
 * learning what the records claim, or which claims carry weaker assurance.
 * This states, in English, what the records say AND what they don't establish.
 * It never asserts more than the fields carry. */
function describeBundle(capsules){
  var caps=capsules.map(unwrapEnvelope).filter(function(c){return c&&c.capsule_id;});
  if(!caps.length)return null;
  var n=caps.length,parts=[];

  var ts=caps.map(function(c){return c.timestamp;}).filter(Boolean).sort();
  var when=ts.length?(ts[0]===ts[ts.length-1]?("at "+ts[0]):("between "+ts[0]+" and "+ts[ts.length-1])):null;
  var ops={};caps.forEach(function(c){if(c.operator)ops[c.operator]=1;});
  var opNames=Object.keys(ops);
  parts.push(n+" record"+(n===1?"":"s")+(when?", "+when:"")
    +(opNames.length===1?", from operator “"+opNames[0]+"”":
      opNames.length>1?", from "+opNames.length+" operators":"")+".");

  var kinds={};caps.forEach(function(c){var t=c.action_type||"unspecified";kinds[t]=(kinds[t]||0)+1;});
  var kindBits=Object.keys(kinds).map(function(k){
    var label=k==="fyi"?"informational":k==="decide"?"decision":k==="act"?"action":k;
    return kinds[k]+" "+label+(kinds[k]===1?"":"s");
  });
  if(kindBits.length)parts.push(kindBits.join(", ")+".");

  var accepted=0,rejected=0,human=0;
  caps.forEach(function(c){
    var d=c.disposition||{};
    if(d.decision==="accept")accepted++;
    else if(d.decision==="reject"||d.decision==="deny")rejected++;
    if(d.human_disposed===true)human++;
  });
  if(rejected)parts.push(rejected+" of "+n+" "+(rejected===1?"was":"were")+" refused.");
  if(accepted===n&&n>0)parts.push("All were accepted.");
  parts.push(human===0
    ? "No human approved any of them — every disposition was made by policy."
    : human+" of "+n+" carried a recorded human disposition.");

  /* Assurance is the part a reader cannot infer and most needs. */
  var selfAtt=0,unconfirmed=0;
  caps.forEach(function(c){
    var a=c.assurance||{};
    if(a.attestation_mode==="self_attested")selfAtt++;
    if(a.effect_mode==="dispatched_unconfirmed")unconfirmed++;
  });
  if(unconfirmed)parts.push(unconfirmed+" record"+(unconfirmed===1?"":"s")+" report"+(unconfirmed===1?"s":"")
    +" the effect as dispatched but unconfirmed — the runtime says it sent the action; nothing here confirms it landed.");
  if(selfAtt===n&&n>0)parts.push("Every record is self-attested: the same party took the action and wrote the record.");

  var withheld=0;
  caps.forEach(function(c){
    var ca=((c.model_attestation||{}).compute_attestation)||{};
    if(ca.agent_input_digest||ca.agent_output_digest)withheld++;
  });
  if(withheld)parts.push("Inputs and outputs are committed as digests only — the payloads are not in "
    +(withheld===n?"these records":"all of these records")+", so their contents cannot be read here, only matched if someone later discloses them.");

  return{code:"summary",label:"What these records say",text:parts.join(" "),
    meta:"plain-language summary of the fields carried; it makes no claim the ritual did not check"};
}

function evaluateRitual(capsules,witness,integrity){
  var stages=[],finding=null;
  var alteredIds={},firstMismatch=null,firstMismatchIsBody=false;
  capsules.forEach(function(c,i){
    /* Unwrap for the capsule_id/alteration bookkeeping only — parseAac(c)
     * below still gets the raw (possibly enveloped) item, since it needs the
     * sibling "disclosures" key to check revealed-payload digests itself. */
    var cu=unwrapEnvelope(c);
    if(!isH64(cu.capsule_id))return;
    var idr=integrity&&integrity[i];
    if(idr&&idr.ok===false){
      alteredIds[cu.capsule_id]=true;
      if(!firstMismatch){firstMismatch=idr;firstMismatchIsBody=true;}
    }
    var g=parseAac(c);
    var bad=g.privlog.filter(function(e){return e.matchOk===false;});
    if(bad.length){alteredIds[cu.capsule_id]=true;if(!firstMismatch){firstMismatch=bad[0];firstMismatchIsBody=false;}}
  });
  if(Object.keys(alteredIds).length){
    if(firstMismatchIsBody){
      stages.push({name:"Integrity",status:"fail",
        detail:"capsule_id does not match the recomputed digest of its own body — stated "+sh(firstMismatch.stated)+", recomputed "+(firstMismatch.recomputed?sh(firstMismatch.recomputed):"(could not be computed)")});
      finding={code:"capsule_id_mismatch",label:"The finding",
        text:"This capsule's content does not hash to its stated capsule_id. The body has been altered after the id was assigned — they no longer content-address to each other.",
        meta:"failed stage: capsule_id_mismatch · stated capsule_id "+firstMismatch.stated+" · recomputed "+(firstMismatch.recomputed||"(error)")};
    }else{
      stages.push({name:"Integrity",status:"fail",
        detail:"record fails at stage digest_mismatch — "+firstMismatch.ctx+" no longer matches its fingerprint"});
      finding={code:"digest_mismatch",label:"The finding",
        text:firstMismatch.id+" ("+firstMismatch.ctx+") is not the value that was sealed.",
        meta:"failed stage: digest_mismatch · field group: "+firstMismatch.ctx+" · digest "+firstMismatch.digest.slice(0,8)+"…"};
    }
  }else{
    stages.push({name:"Integrity",status:"pass",detail:"every record matches its fingerprint"});
  }

  /* How many records actually declare a parent? findChainGaps only reports a
   * MISSING parent; a bundle where no record declares one at all produces zero
   * gaps, which previously rendered as "unbroken — every record names the one
   * before it". That sentence asserts a property nothing checked, and it made a
   * completely unchained bundle indistinguishable from a fully chained one.
   * Sequence is now three-valued: not-declared / partial / unbroken. */
  var _capsForSeq=capsules.map(unwrapEnvelope);
  var _declared=0;
  _capsForSeq.forEach(function(c){
    if(isH64(((c.chain)||{}).parent_capsule_id||""))_declared++;
  });
  var _expectedLinks=Math.max(0,_capsForSeq.length-1);

  var gaps=findChainGaps(capsules);
  if(_capsForSeq.length<2){
    stages.push({name:"Sequence",status:"skip",
      detail:"single record — nothing to sequence"});
  }else if(_declared===0){
    stages.push({name:"Sequence",status:"skip",
      detail:"not checked — no record here declares a parent, so the order shown is presentation order, not an attested sequence"});
    if(!finding){
      finding={code:"no_chain_declared",label:"What this does not show",
        text:"These "+_capsForSeq.length+" records carry no chain links. Nothing here attests that they happened in this order, or that none is missing between them — they are individually verifiable records displayed in the order the bundle listed them.",
        meta:"skipped stage: no_chain_declared · 0 of "+_expectedLinks+" expected links declared"};
    }
  }else if(gaps.length){
    var g0=gaps[0];
    var beforeId=(capsules[g0.beforeIdx]||{}).capsule_id||"",afterId=(capsules[g0.afterIdx]||{}).capsule_id||"";
    stages.push({name:"Sequence",status:"fail",
      detail:"gap between record "+(g0.beforeIdx+1)+" and record "+(g0.afterIdx+1)+" — record "+(g0.afterIdx+1)+" names a parent that is not here"});
    if(!finding){
      finding={code:"chain_gap",label:"The finding",
        text:"Whatever sits between record "+(g0.beforeIdx+1)+" and record "+(g0.afterIdx+1)+" is not in this bundle. That is information, not just an error: the gap has a location and two edges you can browse from.",
        meta:"failed stage: chain_gap · window: "+beforeId.slice(0,8)+"…→"+afterId.slice(0,8)+"… · missing parent "+g0.missingParent.slice(0,8)+"…"};
    }
  }else if(_declared<_expectedLinks){
    stages.push({name:"Sequence",status:"skip",
      detail:"partial — "+_declared+" of "+_expectedLinks+" expected links declared; the undeclared positions are not attested as adjacent"});
  }else{
    stages.push({name:"Sequence",status:"pass",detail:"unbroken — every record names the one before it"});
  }

  var auth=checkAuthenticity(capsules);
  stages.push({name:"Authenticity",status:auth.status,detail:auth.detail});
  var wit=checkWitness(witness,capsules.length);
  stages.push({name:"Witness",status:wit.status,detail:wit.detail});

  return{stages:stages,finding:finding,summary:describeBundle(capsules)};
}

async function renderRitual(bundle,witness){
  var mount=$("ritualMount");if(!mount||!bundle||!bundle.length)return;
  var integrity=null;
  if(typeof crypto!=="undefined"&&crypto.subtle){
    integrity=await Promise.all(bundle.map(verifyCapsuleId));
  }
  var summary=evaluateRitual(bundle,witness,integrity);
  var marks={pass:"✓",fail:"✕",skip:"–"};
  var h="<div class='ritual-stages'>";
  summary.stages.forEach(function(s){
    h+="<div class='ritual-stage ritual-"+s.status+"'><span class='ritual-mark'>"+marks[s.status]+"</span>"
      +"<span class='ritual-name'>"+safe(s.name)+"</span><span class='ritual-detail'>"+safe(s.detail)+"</span></div>";
  });
  h+="</div>";
  if(summary.summary){
    var sm=summary.summary;
    h+="<div class='finding-panel finding-summary'>"
      +"<div class='finding-label'>"+safe(sm.label)+"</div>"
      +"<p class='finding-text'>"+safe(sm.text)+"</p>"
      +"<div class='finding-meta'>"+safe(sm.meta)+"</div></div>";
  }
  if(summary.finding){
    var f=summary.finding;
    h+="<div class='finding-panel finding-"+(f.code==="chain_gap"?"gap":f.code==="no_chain_declared"?"gap":"fail")+"'>"
      +"<div class='finding-label'>"+safe(f.label)+"</div>"
      +"<p class='finding-text'>"+safe(f.text)+"</p>"
      +"<div class='finding-meta'>"+safe(f.meta)+"</div></div>";
  }
  var gaps=findChainGaps(bundle),gapAt={};
  gaps.forEach(function(g){gapAt[g.afterIdx]=g;});
  var notes=annotateRecords(bundle,integrity);
  var rh="<table class='records-table'><thead><tr><th>#</th><th>record</th><th>note</th></tr></thead><tbody>";
  bundle.forEach(function(cap,i){
    if(gapAt[i]){
      var gp=gapAt[i];
      rh+="<tr class='rec-row rec-gap'><td>—</td><td>gap — record "+(gp.beforeIdx+1)+" → record "+(i+1)+", missing parent <code>"+safe(gp.missingParent.slice(0,8))+"…</code></td><td>⌗ chain_gap</td></tr>";
    }
    var n=notes[i],s=_capSummary(cap);
    var noteText=n.note==="digest_mismatch"?"✕ digest_mismatch"
      :n.note==="cites an altered record"?"✓ verifies · cites an altered record"
      :"✓ verifies";
    rh+="<tr class='rec-row"+(n.isAltered?" rec-altered":(n.citesAltered?" rec-flagged":""))+"'>"
      +"<td>"+(i+1)+"</td><td><code>"+safe(s.capsule_id.slice(0,12))+"…</code> "+safe(s.action_type)+"</td>"
      +"<td>"+noteText+"</td></tr>";
  });
  rh+="</tbody></table>";
  h+="<div style='margin-top:16px'>"+rh+"</div>";
  mount.innerHTML=h;
  $("ritualSection").style.display="block";
}

/* ---------- load + permalink ---------- */
function loadCapsule(data){
  _activeIntegrityPromise=verifyCapsuleId(data);
  var profile=detectProfile(data);
  var renderer=PROFILE_RENDERERS[profile];
  if(!renderer){$("parseErr").textContent="Profile not recognised: "+profile;return;}
  renderer(data);
  renderRegPanel(data,false);
  try{
    var frag=btoa(unescape(encodeURIComponent(JSON.stringify(data))));
    history.replaceState(null,"",location.pathname+location.search+"#"+frag);
    $("linkBtn").disabled=false;$("linkBtn").style.opacity="1";
  }catch(ex){}
  $("pasteSection").style.display="none";
  _capsuleLoaded=true;
  var _incSec=$("inclusionSection");if(_incSec)_incSec.style.display="none";
}

/* auto-load from fragment (single capsule object; arrays handled by bundle section below) */
var hash=location.hash.slice(1);
if(hash){
  try{
    _fragData=JSON.parse(decodeURIComponent(escape(atob(hash))));
    if(!Array.isArray(_fragData)){
      loadCapsule(_fragData);
      /* renderRitual's own helpers (verifyCapsuleId/findChainGaps/annotateRecords/
       * _capSummary) unwrap a Disclosure Envelope internally now, so passing the
       * raw fragment straight through is safe for both bare and enveloped shapes. */
      renderRitual([_fragData],_bundleWitness);
    }
  }catch(ex){$("parseErr").textContent="Fragment decode error: "+ex.message;}
}

/* anchor status (same-origin proxy avoids CORS). Unreachable is reported
 * neutrally — never as a failed verification (the check merely didn't run).
 * The fetch and its handling are wired up at the bottom of this file, after
 * the bundle-array fragment (if any) is parsed too -- see the capsule-body
 * integrity gate there for why. */
function _ritualBundle(){return(_bundle&&_bundle.length)?_bundle:(_fragData?[_fragData]:null);}

/* paste form */
$("loadBtn").addEventListener("click",function(){
  var txt=$("capsuleJson").value.trim();
  try{loadCapsule(JSON.parse(txt));}
  catch(ex){$("parseErr").textContent="JSON error: "+ex.message;}
});
$("linkBtn").addEventListener("click",function(){
  if(navigator.clipboard){
    var payload=_bundle?(_bundleWitness?{bundle:_bundle,witness:_bundleWitness}:_bundle):null;
    var txt=payload?btoa(unescape(encodeURIComponent(JSON.stringify(payload)))):location.hash.slice(1);
    var url=location.origin+location.pathname+"#"+txt;
    navigator.clipboard.writeText(url).then(function(){
      $("linkBtn").textContent="Copied!";
      setTimeout(function(){$("linkBtn").textContent="Copy permalink";},2000);
    });
  }
});

/* ---------- bundle / chain navigation ---------- */
var _bundle=null,_bundleIdx=0;

function _capSummary(cap){
  cap=unwrapEnvelope(cap);
  var d=cap.disposition||{};
  return{
    capsule_id:cap.capsule_id||"",
    action_type:cap.action_type||"",
    verdict:d.verdict_class||d.decision||"",
    human:d.human_disposed?"human":"policy",
    timestamp:(cap.timestamp||"").slice(0,19).replace("T"," "),
  };
}

function renderChainTable(capsules,activeIdx){
  var el=$("chainTableContent");if(!el)return;
  var h="<table class='chain-table'><thead><tr>"
    +"<th>#</th><th>capsule_id</th><th>action_type</th><th>verdict</th><th>approver</th><th>timestamp</th>"
    +"</tr></thead><tbody>";
  capsules.forEach(function(cap,i){
    var s=_capSummary(cap);
    var cls="chain-row"+(i===activeIdx?" chain-active":"");
    h+="<tr class='"+cls+"' data-idx='"+i+"'>"
      +"<td>"+safe(String(i+1))+"</td>"
      +"<td><code>"+safe(s.capsule_id.slice(0,12))+"…</code></td>"
      +"<td><code>"+safe(s.action_type)+"</code></td>"
      +"<td>"+safe(s.verdict)+"</td>"
      +"<td>"+safe(s.human)+"</td>"
      +"<td><code style='font-size:11px'>"+safe(s.timestamp)+"</code></td>"
      +"</tr>";
  });
  h+="</tbody></table>";
  el.innerHTML=h;
  el.querySelectorAll("tr.chain-row").forEach(function(tr){
    tr.addEventListener("click",function(){navigateBundle(parseInt(this.getAttribute("data-idx"),10));});
  });
  $("chainNav").style.display="block";
  var prev=$("chainPrevBtn"),next=$("chainNextBtn"),pos=$("chainPos");
  if(prev&&next){
    if(activeIdx>0){prev.disabled=false;prev.style.opacity="1";}
    else{prev.disabled=true;prev.style.opacity=".5";}
    if(activeIdx<capsules.length-1){next.disabled=false;next.style.opacity="1";}
    else{next.disabled=true;next.style.opacity=".5";}
  }
  if(pos)pos.textContent=(activeIdx+1)+" of "+capsules.length;
}

function navigateBundle(idx){
  if(!_bundle||idx<0||idx>=_bundle.length)return;
  _bundleIdx=idx;
  renderChainTable(_bundle,idx);
  loadCapsule(_bundle[idx]);
  renderRitual(_bundle,_bundleWitness);
}

$("chainPrevBtn")&&$("chainPrevBtn").addEventListener("click",function(){navigateBundle(_bundleIdx-1);});
$("chainNextBtn")&&$("chainNextBtn").addEventListener("click",function(){navigateBundle(_bundleIdx+1);});

/* prior-capsule graph nodes become clickable when bundle contains them */
function _patchGraphPriorLinks(){
  if(!_bundle)return;
  var byId={};
  _bundle.forEach(function(cap,i){var u=unwrapEnvelope(cap);if(u.capsule_id)byId[u.capsule_id]=i;});
  document.querySelectorAll(".gn-capsule").forEach(function(node){
    var codeEl=node.querySelector(".gn-digest");
    if(!codeEl)return;
    var fullId=codeEl.textContent;
    if(fullId&&byId[fullId]!==undefined){
      var idx=byId[fullId];
      if(!node.classList.contains("_linked")){
        node.classList.add("_linked");
        node.style.cursor="pointer";
        codeEl.style.color="var(--accent)";
        codeEl.style.textDecoration="underline";
        node.addEventListener("click",function(){navigateBundle(idx);});
      }
    }
  });
}

/* override renderGraph to also patch links after each render */
var _origRenderGraph=renderGraph;
renderGraph=function(g){_origRenderGraph(g);_patchGraphPriorLinks();};

/* auto-load bundle from fragment — either a bare array (legacy: bilateral
 * bundles) or {bundle:[...], witness:{...}} (declares witness config for a
 * self-contained tamper-states fixture; never a live network fetch). */
var hash=location.hash.slice(1);
if(hash){
  try{
    var decoded=JSON.parse(decodeURIComponent(escape(atob(hash))));
    var arr=null,wit=null;
    if(Array.isArray(decoded)&&decoded.length>0){arr=decoded;}
    else if(decoded&&Array.isArray(decoded.bundle)&&decoded.bundle.length>0){arr=decoded.bundle;wit=decoded.witness||null;}
    if(arr){
      _bundle=arr;
      _bundleWitness=wit;
      _bundleIdx=0;
      renderChainTable(arr,0);
      loadCapsule(arr[0]);
      renderRitual(arr,wit);
    }
  }catch(ex){}
}

/* anchor status fetch, deferred to here (after both the single-fragment and
 * bundle-array autoload blocks above) so _activeIntegrityPromise already
 * reflects whichever capsule ended up focal by the time this Promise chain
 * reads it. Gated on capsule-body integrity: a capsule_id that does not
 * recompute from its own fragment body must never show the green "anchored"
 * banner, no matter what the anchor log says about that id -- the id being
 * logged proves nothing about the (possibly altered) body sitting in this
 * fragment. */
if(capsuleId){
  fetch("/anchor-status/"+capsuleId)
    .then(function(r){return r.json();})
    .catch(function(ex){return{error:ex.message};})
    .then(function(s){
      return Promise.resolve(_activeIntegrityPromise).then(function(integrity){
        var b=$("anchorBanner");
        if(integrity&&integrity.ok===false){
          b.innerHTML="<span class='anchor-fail'>✕ CAPSULE ID MISMATCH</span> — this body does not hash to its stated <code>capsule_id</code>"
            +"<div class='anchor-fail-detail'>stated&nbsp;&nbsp;<code>"+safe(integrity.stated)+"</code><br>recomputed <code>"+safe(integrity.recomputed||"(could not be computed)")+"</code></div>";
          b.className="anchor-banner anchor-fail";
          var rbf=_ritualBundle();if(rbf)renderRitual(rbf,{reachable:true});
          return;
        }
        if(s.error){
          b.innerHTML="<span class='anchor-offline'>Anchor unreachable</span> — witness check skipped, not failed: "+safe(s.error);
          b.className="anchor-banner anchor-offline";
          var rb=_ritualBundle();if(rb)renderRitual(rb,{reachable:false});
          return;
        }
        var _ri=rungInfo(s.rung);
        if(s.anchored){
          b.innerHTML="<span class='"+_ri.innerCls+"'>✓ "+_ri.label+"</span> log index <code>"+s.log_index+"</code>"+
            (s.receipt_verified?" · <span class='anchor-ok'>inclusion proof verified (RFC 9162)</span>":"");
          if(s.logged_at)b.innerHTML+=" · "+safe(s.logged_at);
          b.className="anchor-banner "+_ri.cls;
          /* upgrade reg panel with tamper-evident-log rows now that receipt is confirmed */
          if(_regLastData)renderRegPanel(_regLastData,true);
          var rb2=_ritualBundle();
          if(rb2)renderRitual(rb2,{held:1,configured:1,reachable:true,verified:s.receipt_verified!==false});
          /* inclusion-only view: show witnessing facts when no capsule is loaded */
          if(!_capsuleLoaded){
            var _iSec=$("inclusionSection");
            if(_iSec){
              $("inclDigest").textContent=capsuleId;
              $("inclLeaf").textContent=s.leaf_index!=null?s.leaf_index:"—";
              $("inclTree").textContent=s.tree_size!=null?s.tree_size:"—";
              var _rv=s.receipt_verified;
              $("inclReceipt").innerHTML=_rv?"<span class='anchor-ok'>✓ verified (RFC 9162 SHA-256)</span>":"<span class='anchor-none'>unverified</span>";
              _iSec.style.display="block";
              if(document.title)document.title="Entry "+capsuleId.slice(0,8)+"… — Witnessed";
            }
          }
        }else{
          b.innerHTML="<span class='"+_ri.innerCls+"'>"+_ri.label+"</span>";
          b.className="anchor-banner "+_ri.cls;
          var rb3=_ritualBundle();if(rb3)renderRitual(rb3,{held:0,configured:1,reachable:true});
        }
      });
    })
    .catch(function(ex){
      var b=$("anchorBanner");
      b.innerHTML="<span class='anchor-offline'>Anchor unreachable</span> — witness check skipped, not failed: "+safe(ex.message);
      b.className="anchor-banner anchor-offline";
      var rb=_ritualBundle();if(rb)renderRitual(rb,{reachable:false});
    });
}
})();
"""


#: Vanilla-JS port of capsule-ledger's ``capsule_ledger.mmr.core`` (MMRIVER-draft
#: -compatible completeness-certificate math). Served at ``/static/mmr.js``.
#:
#: This is a faithful, function-for-function port of the *pure* verification
#: half of that module (``leaf_hash``, ``interior_hash``, ``root_from_peaks``,
#: ``height_at``, ``node_count``, ``peaks``, ``leaf_index_to_pos``,
#: ``verify_inclusion``, ``verify_consistency``) — never the mutating
#: ``add_leaf``/proof-*building* half, because this is a read-only recipient
#: viewer: it only ever checks a completeness certificate someone else
#: produced, never builds one. ``tests/test_mmr_js_parity.py`` runs this file
#: for real (via Node — see ``tests/js_harness_mmr.mjs``) against
#: ``test-vectors/mmr/`` and asserts byte-identical output against the Python
#: reference, so "faithful port" is a checked claim, not a comment.
#:
#: ``verify_inclusion``/``verify_consistency`` keep the Python original's
#: never-raise contract: malformed input (wrong lengths, bad hex, wrong
#: shape) resolves to ``false``, never a thrown exception — a verifier is a
#: total function from (possibly adversarial) input to a boolean. SHA-256 is
#: ``crypto.subtle.digest``, which is asynchronous, so both verify functions
#: are ``async`` and resolve to a boolean rather than returning one directly.
MMR_JS = r"""
var MMR = (function(){
"use strict";

var DIGEST_LEN = 32;
var MAX_MMR_SIZE = Math.pow(2, 50);

function MmrError(msg){ this.message = msg; this.name = "MmrError"; }
MmrError.prototype = Object.create(Error.prototype);

function isNonNegInt(n){ return typeof n === "number" && Number.isInteger(n) && n >= 0; }

function requireNonNegInt(n, what){
  if(!isNonNegInt(n)) throw new MmrError(what + " must be a non-negative integer: " + n);
}

function hexToBytes(hex){
  if(typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)){
    throw new MmrError("not a valid hex string");
  }
  var out = new Uint8Array(hex.length / 2);
  for(var i = 0; i < out.length; i++){
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function bytesToHex(bytes){
  var s = "";
  for(var i = 0; i < bytes.length; i++){
    s += bytes[i].toString(16).padStart(2, "0");
  }
  return s;
}

function assertDigest(b, what){
  if(!(b instanceof Uint8Array) || b.length !== DIGEST_LEN){
    throw new MmrError((what || "digest") + " must be " + DIGEST_LEN + " bytes");
  }
}

function parseDigestHex(h){
  if(typeof h !== "string") throw new MmrError("proof element is not a hex string");
  var b = hexToBytes(h);
  if(b.length !== DIGEST_LEN) throw new MmrError("proof element has wrong digest length: " + b.length);
  return b;
}

function concatBytes(){
  var total = 0;
  for(var i = 0; i < arguments.length; i++) total += arguments[i].length;
  var out = new Uint8Array(total);
  var off = 0;
  for(var j = 0; j < arguments.length; j++){
    out.set(arguments[j], off);
    off += arguments[j].length;
  }
  return out;
}

function bytesEqual(a, b){
  if(a.length !== b.length) return false;
  for(var i = 0; i < a.length; i++){ if(a[i] !== b[i]) return false; }
  return true;
}

async function sha256(bytes){
  var digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

/* be64(n) -- big-endian 8-byte encoding. n stays well within
 * Number.MAX_SAFE_INTEGER (our domain is < MAX_MMR_SIZE = 2**50), so plain
 * float division/modulo is exact -- no BigInt needed. */
function beU64(n){
  var bytes = new Uint8Array(8);
  var v = n;
  for(var i = 7; i >= 0; i--){
    bytes[i] = v % 256;
    v = Math.floor(v / 256);
  }
  return bytes;
}

/* leaf_hash = sha256(0x00 || body_digest) */
async function leafHash(bodyDigest){
  assertDigest(bodyDigest, "body_digest");
  return sha256(concatBytes(new Uint8Array([0x00]), bodyDigest));
}

/* interior_hash = sha256(be64(position+1) || left || right) */
async function interiorHash(left, right, position){
  assertDigest(left, "left");
  assertDigest(right, "right");
  requireNonNegInt(position, "position");
  return sha256(concatBytes(beU64(position + 1), left, right));
}

/* root = bagged peaks, right-to-left, NO domain-separator byte */
async function rootFromPeaks(peakHashes){
  if(!peakHashes.length) return new Uint8Array(DIGEST_LEN);
  for(var i = 0; i < peakHashes.length; i++) assertDigest(peakHashes[i], "peak");
  var hashes = peakHashes.slice();
  while(hashes.length > 1){
    var right = hashes.pop();
    var left = hashes.pop();
    hashes.push(await sha256(concatBytes(right, left)));
  }
  return hashes[0];
}

function popcount(n){
  var c = 0;
  while(n > 0){
    c += (n % 2 === 1) ? 1 : 0;
    n = Math.floor(n / 2);
  }
  return c;
}

function heightAt(pos){
  requireNonNegInt(pos, "pos");
  var pos1 = pos + 1, h = 0;
  while(Math.pow(2, h + 1) - 1 < pos1) h += 1;
  while(h > 0){
    var size = Math.pow(2, h + 1) - 1;
    if(pos1 === size) return h;
    var leftSize = Math.pow(2, h) - 1;
    if(pos1 > leftSize) pos1 -= leftSize;
    h -= 1;
  }
  return 0;
}

function nodeCount(leafCount_){
  requireNonNegInt(leafCount_, "leaf_count");
  return 2 * leafCount_ - popcount(leafCount_);
}

function peaks(size){
  if(!isNonNegInt(size) || size >= MAX_MMR_SIZE) throw new MmrError("invalid MMR size: " + size);
  var result = [], remaining = size, offset = 0, prevHeight = Infinity;
  while(remaining > 0){
    var h = 0;
    while(Math.pow(2, h + 2) - 1 <= remaining) h += 1;
    if(h >= prevHeight) throw new MmrError("invalid MMR size (not a valid node count): " + size);
    var mSize = Math.pow(2, h + 1) - 1;
    offset += mSize;
    result.push(offset - 1);
    remaining -= mSize;
    prevHeight = h;
  }
  return result;
}

function leafCountFromSize(size){
  var pks = peaks(size), total = 0;
  for(var i = 0; i < pks.length; i++) total += Math.pow(2, heightAt(pks[i]));
  return total;
}

function leafIndexToPos(leafIndex){
  requireNonNegInt(leafIndex, "leaf_index");
  var pos = nodeCount(leafIndex);
  if(pos >= MAX_MMR_SIZE) throw new MmrError("leaf_index too large: " + leafIndex);
  return pos;
}

function findContainingPeak(pos, peakPositions){
  for(var i = 0; i < peakPositions.length; i++){
    var peakPos = peakPositions[i];
    var h = heightAt(peakPos);
    var mSize = Math.pow(2, h + 1) - 1;
    var start = peakPos - mSize + 1;
    if(start <= pos && pos <= peakPos) return i;
  }
  return -1;
}

/* Bottom-up sibling path from targetPos up to (but excluding) the mountain
 * root at rootPos (height `height`). Mirrors core.py's _locate_path. */
function locatePath(rootPos, height, targetPos){
  var topDown = [];
  var curRoot = rootPos, curHeight = height;
  while(curHeight > 0 && curRoot !== targetPos){
    var parentPos = curRoot;
    var leftSize = Math.pow(2, curHeight) - 1;
    var leftChildRoot = curRoot - leftSize - 1;
    var rightChildRoot = curRoot - 1;
    var step;
    if(targetPos <= leftChildRoot){
      step = {siblingPos: rightChildRoot, targetIsRight: false, parentPos: parentPos};
      curRoot = leftChildRoot;
    }else{
      step = {siblingPos: leftChildRoot, targetIsRight: true, parentPos: parentPos};
      curRoot = rightChildRoot;
    }
    topDown.push(step);
    curHeight -= 1;
  }
  topDown.reverse();
  return topDown;
}

/* Pure, total-order-stable inclusion verification. Never throws -- any
 * malformed input resolves to false. */
async function verifyInclusion(rootHex, size, leafIndex, bodyDigestHex, proof){
  try{
    var root = hexToBytes(rootHex);
    var bodyDigest = hexToBytes(bodyDigestHex);
    assertDigest(root, "root");
    assertDigest(bodyDigest, "body_digest");
    if(!proof || proof.v !== 1 || proof.kind !== "inclusion") return false;
    if(proof.size !== size || proof.leaf_index !== leafIndex) return false;
    if(!isNonNegInt(size) || size >= MAX_MMR_SIZE) return false;
    if(!isNonNegInt(leafIndex)) return false;
    if(!Array.isArray(proof.witness) || !Array.isArray(proof.peaks_left) || !Array.isArray(proof.peaks_right)){
      return false;
    }

    var lc = leafCountFromSize(size);
    if(leafIndex >= lc) return false;

    var leafPos = leafIndexToPos(leafIndex);
    var pks = peaks(size);
    var peakIdx = findContainingPeak(leafPos, pks);
    if(peakIdx === -1) return false;

    var peakPos = pks[peakIdx];
    var peakHeight = heightAt(peakPos);
    var path = locatePath(peakPos, peakHeight, leafPos);

    if(proof.witness.length !== path.length) return false;
    if(proof.peaks_left.length !== peakIdx) return false;
    if(proof.peaks_right.length !== pks.length - peakIdx - 1) return false;

    var witnessBytes = proof.witness.map(parseDigestHex);
    var peaksLeftBytes = proof.peaks_left.map(parseDigestHex);
    var peaksRightBytes = proof.peaks_right.map(parseDigestHex);

    var acc = await leafHash(bodyDigest);
    for(var i = 0; i < path.length; i++){
      var step = path[i], sib = witnessBytes[i];
      acc = step.targetIsRight
        ? await interiorHash(sib, acc, step.parentPos)
        : await interiorHash(acc, sib, step.parentPos);
    }

    var allPeaks = peaksLeftBytes.concat([acc]).concat(peaksRightBytes);
    var computedRoot = await rootFromPeaks(allPeaks);
    return bytesEqual(computedRoot, root);
  }catch(e){
    return false;
  }
}

/* Pure consistency verification. Never throws. */
async function verifyConsistency(rootAHex, sizeA, rootBHex, sizeB, proof){
  try{
    var rootA = hexToBytes(rootAHex);
    var rootB = hexToBytes(rootBHex);
    assertDigest(rootA, "root_a");
    assertDigest(rootB, "root_b");
    if(!proof || proof.v !== 1 || proof.kind !== "consistency") return false;
    if(proof.size_a !== sizeA || proof.size_b !== sizeB) return false;
    if(!isNonNegInt(sizeA)) return false;
    if(!isNonNegInt(sizeB) || sizeB < sizeA) return false;
    if(!Array.isArray(proof.old_peaks) || !Array.isArray(proof.new_peaks) || !Array.isArray(proof.witness)){
      return false;
    }

    var oldPeakPositions = peaks(sizeA);
    var newPeakPositions = peaks(sizeB);

    if(proof.old_peaks.length !== oldPeakPositions.length) return false;
    if(proof.new_peaks.length !== newPeakPositions.length) return false;
    if(proof.witness.length !== oldPeakPositions.length) return false;

    var oldPeaksBytes = proof.old_peaks.map(parseDigestHex);
    var newPeaksBytes = proof.new_peaks.map(parseDigestHex);

    var computedRootA = await rootFromPeaks(oldPeaksBytes);
    if(!bytesEqual(computedRootA, rootA)) return false;
    var computedRootB = await rootFromPeaks(newPeaksBytes);
    if(!bytesEqual(computedRootB, rootB)) return false;

    for(var i = 0; i < oldPeakPositions.length; i++){
      var p = oldPeakPositions[i];
      var containingIdx = findContainingPeak(p, newPeakPositions);
      if(containingIdx === -1) return false;

      var newPeakPos = newPeakPositions[containingIdx];
      var newPeakHeight = heightAt(newPeakPos);
      var path = locatePath(newPeakPos, newPeakHeight, p);

      var w = proof.witness[i];
      if(!Array.isArray(w) || w.length !== path.length) return false;
      var wBytes = w.map(parseDigestHex);

      var acc = oldPeaksBytes[i];
      for(var j = 0; j < path.length; j++){
        var step = path[j], sib = wBytes[j];
        acc = step.targetIsRight
          ? await interiorHash(sib, acc, step.parentPos)
          : await interiorHash(acc, sib, step.parentPos);
      }
      if(!bytesEqual(acc, newPeaksBytes[containingIdx])) return false;
    }

    return true;
  }catch(e){
    return false;
  }
}

return {
  DIGEST_LEN: DIGEST_LEN,
  MAX_MMR_SIZE: MAX_MMR_SIZE,
  hexToBytes: hexToBytes,
  bytesToHex: bytesToHex,
  leafHash: leafHash,
  interiorHash: interiorHash,
  rootFromPeaks: rootFromPeaks,
  heightAt: heightAt,
  nodeCount: nodeCount,
  peaks: peaks,
  leafCountFromSize: leafCountFromSize,
  leafIndexToPos: leafIndexToPos,
  verifyInclusion: verifyInclusion,
  verifyConsistency: verifyConsistency
};
})();
if(typeof globalThis !== "undefined"){ globalThis.MMR = MMR; }
"""


#: Extra CSS for the bundle page — reuses _PAGE_CSS's variables and
#: _CAPSULE_CSS's .ritual-stages/.records-table/.pltable/.anchor-banner
#: classes (same visual language as the single-capsule verify page).
_BUNDLE_CSS = """
.share-row{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.share-row .mono{font-size:11.5px;color:var(--muted);word-break:break-all}
.share-row .btnrow{display:flex;gap:10px;flex-shrink:0}
.completeness-card{border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin-bottom:20px}
.completeness-card.status-pass{background:var(--pass-soft);border-color:var(--pass)}
.completeness-card.status-fail{background:var(--fail-soft);border-color:var(--fail)}
.completeness-card.status-skip{background:var(--paper-2);color:var(--muted)}
.completeness-title{font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}
.completeness-card.status-pass .completeness-title{color:var(--pass)}
.completeness-card.status-fail .completeness-title{color:var(--fail)}
.completeness-card.status-skip .completeness-title{color:var(--muted)}
.completeness-detail{font-size:13.5px;color:var(--ink)}
.bundle-empty{border:1px dashed var(--line);border-radius:12px;padding:28px;text-align:center;color:var(--muted);font-size:14px;margin-bottom:20px}
"""

#: Bundle-viewer client controller — served at ``/static/bundle.js``.
#:
#: This is the "Bundle-open page" from the task: a recipient-side viewer for
#: ``capsule bundle`` output (capsule-ledger's ``capsule_ledger/cli/bundle_cmd.py``).
#: Bundle JSON travels in the URL fragment only (never sent to this server —
#: see ``render_bundle_page``); the offline single-file mode inlines the same
#: data as ``window.__BUNDLE_FRAGMENT_B64U__`` instead of a URL fragment (a
#: downloaded file has no server to carry a fragment to, but the file itself
#: can still embed one) — either way this script never performs a network
#: request with bundle content in it.
#:
#: ``isH64``/``sh``/``safe``/``KNOWN_TYPES``/``parseAac``/``_capMismatched``/
#: ``findChainGaps``/``annotateRecords`` below are a **verbatim port** of the
#: same-named functions in ``CAPSULE_JS`` (the existing single-capsule verify
#: page) — copied, not reinvented, because a ledger bundle's ``records`` are
#: the exact same AAC capsule shape ``CAPSULE_JS`` already parses structurally
#: (digest recompute, chain-gap detection). ``tests/test_capsule_view.py``'s
#: ``test_bundle_js_shared_helpers_match_capsule_js`` pins byte-for-byte
#: equality against ``CAPSULE_JS`` so this can never silently drift.
#:
#: The completeness certificate check (``checkCompleteness``) is new: it
#: verifies a bundle's MMR range/consistency proof (if present) via
#: ``MMR.verifyInclusion``/``MMR.verifyConsistency`` from ``mmr.js`` — see
#: the completeness_certificate schema comment below.
BUNDLE_JS = r"""
/* === PORTED FROM CAPSULE_JS (verbatim) — see test_bundle_js_shared_helpers_match_capsule_js === */
var KNOWN_TYPES={"capsule":1,"offer_terms":1,"wicket_manifest":1,"response":1,
  "gate_checks":1,"subject":1,"bilateral_subject":1,"compute_attestation":1,
  "agent_input":1,"agent_output":1};
function isH64(s){return typeof s==="string"&&s.length===64&&/^[0-9a-f]+$/i.test(s);}
/* Disclosure Envelope unwrap: {"capsule":{...unmodified...},"disclosures":{...}} ->
 * the unmodified capsule. A bare capsule (no "capsule" wrapper key, or a
 * bilateral binding with buyer_capsule/seller_capsule) passes through unchanged. */
function unwrapEnvelope(item){return(item&&typeof item==="object"&&item.capsule&&typeof item.capsule==="object")?item.capsule:item;}
function sh(d){return d.slice(0,8)+"…"+d.slice(-4);}
function safe(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}

/* ---------- disclosed-payload rendering (shared helper — same canonicalization as
 * the digest recompute; see test_bundle_js_shared_helpers_match_capsule_js). The
 * bytes hashed against the committed digest and the bytes shown to the reader MUST
 * come from the same function -- a display that re-serializes by a different rule
 * than JSON.stringify(p, Object.keys(p).sort()) could show content that doesn't
 * match what was actually verified. */
var PAYLOAD_TRUNCATE_BYTES=8192;
function canonicalPayloadText(payload){
  return typeof payload==="string"?payload:JSON.stringify(payload,Object.keys(payload).sort());
}
function payloadPreview(payload){
  var t=canonicalPayloadText(payload);
  return t.length>80?t.slice(0,80)+"…":t;
}
function payloadCellHtml(entry,recomputedDigest){
  if(entry.withheld||entry._revPayload==null||entry.matchOk!==true)return"";
  var full=typeof entry._revPayload==="string"
    ?entry._revPayload
    :JSON.stringify(entry._revPayload,Object.keys(entry._revPayload).sort(),2);
  var bytes=new TextEncoder().encode(full);
  var truncated=bytes.length>PAYLOAD_TRUNCATE_BYTES;
  var shown=truncated?new TextDecoder("utf-8").decode(bytes.slice(0,PAYLOAD_TRUNCATE_BYTES)):full;
  var note=truncated?"<p class='pl-payload-truncated'>truncated for display, full payload is in the URL fragment</p>":"";
  return"<details class='pl-payload-details'><summary><code>"+safe(payloadPreview(entry._revPayload))+"</code></summary>"
    +"<div class='pl-payload-full'><pre>"+safe(shown)+"</pre>"+note
    +"<div class='pl-payload-digests'><div>committed <code>"+safe(entry.digest)+"</code></div>"
    +"<div>recomputed <code>"+safe(recomputedDigest||"")+"</code></div></div></div></details>";
}

/* === PORTED FROM CAPSULE_JS (verbatim) — capsule_id recompute (RFC 8785 JCS
 * + SHA-256), see test_bundle_js_shared_helpers_match_capsule_js === */
var CHAIN_LINKAGE_FIELDS={"capsule_id":1,"chain":1};

function CapsuleIdError(msg){this.message=msg;this.name="CapsuleIdError";}

function _capIdNormalize(v){
  if(Array.isArray(v))return v.map(_capIdNormalize);
  if(v&&typeof v==="object"){
    var out={};
    Object.keys(v).forEach(function(k){
      var nv=_capIdNormalize(v[k]);
      if(nv===null||nv===undefined)return;
      if(Array.isArray(nv)&&nv.length===0)return;
      if(nv&&typeof nv==="object"&&!Array.isArray(nv)&&Object.keys(nv).length===0)return;
      out[k]=nv;
    });
    return out;
  }
  return v;
}

function _capIdJcsString(s){
  var out=['"'];
  for(var ch of s){
    var o=ch.codePointAt(0);
    if(ch==='"')out.push('\\"');
    else if(ch==="\\")out.push("\\\\");
    else if(o===0x08)out.push("\\b");
    else if(o===0x09)out.push("\\t");
    else if(o===0x0A)out.push("\\n");
    else if(o===0x0C)out.push("\\f");
    else if(o===0x0D)out.push("\\r");
    else if(o<0x20)out.push("\\u"+o.toString(16).padStart(4,"0"));
    else out.push(ch);
  }
  out.push('"');
  return out.join("");
}

function _capIdJcsValue(v){
  if(v===null||v===undefined)return"null";
  if(v===true)return"true";
  if(v===false)return"false";
  if(typeof v==="string")return _capIdJcsString(v);
  if(typeof v==="number"){
    if(!Number.isInteger(v))throw new CapsuleIdError("float in digest-bearing field");
    if(v>Number.MAX_SAFE_INTEGER||v<-Number.MAX_SAFE_INTEGER)throw new CapsuleIdError("integer outside safe range");
    return String(v);
  }
  if(Array.isArray(v))return"["+v.map(_capIdJcsValue).join(",")+"]";
  if(typeof v==="object"){
    var keys=Object.keys(v).sort();
    return"{"+keys.map(function(k){return _capIdJcsString(k)+":"+_capIdJcsValue(v[k]);}).join(",")+"}";
  }
  throw new CapsuleIdError("value not JSON-serializable: "+typeof v);
}

async function _capIdSha256Hex(bytes){
  var buf=await crypto.subtle.digest("SHA-256",bytes);
  return Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
}

async function computeCapsuleId(capsule){
  if(!capsule||typeof capsule!=="object"||Array.isArray(capsule))throw new CapsuleIdError("capsule must be a JSON object");
  var canonical={};
  Object.keys(capsule).forEach(function(k){if(!CHAIN_LINKAGE_FIELDS[k])canonical[k]=capsule[k];});
  var jcsStr=_capIdJcsValue(_capIdNormalize(canonical));
  return await _capIdSha256Hex(new TextEncoder().encode(jcsStr));
}

async function verifyCapsuleId(cap){
  var c=unwrapEnvelope(cap);
  var stated=(c&&c.capsule_id)||"";
  if(!isH64(stated))return{ok:null,stated:stated,recomputed:null};
  if(typeof crypto==="undefined"||!crypto.subtle)return{ok:null,stated:stated,recomputed:null};
  try{
    var recomputed=await computeCapsuleId(c);
    return{ok:recomputed===stated,stated:stated,recomputed:recomputed};
  }catch(ex){
    return{ok:false,stated:stated,recomputed:null,error:ex.message};
  }
}

function parseAac(data){
  var nodes=[],edges=[],privlog=[],unk=[],seen={};
  var isB=!!(data.buyer_capsule&&data.seller_capsule);

  function addN(id,type,label,withheld,payload){
    if(seen[id])return false;seen[id]=true;
    var k=!!KNOWN_TYPES[type];
    if(!k&&unk.indexOf(type)<0)unk.push(type);
    nodes.push({id:id,type:type,label:label,digest:id,isKnown:k,withheld:withheld!==false,payload:payload||null});
    return true;
  }
  function addArt(digest,type,label,ctx){
    if(!isH64(digest)||!addN(digest,type,label,true,null))return;
    privlog.push({id:label,type:type,digest:digest,withheld:true,isKnown:!!KNOWN_TYPES[type],matchOk:null,ctx:ctx});
  }
  function addEdge(f,t,lbl){
    var k="_e_"+f+"_"+t+"_"+lbl;if(seen[k])return;seen[k]=true;
    edges.push({from:f,to:t,label:lbl});
  }
  /* disclosures: the Disclosure Envelope's out-of-band {agent_input, agent_output}
   * object for this capsule (draft-mih-scitt-agent-action-capsule-disclosure-envelope-00).
   * NEVER read from cap.model_attestation.compute_attestation — that region is
   * digest-committed, so embedding a payload there would change capsule_id. */
  function extractCap(cap,capId,pfx,disclosures){
    disclosures=disclosures||{};
    var p=pfx?pfx+".":"";
    var chain=cap.chain||{};
    var prior=chain.parent_capsule_id||"";
    if(isH64(prior)&&addN(prior,"capsule","prior capsule "+sh(prior),false,null))
      addEdge(capId,prior,"chains_to");
    var ma=cap.model_attestation||{},ca=ma.compute_attestation||{},subj=ca.subject_digest||"";
    if(isH64(subj)){addArt(subj,"subject","subject",p+"compute_attestation.subject_digest");addEdge(capId,subj,"attests_over");}
    var _actxW=p+"compute_attestation — payload not carried in the record";
    var _actxR="payload carried in fragment; recomputed against committed digest";
    var ai=ca.agent_input_digest||"",aiPre=disclosures.agent_input,aiRev=aiPre!=null;
    if(isH64(ai)&&addN(ai,"agent_input","agent input "+sh(ai),!aiRev,aiRev?aiPre:null)){
      privlog.push({id:"agent input",type:"agent_input",digest:ai,withheld:!aiRev,isKnown:true,matchOk:null,
                    ctx:aiRev?_actxR:_actxW,_revPayload:aiRev?aiPre:null});addEdge(capId,ai,"attests_over");}
    var ao=ca.agent_output_digest||"",aoPre=disclosures.agent_output,aoRev=aoPre!=null;
    if(isH64(ao)&&addN(ao,"agent_output","agent output "+sh(ao),!aoRev,aoRev?aoPre:null)){
      privlog.push({id:"agent output",type:"agent_output",digest:ao,withheld:!aoRev,isKnown:true,matchOk:null,
                    ctx:aoRev?_actxR:_actxW,_revPayload:aoRev?aoPre:null});addEdge(capId,ao,"attests_over");}
    var eff=cap.effect||{},resp=eff.response_digest||"";
    if(isH64(resp)){addArt(resp,"response","response",p+"effect.response_digest");addEdge(capId,resp,"effect_response");}
    (cap.constraints||[]).forEach(function(c){
      var ev=c.evidence_digest||"",cid=c.id||"constraint";
      if(isH64(ev)){addArt(ev,"wicket_manifest","manifest ["+cid+"]",p+"constraints["+cid+"].evidence_digest");addEdge(capId,ev,"commits_to");}
    });
  }

  if(isB){
    var bc=data.buyer_capsule||{},sc=data.seller_capsule||{};
    var bid=bc.capsule_id||"",sid=sc.capsule_id||"",sth=data.sealed_terms_hash||"",terms=data.terms;
    var bDisc=(data.disclosures&&data.disclosures.buyer)||{},sDisc=(data.disclosures&&data.disclosures.seller)||{};
    if(isH64(bid))addN(bid,"capsule","buyer capsule "+sh(bid),false,null);
    if(isH64(sid))addN(sid,"capsule","seller capsule "+sh(sid),false,null);
    if(isH64(sth)){
      var rev=terms!=null;
      addN(sth,"offer_terms","offer terms "+sh(sth),!rev,rev?terms:null);
      privlog.push({id:"sealed_terms_hash",type:"offer_terms",digest:sth,withheld:!rev,
                    isKnown:true,matchOk:null,ctx:"binding.sealed_terms_hash",_revPayload:rev?terms:null});
      if(isH64(bid))addEdge(bid,sth,"attests_over");
      if(isH64(sid))addEdge(sid,sth,"attests_over");
    }
    if(isH64(bid)&&isH64(sid))addEdge(sid,bid,"chains_to");
    if(isH64(bid))extractCap(bc,bid,"buyer",bDisc);
    if(isH64(sid))extractCap(sc,sid,"seller",sDisc);
  }else{
    /* Disclosure Envelope wrapper: {"capsule":{...unmodified...},"disclosures":{...}}.
     * A bare capsule (no "capsule" wrapper key) is the legacy/WITHHELD-only shape —
     * still fully supported, just with no disclosures to read. */
    var envCap=(data.capsule&&typeof data.capsule==="object")?data.capsule:data;
    var envDisc=(data.capsule&&typeof data.capsule==="object")?(data.disclosures||{}):{};
    var cid=envCap.capsule_id||"";
    if(isH64(cid)){addN(cid,"capsule","capsule "+sh(cid),false,null);extractCap(envCap,cid,"",envDisc);}
  }
  return{nodes:nodes,edges:edges,privlog:privlog,unk:unk,isB:isB};
}

function _capMismatched(cap){
  var g=parseAac(cap);
  return g.privlog.some(function(e){return e.matchOk===false;});
}

function findChainGaps(capsules){
  /* Unwrap first: a Disclosure-Envelope-wrapped bundle item carries capsule_id
   * and chain nested under "capsule", not at the top level — without this,
   * every envelope-wrapped item is invisible to gap detection. */
  var caps=capsules.map(unwrapEnvelope);
  var ids={};
  caps.forEach(function(c){if(isH64(c.capsule_id))ids[c.capsule_id]=true;});
  var gaps=[];
  for(var i=1;i<caps.length;i++){
    var parent=((caps[i].chain)||{}).parent_capsule_id||"";
    if(isH64(parent)&&!ids[parent])gaps.push({beforeIdx:i-1,afterIdx:i,missingParent:parent});
  }
  return gaps;
}

function annotateRecords(capsules,integrity){
  /* Same unwrap as findChainGaps — _capMismatched still receives the raw
   * (possibly enveloped) item, since parseAac needs the sibling "disclosures"
   * key to check revealed-payload digests. */
  var caps=capsules.map(unwrapEnvelope);
  var alteredIds={};
  capsules.forEach(function(c,i){
    var cid=caps[i].capsule_id||"";
    if(!isH64(cid))return;
    var idr=integrity&&integrity[i];
    if((idr&&idr.ok===false)||_capMismatched(c))alteredIds[cid]=true;
  });
  var byId={};
  caps.forEach(function(c){if(isH64(c.capsule_id))byId[c.capsule_id]=c;});
  return caps.map(function(cap){
    var cid=cap.capsule_id||"";
    if(alteredIds[cid])return{note:"digest_mismatch",isAltered:true,citesAltered:false};
    var cites=false,seen={},cur=cap;
    while(true){
      var parent=((cur.chain)||{}).parent_capsule_id||"";
      if(!isH64(parent)||seen[parent])break;
      seen[parent]=true;
      if(alteredIds[parent]){cites=true;break;}
      cur=byId[parent];if(!cur)break;
    }
    return{note:cites?"cites an altered record":"verifies",isAltered:false,citesAltered:cites};
  });
}
/* === END PORTED FROM CAPSULE_JS === */

/* Everything from here down to the render/DOM section is pure (no
 * document/window access) and directly callable from a Node harness --
 * see tests/js_harness_bundle.mjs / tests/test_bundle_page.py. */

/* ---------- base64url fragment codec ----------
 * capsule-ledger's `capsule bundle` encodes the fragment as
 * base64.urlsafe_b64encode(json.dumps(bundle, separators=(",",":"), sort_keys=True)).rstrip("=")
 * -- URL-safe alphabet, no padding. Not the same alphabet plain atob/btoa use,
 * so this is decoded/encoded explicitly rather than reusing capsule.js's
 * plain-base64 helpers. */
function b64uToStd(s){return s.replace(/-/g,"+").replace(/_/g,"/");}
function stdToB64u(s){return s.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function decodeFragment(hash){
  var std=b64uToStd(hash);
  var pad=std.length%4; if(pad)std+="=".repeat(4-pad);
  var bin=atob(std);
  var bytes=new Uint8Array(bin.length);
  for(var i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
  return JSON.parse(new TextDecoder("utf-8").decode(bytes));
}
function encodeFragment(obj){
  var bytes=new TextEncoder().encode(JSON.stringify(obj));
  var bin="";
  for(var i=0;i<bytes.length;i++)bin+=String.fromCharCode(bytes[i]);
  return stdToB64u(btoa(bin));
}

/* ---------- completeness certificate ----------
 * Optional bundle field this viewer knows how to check (capsule-ledger's
 * `capsule bundle` does not populate it yet as of this viewer shipping --
 * a bundle without one is handled honestly as "not available", never a
 * fabricated pass. Schema, mirroring capsule_ledger.mmr.index.MmrLedger's own
 * RangeProof/ConsistencyProof shapes 1:1 so a future capsule-ledger CLI
 * change can populate it directly from that module's own output:
 *
 * completeness_certificate: {
 *   v: 1,
 *   range_proof: {from_seq, to_seq, size, inclusion_from: <InclusionProof>, inclusion_to: <InclusionProof>},
 *   range_root: "<hex>",         // MMR root at `range_proof.size` (the tree as it stood right after to_seq)
 *   checkpoint_size: <int>,      // MMR node_count(checkpoint.tree_size); omitted/equal to range_proof.size if no growth since
 *   checkpoint_root: "<hex>",    // MMR root at checkpoint_size
 *   consistency_proof: <ConsistencyProof> | null   // bridges range_root/size -> checkpoint_root/size; null if they coincide
 * }
 *
 * Each <InclusionProof>/<ConsistencyProof> is exactly the JSON shape
 * capsule_ledger.mmr.core's dataclasses serialize to (v, kind, size, leaf_index,
 * witness, peaks_left, peaks_right / v, kind, size_a, size_b, old_peaks,
 * witness, new_peaks) -- see mmr.js's verifyInclusion/verifyConsistency.
 * Boundary leaf body digests are the bundle's own first/last record
 * capsule_id (hex) -- MmrLedger indexes leaf i's body_digest as
 * bytes.fromhex(record.capsule_id), so no extra data is needed beyond what
 * bundle.records already carries. */
async function checkCompleteness(bundle){
  var cc=bundle.completeness_certificate;
  var records=bundle.records||[];
  if(!records.length)return{status:"skip",detail:"empty bundle — nothing to certify"};
  if(!cc){
    return{status:"skip",detail:"no completeness certificate in this bundle — the claimed record "+
      "range and checkpoint are producer-asserted only, not cryptographically proven here. "+
      "Every capsule that IS present still verifies on its own (see Integrity, above)."};
  }
  try{
    var rp=cc.range_proof;
    if(!rp||!rp.inclusion_from||!rp.inclusion_to)return{status:"fail",detail:"malformed completeness certificate: missing range_proof"};
    var fromRec=records[0],toRec=records[records.length-1];
    var okFrom=await MMR.verifyInclusion(cc.range_root,rp.size,rp.inclusion_from.leaf_index,fromRec.capsule_id,rp.inclusion_from);
    var okTo=await MMR.verifyInclusion(cc.range_root,rp.size,rp.inclusion_to.leaf_index,toRec.capsule_id,rp.inclusion_to);
    if(!okFrom||!okTo){
      return{status:"fail",detail:"range boundary inclusion proof did not verify — this bundle's "+
        "claimed record range is not provably complete against its cited root"};
    }
    if(cc.consistency_proof){
      var okC=await MMR.verifyConsistency(cc.range_root,rp.size,cc.checkpoint_root,cc.checkpoint_size,cc.consistency_proof);
      if(!okC){
        return{status:"fail",detail:"checkpoint consistency proof did not verify — the cited checkpoint "+
          "does not provably extend this range's root"};
      }
    }
    var ckpt=bundle.checkpoint||{};
    return{status:"pass",detail:"records "+rp.from_seq+"–"+rp.to_seq+" are provably complete under root "+
      cc.range_root.slice(0,12)+"…"+(cc.consistency_proof?(" · extends to checkpoint #"+(ckpt.tree_size!=null?ckpt.tree_size:cc.checkpoint_size)):"")};
  }catch(e){
    return{status:"fail",detail:"completeness certificate malformed or unverifiable: "+e.message};
  }
}

/* ---------- authoritative digest verification (async — crypto.subtle) ----------
 * parseAac's privlog entries carry matchOk:null until a REVEALED field's
 * payload is actually hashed and compared against its committed digest.
 * This is the single, awaited source of truth for that comparison — both
 * the displayed privilege log (buildBundlePrivlog) and the verdict logic
 * (crossCheckSelfReport, evaluateBundleRitual's Integrity stage) call this
 * rather than each re-deriving (or worse, silently skipping) it. A prior
 * version of this file computed the digest only inside the DOM-rendering
 * path — after the ritual/cross-check verdicts had already been decided —
 * so a genuine digest mismatch could never flip either verdict. Fixed here:
 * a verification check that can't reject anything isn't a check. */
async function verifyCapsuleDigests(cap,disclosures){
  var g=parseAac(disclosures?{capsule:cap,disclosures:disclosures}:cap);
  if(typeof crypto==="undefined"||!crypto.subtle)return g;  // no WebCrypto: leave matchOk null (skip, not a fabricated pass)
  for(var i=0;i<g.privlog.length;i++){
    var e=g.privlog[i];
    if(e.withheld||e._revPayload==null)continue;
    var bytes=new TextEncoder().encode(canonicalPayloadText(e._revPayload));
    var buf=await crypto.subtle.digest("SHA-256",bytes);
    var hex=Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
    e.matchOk=(hex===e.digest);
    e._recomputedDigest=hex;
  }
  return g;
}

/* ---------- cross-check against the bundle's own self-reported verification ----------
 * capsule-ledger's `capsule bundle` already runs each capsule through its own
 * structural verifier (agent_action_capsule.verify) and embeds the verdict
 * in bundle.verification[capsule_id] -- but a recipient should never just
 * trust a producer's self-report. This cross-checks it against OUR OWN
 * independent digest recompute (verifyCapsuleDigests, above) and flags any
 * disagreement as its own finding, rather than silently preferring either
 * source. */
async function crossCheckSelfReport(bundle,records){
  var selfReport=bundle.verification||{};
  var bundleDisclosures=bundle.disclosures||{};
  var disagreements=[];
  for(var idx=0;idx<records.length;idx++){
    var cap=records[idx];
    var cid=cap.capsule_id;
    if(!isH64(cid))continue;
    var g=await verifyCapsuleDigests(cap,bundleDisclosures[cid]);
    var ours=!g.privlog.some(function(e){return e.matchOk===false;});
    var reported=selfReport[cid];
    if(reported&&typeof reported.ok==="boolean"&&reported.ok!==ours){
      disagreements.push({capsule_id:cid,ours:ours,reported:reported.ok});
    }
  }
  if(!disagreements.length){
    var n=Object.keys(selfReport).length;
    return{status:"pass",detail:n?("producer self-report agrees with independent recompute for all "+n+" record(s)"):"no producer self-report present; independent recompute is the only signal (see Integrity)"};
  }
  return{status:"fail",detail:disagreements.length+" record(s) where the producer's self-reported verdict "+
    "disagrees with this viewer's own independent recompute — trust the recompute, investigate the bundle"};
}

/* ---------- plain-language summary (renders on EVERY bundle) ----------
 * The ritual answers "does this verify". It does not answer "what happened",
 * and until now a clean bundle said almost nothing — four terse stage lines and
 * no prose. A stranger handed a permalink could see green checks without ever
 * learning what the records claim, or which claims carry weaker assurance.
 * This states, in English, what the records say AND what they don't establish.
 * It never asserts more than the fields carry. */
function describeBundle(capsules){
  var caps=capsules.map(unwrapEnvelope).filter(function(c){return c&&c.capsule_id;});
  if(!caps.length)return null;
  var n=caps.length,parts=[];

  var ts=caps.map(function(c){return c.timestamp;}).filter(Boolean).sort();
  var when=ts.length?(ts[0]===ts[ts.length-1]?("at "+ts[0]):("between "+ts[0]+" and "+ts[ts.length-1])):null;
  var ops={};caps.forEach(function(c){if(c.operator)ops[c.operator]=1;});
  var opNames=Object.keys(ops);
  parts.push(n+" record"+(n===1?"":"s")+(when?", "+when:"")
    +(opNames.length===1?", from operator “"+opNames[0]+"”":
      opNames.length>1?", from "+opNames.length+" operators":"")+".");

  var kinds={};caps.forEach(function(c){var t=c.action_type||"unspecified";kinds[t]=(kinds[t]||0)+1;});
  var kindBits=Object.keys(kinds).map(function(k){
    var label=k==="fyi"?"informational":k==="decide"?"decision":k==="act"?"action":k;
    return kinds[k]+" "+label+(kinds[k]===1?"":"s");
  });
  if(kindBits.length)parts.push(kindBits.join(", ")+".");

  var accepted=0,rejected=0,human=0;
  caps.forEach(function(c){
    var d=c.disposition||{};
    if(d.decision==="accept")accepted++;
    else if(d.decision==="reject"||d.decision==="deny")rejected++;
    if(d.human_disposed===true)human++;
  });
  if(rejected)parts.push(rejected+" of "+n+" "+(rejected===1?"was":"were")+" refused.");
  if(accepted===n&&n>0)parts.push("All were accepted.");
  parts.push(human===0
    ? "No human approved any of them — every disposition was made by policy."
    : human+" of "+n+" carried a recorded human disposition.");

  /* Assurance is the part a reader cannot infer and most needs. */
  var selfAtt=0,unconfirmed=0;
  caps.forEach(function(c){
    var a=c.assurance||{};
    if(a.attestation_mode==="self_attested")selfAtt++;
    if(a.effect_mode==="dispatched_unconfirmed")unconfirmed++;
  });
  if(unconfirmed)parts.push(unconfirmed+" record"+(unconfirmed===1?"":"s")+" report"+(unconfirmed===1?"s":"")
    +" the effect as dispatched but unconfirmed — the runtime says it sent the action; nothing here confirms it landed.");
  if(selfAtt===n&&n>0)parts.push("Every record is self-attested: the same party took the action and wrote the record.");

  var withheld=0;
  caps.forEach(function(c){
    var ca=((c.model_attestation||{}).compute_attestation)||{};
    if(ca.agent_input_digest||ca.agent_output_digest)withheld++;
  });
  if(withheld)parts.push("Inputs and outputs are committed as digests only — the payloads are not in "
    +(withheld===n?"these records":"all of these records")+", so their contents cannot be read here, only matched if someone later discloses them.");

  return{code:"summary",label:"What these records say",text:parts.join(" "),
    meta:"plain-language summary of the fields carried; it makes no claim the ritual did not check"};
}

/* ---------- ritual: Integrity / Sequence / Completeness / Cross-check ---------- */
async function evaluateBundleRitual(records,completeness,crossCheck,integrity,disclosures){
  var stages=[],finding=null;
  var alteredIds={},firstMismatch=null,firstMismatchIsBody=false;
  disclosures=disclosures||{};
  for(var idx=0;idx<records.length;idx++){
    var c=records[idx];
    if(!isH64(c.capsule_id))continue;
    var idr=integrity&&integrity[idx];
    if(idr&&idr.ok===false){
      alteredIds[c.capsule_id]=true;
      if(!firstMismatch){firstMismatch=idr;firstMismatchIsBody=true;}
    }
    var g=await verifyCapsuleDigests(c,disclosures[c.capsule_id]);
    var bad=g.privlog.filter(function(e){return e.matchOk===false;});
    if(bad.length){alteredIds[c.capsule_id]=true;if(!firstMismatch){firstMismatch=bad[0];firstMismatchIsBody=false;}}
  }
  if(Object.keys(alteredIds).length){
    if(firstMismatchIsBody){
      stages.push({name:"Integrity",status:"fail",
        detail:"capsule_id does not match the recomputed digest of its own body — stated "+sh(firstMismatch.stated)+", recomputed "+(firstMismatch.recomputed?sh(firstMismatch.recomputed):"(could not be computed)")});
      finding={label:"The finding",
        text:"This capsule's content does not hash to its stated capsule_id. The body has been altered after the id was assigned — they no longer content-address to each other.",
        meta:"failed stage: capsule_id_mismatch · stated capsule_id "+firstMismatch.stated+" · recomputed "+(firstMismatch.recomputed||"(error)")};
    }else{
      stages.push({name:"Integrity",status:"fail",
        detail:"record fails at stage digest_mismatch — "+firstMismatch.ctx+" no longer matches its fingerprint"});
      finding={label:"The finding",
        text:firstMismatch.id+" ("+firstMismatch.ctx+") is not the value that was sealed.",
        meta:"failed stage: digest_mismatch · field group: "+firstMismatch.ctx+" · digest "+firstMismatch.digest.slice(0,8)+"…"};
    }
  }else{
    stages.push({name:"Integrity",status:"pass",detail:"every record matches its fingerprint"});
  }

  /* Same three-valued Sequence as the capsule surface: a bundle where nothing
   * declares a parent must not render as "unbroken". See CAPSULE_JS. */
  var _capsForSeq=records.map(unwrapEnvelope);
  var _declared=0;
  _capsForSeq.forEach(function(c){
    if(isH64(((c.chain)||{}).parent_capsule_id||""))_declared++;
  });
  var _expectedLinks=Math.max(0,_capsForSeq.length-1);

  var gaps=findChainGaps(records);
  if(_capsForSeq.length<2){
    stages.push({name:"Sequence",status:"skip",detail:"single record — nothing to sequence"});
  }else if(_declared===0){
    stages.push({name:"Sequence",status:"skip",
      detail:"not checked — no record here declares a parent, so the order shown is presentation order, not an attested sequence"});
  }else if(gaps.length){
    var g0=gaps[0];
    stages.push({name:"Sequence",status:"fail",
      detail:"gap between record "+(g0.beforeIdx+1)+" and record "+(g0.afterIdx+1)+" — record "+(g0.afterIdx+1)+" names a parent that is not here"});
    if(!finding){
      finding={label:"The finding",
        text:"Whatever sits between record "+(g0.beforeIdx+1)+" and record "+(g0.afterIdx+1)+" is not in this bundle.",
        meta:"failed stage: chain_gap · missing parent "+g0.missingParent.slice(0,8)+"…"};
    }
  }else if(_declared<_expectedLinks){
    stages.push({name:"Sequence",status:"skip",
      detail:"partial — "+_declared+" of "+_expectedLinks+" expected links declared; the undeclared positions are not attested as adjacent"});
  }else{
    stages.push({name:"Sequence",status:"pass",detail:"unbroken — every record names the one before it"});
  }

  stages.push({name:"Completeness",status:completeness.status,detail:completeness.detail});
  stages.push({name:"Cross-check",status:crossCheck.status,detail:crossCheck.detail});

  return{stages:stages,finding:finding,summary:describeBundle(records)};
}

/* ---------- privilege log (aggregated across every record) ----------
 * Awaits verifyCapsuleDigests per record first, so every REVEALED row's
 * matchOk is already resolved true/false by the time this returns — the
 * displayed log and the ritual/cross-check verdicts read the same, single
 * digest-verification pass, never two independent (and divergent) ones. */
async function buildBundlePrivlog(records,disclosures){
  var rows=[];
  disclosures=disclosures||{};
  for(var i=0;i<records.length;i++){
    var g=await verifyCapsuleDigests(records[i],disclosures[records[i].capsule_id]);
    g.privlog.forEach(function(e){
      rows.push({record_index:i,capsule_id:records[i].capsule_id||"",entry:e});
    });
  }
  return rows;
}

/* ---------- render/DOM section: everything below touches document/window --------- */
(function(){"use strict";

function $(id){return document.getElementById(id);}

function renderPrivlog(rows){
  var el=$("privlogContent");if(!el)return;
  if(!rows.length){el.innerHTML="<p style='color:var(--muted);font-size:13px'>No committed artifacts found across these records.</p>";return;}
  var h="<table class='pltable'><thead><tr><th>#</th><th>artifact</th><th>type</th><th>digest</th><th>status</th><th>payload</th><th>context</th></tr></thead><tbody>";
  rows.forEach(function(r,idx){
    var e=r.entry;
    var st=e.withheld?"<span class='pl-withheld'>WITHHELD</span>":
            e.matchOk===true?"<span class='pl-match'>REVEALED · ✓ match</span>":
            e.matchOk===false?"<span class='pl-mismatch'>REVEALED · ✗ MISMATCH</span>":
            "<span class='pl-revealed'>REVEALED</span>";
    h+="<tr data-idx='"+idx+"' data-dig='"+safe(e.digest)+"'><td>"+(r.record_index+1)+"</td><td>"+safe(e.id)+"</td>"+
      "<td>"+safe(e.type)+(e.isKnown?"":' <em class="opaque-badge">OPAQUE</em>')+"</td>"+
      "<td><code>"+safe(e.digest.slice(0,16))+"…</code></td><td class='pl-st'>"+st+"</td>"+
      "<td class='pl-payload'>"+payloadCellHtml(e,e._recomputedDigest)+"</td><td class='pl-ctx'>"+safe(e.ctx)+"</td></tr>";
  });
  h+="</tbody></table>";
  el.innerHTML=h;
  $("privlogSection").style.display="block";
  // matchOk is already resolved (buildBundlePrivlog awaits
  // verifyCapsuleDigests before this is called) -- no second, independent
  // digest pass here; the table above already reflects the real verdict.
}

function renderRecordsTable(records,integrity){
  var el=$("recordsTableContent");if(!el)return;
  var notes=annotateRecords(records,integrity);
  var gaps=findChainGaps(records),gapAt={};
  gaps.forEach(function(g){gapAt[g.afterIdx]=g;});
  var h="<table class='records-table'><thead><tr><th>#</th><th>capsule_id</th><th>action_type</th><th>note</th></tr></thead><tbody>";
  records.forEach(function(cap,i){
    if(gapAt[i]){
      var gp=gapAt[i];
      h+="<tr class='rec-row rec-gap'><td>—</td><td colspan='2'>gap — missing parent <code>"+safe(gp.missingParent.slice(0,8))+"…</code></td><td>⌗ chain_gap</td></tr>";
    }
    var n=notes[i];
    var noteText=n.note==="digest_mismatch"?"✕ digest_mismatch":
      n.note==="cites an altered record"?"✓ verifies · cites an altered record":"✓ verifies";
    h+="<tr class='rec-row"+(n.isAltered?" rec-altered":(n.citesAltered?" rec-flagged":""))+"'>"+
      "<td>"+(i+1)+"</td><td><code>"+safe((cap.capsule_id||"").slice(0,16))+"…</code></td>"+
      "<td><code>"+safe(cap.action_type||"")+"</code></td><td>"+noteText+"</td></tr>";
  });
  h+="</tbody></table>";
  el.innerHTML=h;
}

function renderRitual(summary){
  var mount=$("ritualMount");if(!mount)return;
  var marks={pass:"✓",fail:"✕",skip:"–"};
  var h="<div class='ritual-stages'>";
  summary.stages.forEach(function(s){
    h+="<div class='ritual-stage ritual-"+s.status+"'><span class='ritual-mark'>"+marks[s.status]+"</span>"+
      "<span class='ritual-name'>"+safe(s.name)+"</span><span class='ritual-detail'>"+safe(s.detail)+"</span></div>";
  });
  h+="</div>";
  if(summary.summary){
    var sm=summary.summary;
    h+="<div class='finding-panel finding-summary'><div class='finding-label'>"+safe(sm.label)+"</div>"+
      "<p class='finding-text'>"+safe(sm.text)+"</p><div class='finding-meta'>"+safe(sm.meta)+"</div></div>";
  }
  if(summary.finding){
    var f=summary.finding;
    h+="<div class='finding-panel finding-fail'><div class='finding-label'>"+safe(f.label)+"</div>"+
      "<p class='finding-text'>"+safe(f.text)+"</p><div class='finding-meta'>"+safe(f.meta)+"</div></div>";
  }
  mount.innerHTML=h;
}

function renderCompletenessCard(c){
  var mount=$("completenessMount");if(!mount)return;
  var label=c.status==="pass"?"Completeness — verified":c.status==="fail"?"Completeness — FAILED":"Completeness — not available";
  mount.innerHTML="<div class='completeness-card status-"+c.status+"'><div class='completeness-title'>"+safe(label)+
    "</div><div class='completeness-detail'>"+safe(c.detail)+"</div></div>";
}

/* ---------- load + permalink + offline download ---------- */
var _bundleData=null,_fragmentB64u=null;

function permalinkBase(){
  if(location.protocol==="file:"||location.protocol==="blob:")return "https://verify.agentactioncapsule.org/bundle";
  return location.origin+location.pathname;
}

async function loadBundle(data,fragmentB64u){
  _bundleData=data;
  _fragmentB64u=fragmentB64u||encodeFragment(data);
  var records=data.records||[];
  var range=data.range||[0,-1];
  var ckpt=data.checkpoint||{};

  $("emptyState")&&($("emptyState").style.display="none");
  $("pasteSection")&&($("pasteSection").style.display="none");

  var summaryEl=$("bundleSummary");
  if(summaryEl){
    summaryEl.textContent=records.length+" record(s) · range "+range[0]+"–"+range[1]+
      " · checkpoint #"+(ckpt.tree_size!=null?ckpt.tree_size:"?");
  }
  var permalinkEl=$("permalinkText");
  if(permalinkEl)permalinkEl.textContent=permalinkBase()+"#"+_fragmentB64u.slice(0,24)+"…";
  var dl=$("downloadBtn");if(dl){dl.disabled=false;dl.style.opacity="1";}
  var cp=$("copyLinkBtn");if(cp){cp.disabled=false;cp.style.opacity="1";}

  var integrity=await Promise.all(records.map(verifyCapsuleId));

  var privlog=await buildBundlePrivlog(records,data.disclosures);
  renderPrivlog(privlog);
  renderRecordsTable(records,integrity);

  var completeness=await checkCompleteness(data);
  renderCompletenessCard(completeness);
  var crossCheck=await crossCheckSelfReport(data,records);
  var ritual=await evaluateBundleRitual(records,completeness,crossCheck,integrity,data.disclosures);
  renderRitual(ritual);

  try{ history.replaceState(null,"",location.pathname+location.search+"#"+_fragmentB64u); }catch(ex){}
}

function bootstrapLoad(){
  if(typeof window!=="undefined"&&window.__BUNDLE_FRAGMENT_B64U__&&window.__BUNDLE_FRAGMENT_B64U__!=="@@BUNDLE_FRAGMENT@@"){
    try{
      var frag=window.__BUNDLE_FRAGMENT_B64U__;
      loadBundle(decodeFragment(frag),frag);
      return;
    }catch(ex){ $("parseErr")&&($("parseErr").textContent="Embedded bundle decode error: "+ex.message); }
  }
  var hash=location.hash.slice(1);
  if(hash){
    try{ loadBundle(decodeFragment(hash),hash); return; }
    catch(ex){ $("parseErr")&&($("parseErr").textContent="Fragment decode error: "+ex.message); }
  }
  $("emptyState")&&($("emptyState").style.display="block");
}

$("loadBtn")&&$("loadBtn").addEventListener("click",function(){
  var txt=$("bundleJson").value.trim();
  try{ loadBundle(JSON.parse(txt)); }
  catch(ex){ $("parseErr").textContent="JSON error: "+ex.message; }
});

$("copyLinkBtn")&&$("copyLinkBtn").addEventListener("click",function(){
  if(!_fragmentB64u||!navigator.clipboard)return;
  navigator.clipboard.writeText(permalinkBase()+"#"+_fragmentB64u).then(function(){
    var b=$("copyLinkBtn");var old=b.textContent;b.textContent="Copied!";setTimeout(function(){b.textContent=old;},2000);
  });
});

$("downloadBtn")&&$("downloadBtn").addEventListener("click",function(){
  if(!_fragmentB64u)return;
  fetch("/bundle/offline-shell").then(function(r){return r.text();}).then(function(html){
    var out=html.replace("@@BUNDLE_FRAGMENT@@",_fragmentB64u);
    var blob=new Blob([out],{type:"text/html"});
    var a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download="bundle-viewer.html";
    document.body.appendChild(a);a.click();document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }).catch(function(){
    var b=$("downloadBtn");if(b){var old=b.textContent;b.textContent="Offline copy unavailable";setTimeout(function(){b.textContent=old;},2500);}
  });
});

bootstrapLoad();
})();
"""


def _referrer_domain(referer: str) -> str | None:
    """Extract eTLD+1 from Referer header; None for same-origin/missing."""
    if not referer:
        return None
    try:
        from urllib.parse import urlparse
        host = urlparse(referer).hostname or ""
        if not host or host in ("verify.actionstate.ai", "localhost", "127.0.0.1"):
            return None
        parts = host.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:  # noqa: BLE001
        return None


def _instrument_capsule_view(referer: str = "") -> None:
    """Increment anonymous counters only — no content retained."""
    _CAPSULE_VIEW_COUNTER[0] += 1
    domain = _referrer_domain(referer)
    if domain:
        _REFERRER_COUNTER[domain] = _REFERRER_COUNTER.get(domain, 0) + 1


def _ed25519_hex_to_pem(raw_hex: str) -> str:
    """Wrap a raw 32-byte Ed25519 key (hex) in PEM SubjectPublicKeyInfo."""
    raw = bytes.fromhex(raw_hex)
    # SubjectPublicKeyInfo header for OID 1.3.101.112 (Ed25519)
    spki = bytes.fromhex("302a300506032b6570032100") + raw
    b64 = base64.b64encode(spki).decode()
    return f"-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"


def _anchor_proxy_json(capsule_id: str) -> dict:
    """Fetch anchor status and verify receipt for *capsule_id* (server-side, avoids CORS).

    Calls ``GET /v1/inclusion/{capsule_id}`` on the anchor — a read-only resolve
    endpoint added in capsule-anchor PR #11.  200 → anchored; 404 → not found.
    The returned bundle contains ``receipt_b64`` and ``entry_hash`` so we can
    verify the RFC 9162 inclusion proof locally without a second round-trip.

    Returns a JSON-serialisable dict; ``error`` key is set on failure.
    Live against anchor.agentactioncapsule.org — RFC 9162 SHA-256 inclusion proof.
    """
    import urllib.error
    import urllib.request

    result: dict = {
        "capsule_id": capsule_id,
        "anchored": False,
        "receipt_verified": False,
        "log_index": None,
        "logged_at": None,
        "leaf_index": None,
        "tree_size": None,
        "error": None,
        # Anchoring-evidence rung (docs/ledger-grade.md §4 twin, same five-value
        # vocabulary as agent_action_capsule.history.RUNGS). This surface talks
        # to ONE anchor and reports only what THAT anchor knows: "standalone"
        # here means "not found at this anchor", never a claim about a
        # capsule's full cross-party state. None on a real transport error —
        # not found and unreachable are different things.
        "rung": "standalone",
    }

    def _fetch_json(url: str) -> object:
        req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        with urllib.request.urlopen(req, timeout=8) as r:  # noqa: S310
            return json.loads(r.read())

    try:
        # GET /v1/inclusion/{capsule_id} — 200 present / 404 absent (PR #11)
        inclusion = _fetch_json(f"{_ANCHOR_BASE}/v1/inclusion/{capsule_id}")

        result["anchored"] = True
        result["leaf_index"] = inclusion.get("leaf_index")
        result["tree_size"] = inclusion.get("tree_size")
        # log_index == leaf_index for this log (sequential, 0-based)
        result["log_index"] = inclusion.get("leaf_index")
        # _ANCHOR_BASE is this deployment's public transparency service, so a
        # found entry defaults to publicly-anchored; an inclusion response MAY
        # override with an explicit visibility hint (same vocabulary as the
        # library's inclusion_proofs), never grading ABOVE what it states.
        result["rung"] = _VISIBILITY_TO_RUNG.get(inclusion.get("visibility"), "publicly-anchored")

        receipt_b64 = inclusion.get("receipt_b64", "")
        entry_hash = inclusion.get("entry_hash", "")

        if receipt_b64 and entry_hash:
            try:
                pubkey_data = _fetch_json(f"{_ANCHOR_BASE}/anchor/authority-pubkey")
                pubkey_hex = pubkey_data.get("pubkey_hex", "")
                log_pem = _ed25519_hex_to_pem(pubkey_hex) if len(pubkey_hex) == 64 else None

                if log_pem:
                    receipt_bytes = base64.b64decode(receipt_b64 + "==")
                    vr = verify_receipt(
                        receipt_bytes,
                        leaf_entry_hex=entry_hash,
                        log_public_key_pem=log_pem.encode(),
                    )
                    result["receipt_verified"] = vr.ok
                    if not vr.ok:
                        result["receipt_errors"] = list(vr.errors)
            except Exception as exc:  # noqa: BLE001
                result["receipt_verify_error"] = str(exc)

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # capsule_id not found in log — not an error, just not anchored
            return result
        result["error"] = f"anchor returned HTTP {exc.code}"
        result["rung"] = None   # unreachable/errored is not the same claim as "not found"
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        result["rung"] = None

    return result


def _capsule_id_from_path(path: str, prefix: str) -> str | None:
    """Extract the 64-hex capsule_id from a path like /v/<id> or /anchor-status/<id>."""
    stripped = path.lstrip("/")
    if not stripped.startswith(prefix.lstrip("/")):
        return None
    tail = stripped[len(prefix.lstrip("/")):]
    cid = tail.strip("/")
    if len(cid) == 64 and all(c in "0123456789abcdefABCDEF" for c in cid):
        return cid.lower()
    return None


#: URL for the regulatory crosswalk document (public repo path).
_REG_CROSSWALK_URL = (
    "https://github.com/action-state-group/agent-action-capsule"
    "/blob/main/docs/regulatory-crosswalk.md"
)

#: Crosswalk rows by property — (regulation, article_summary, property_id).
#: Rendered in the regulatory-context panel on the capsule permalink page.
#: Property IDs drive panel gating: tamper-evident-log (receipt), human-oversight
#: (disposition+human_disposed), disclosure-transparency (withheld commitments).
_CROSSWALK_ROWS: tuple[tuple[str, str, str], ...] = (
    # tamper-evident-log rows (shown when anchor receipt present)
    ("EU AI Act Art 12(1)", "Automatic logging capabilities for high-risk AI systems", "tamper-evident-log"),
    ("EU AI Act Art 12(2)", "Level of traceability appropriate to the system's purpose", "tamper-evident-log"),
    ("DORA Art 9(4)", "ICT security policies — logging and monitoring", "tamper-evident-log"),
    ("DORA Art 10(1)-(2)", "Detection of anomalous activity", "tamper-evident-log"),
    ("DORA Art 17(3)(b)", "ICT incident records", "tamper-evident-log"),
    ("SEC Rule 17a-4(f)(2)(ii)(A)", "Non-rewriteable, non-erasable electronic records", "tamper-evident-log"),
    ("FINRA Rule 4511(c)", "17a-4 format compliance", "tamper-evident-log"),
    ("NSA CSI U/OO/6030316-26 (May 2026)", "Structured audit records of all MCP tool interactions", "tamper-evident-log"),
    ("ASD ACSC et al. (May 2026)", "Comprehensive logging and audit trails for all agent actions and decisions", "tamper-evident-log"),
    # human-oversight-record rows (shown when disposition + human_disposed present)
    ("EU AI Act Art 50(2)/(3)", "Notice and disclosure to persons subject to AI interaction", "human-oversight-record"),
    ("MAS SAFR (Jul 2026)", "Human oversight and decision review", "human-oversight-record"),
    ("FCA AI accountability (FS23/5)", "Transparency of AI decision-making", "human-oversight-record"),
    ("NIST AI RMF MANAGE 1.3", "High-priority risk response planning and documentation", "human-oversight-record"),
    ("NSA CSI U/OO/6030316-26 (May 2026)", "Approval workflows for agentic capability and data-access changes", "human-oversight-record"),
    ("ASD ACSC et al. (May 2026)", "Mandatory human approval for high-impact agentic decisions", "human-oversight-record"),
    # disclosure-transparency-record rows (shown when withheld commitments present)
    ("EU AI Act Art 50(1)", "Machine-readable AI-content marking", "disclosure-transparency-record"),
    ("NIST AI RMF MEASURE 2.8", "Transparency and accountability risks", "disclosure-transparency-record"),
    ("prEN 18229-1", "Transparency documentation requirements for AI systems", "disclosure-transparency-record"),
    ("NSA CSI U/OO/6030316-26 (May 2026)", "Filter and validate tool output before downstream consumption", "disclosure-transparency-record"),
    ("ASD ACSC et al. (May 2026)", "Trust classification of all external and tool-provided content", "disclosure-transparency-record"),
    # per-action-attribution rows — always shown (capsule_id + operator + developer are always present)
    ("EU AI Act Art 26(6)", "Deployer log retention", "per-action-attribution"),
    ("DORA Art 17(3)(b)", "ICT incident records — attribution", "per-action-attribution"),
    ("NIST AI RMF GOVERN 1.1", "Risk management policies and practices", "per-action-attribution"),
    ("FCA AI accountability (FS23/5)", "Accountability and audit trails", "per-action-attribution"),
    ("NSA CSI U/OO/6030316-26 (May 2026)", "Message signing, expiration timestamps, and replay-protection metadata", "per-action-attribution"),
    ("ASD ACSC et al. (May 2026)", "Cryptographically anchored per-agent identity and delegation chain traceability", "per-action-attribution"),
)

_PROP_LABELS: dict[str, str] = {
    "tamper-evident-log": "tamper-evident-log",
    "human-oversight-record": "human-oversight-record",
    "disclosure-transparency-record": "disclosure-transparency-record",
    "per-action-attribution": "per-action-attribution",
}


def _is_hex64(s: object) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def _unwrap_envelope(data: dict) -> dict:
    """Python mirror of ``CAPSULE_JS``'s ``unwrapEnvelope()``.

    Unwraps a Disclosure Envelope (``{"capsule": {...}, "disclosures": {...}}``)
    to the underlying capsule. A bare capsule (no "capsule" key) passes through
    unchanged.
    """
    inner = data.get("capsule") if isinstance(data, dict) else None
    return inner if isinstance(inner, dict) else data


def _capsule_has_hitl(cap: dict) -> bool:
    """Python mirror of ``CAPSULE_JS``'s ``checkHitl()`` — kept in parity by tests.

    §5.4/5.5: ``human_disposed`` lives INSIDE the ``disposition`` block, not at
    the capsule top level; ``disposition.approver == "human"`` independently
    signals human-oversight per the regulatory crosswalk (both cited for
    ``human-oversight-record``). Unwraps a Disclosure Envelope first — for
    ``{"capsule": {...}, "disclosures": {...}}``, disposition lives at
    ``data.capsule.disposition``, not at the top level.
    """
    cap = _unwrap_envelope(cap)
    disposition = cap.get("disposition") if isinstance(cap, dict) else None
    if not disposition:
        return False
    return disposition.get("human_disposed") is True or disposition.get("approver") == "human"


def _capsule_has_sd(cap: dict) -> bool:
    """Python mirror of ``CAPSULE_JS``'s ``checkSd()`` — kept in parity by tests.

    Same envelope-unwrap as ``_capsule_has_hitl``: a Disclosure-Envelope-wrapped
    fragment carries ``model_attestation``/``constraints``/``withheld_commitments``
    at ``data.capsule.*``, not at the top level.
    """
    cap = _unwrap_envelope(cap)
    if not isinstance(cap, dict):
        return False
    ca = ((cap.get("model_attestation") or {}).get("compute_attestation")) or {}
    return bool(
        cap.get("withheld_commitments")
        or any(c.get("evidence_digest") for c in (cap.get("constraints") or []))
        or _is_hex64(ca.get("agent_input_digest", ""))
        or _is_hex64(ca.get("agent_output_digest", ""))
    )


def _render_reg_panel(has_receipt: bool, has_hitl: bool, has_withheld: bool) -> str:
    """Return HTML for the regulatory-context collapsible panel.

    Property-driven: rows are filtered by which structural properties are
    detected in the capsule.  No scores, no checkmarks against regulations.

    Args:
        has_receipt:  True if an anchor receipt is present (tamper-evident-log).
        has_hitl:     True if disposition + human_disposed fields are present
                      (human-oversight-record).
        has_withheld: True if withheld commitments (SD) block is present
                      (disclosure-transparency-record).
    """
    # per-action-attribution is always shown — capsule_id + operator + developer
    # are structural invariants of every capsule.
    active_props: set[str] = {"per-action-attribution"}
    if has_receipt:
        active_props.add("tamper-evident-log")
    if has_hitl:
        active_props.add("human-oversight-record")
    if has_withheld:
        active_props.add("disclosure-transparency-record")

    rows_html = "\n".join(
        f"<tr><td>{_esc(reg)}</td><td>{_esc(summary)}</td>"
        f"<td><span class='reg-prop'>{_esc(prop_id)}</span></td></tr>"
        for reg, summary, prop_id in _CROSSWALK_ROWS
        if prop_id in active_props
    )

    props_shown = ", ".join(sorted(active_props))
    crosswalk_url = _esc(_REG_CROSSWALK_URL)

    return f"""<details class="reg-panel" open>
  <summary>Regulatory context (informational) <span style="font-weight:400;font-size:12px;color:var(--muted);margin-left:8px">properties detected: {_esc(props_shown)}</span></summary>
  <div class="reg-panel-body">
    <p class="reg-disclaimer">This panel identifies structural properties of this record. It is not legal advice. Consult the <a href="{crosswalk_url}" target="_blank" rel="noopener noreferrer">full crosswalk</a> for instrument citations and limits.</p>
    <table class="reg-table">
      <thead>
        <tr><th>Regulation / Article</th><th>Summary</th><th>Property</th></tr>
      </thead>
      <tbody>
{rows_html}
      </tbody>
    </table>
  </div>
</details>"""


def render_capsule_page(capsule_id: str) -> str:
    """Return the HTML for ``GET /v/<capsule_id>`` — the AAC capsule verification page."""
    short_id = f"{capsule_id[:8]}…{capsule_id[-4:]}"
    cid = _esc(capsule_id)
    sid = _esc(short_id)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Capsule {sid} — Agent Action Capsule Verifier</title>
<style>
{_PAGE_CSS}
{_CAPSULE_CSS}
</style>
</head>
<body data-capsule-id="{cid}">
<nav>
  <div class="nav-in">
    <a class="brand" href="https://agentactioncapsule.org">
      <span class="glyph"></span> Agent Action Capsule <span class="svc">Verifier</span>
    </a>
    <div class="nav-links">
      <a href="https://agentactioncapsule.org">Standard</a>
      <a href="https://anchor.agentactioncapsule.org">Transparency Log</a>
      <a href="/" class="active">Verifier</a>
      <a href="https://agentactioncapsule.org/docs/">Docs</a>
    </div>
  </div>
</nav>

<div class="wrap" style="padding:32px 0 16px">
  <div class="pill">capsule · Agent Action Capsule profile</div>
  <h1 style="margin-top:12px">Capsule <code class="mono" style="font-size:1.1rem">{sid}</code></h1>
  <p class="mono" style="font-size:11.5px;word-break:break-all;color:var(--muted);margin-top:6px">{cid}</p>
</div>

<div class="wrap" style="margin-bottom:8px">
  <div class="anchor-banner anchor-loading" id="anchorBanner">Checking anchor status…</div>
</div>

<section id="ritualSection" class="band" style="display:none">
  <div class="wrap">
    <div class="sec-eyebrow">Verification ritual</div>
    <h2 class="sec-title">Integrity · Sequence · Authenticity · Witness</h2>
    <p style="font-size:14px;color:var(--muted);margin-bottom:16px">
      Failure is precise: the stage that failed is named, the finding has a location,
      and everything that still verifies keeps its verdict. Unreachable is never rendered as disproven.
    </p>
    <div id="ritualMount"></div>
  </div>
</section>

<section id="chainNav" class="band" style="display:none">
  <div class="wrap">
    <div class="sec-eyebrow">Capsule Chain</div>
    <h2 class="sec-title">Chain navigation</h2>
    <div id="chainTableContent"></div>
    <div class="chain-nav-btns">
      <button id="chainPrevBtn" class="verify-btn" style="opacity:.5" disabled>&#x2190; Previous</button>
      <span class="chain-pos" id="chainPos"></span>
      <button id="chainNextBtn" class="verify-btn" style="opacity:.5" disabled>Next &#x2192;</button>
    </div>
  </div>
</section>

<section id="graphSection" class="band" style="display:none">
  <div class="wrap">
    <div class="sec-eyebrow">Digest Graph</div>
    <h2 class="sec-title">Artifact nodes and typed references</h2>
    <div id="graphContent"></div>
  </div>
</section>

<section id="privlogSection" class="band" style="display:none">
  <div class="wrap">
    <div class="sec-eyebrow">Privilege Log</div>
    <h2 class="sec-title">Disclosed vs. withheld artifacts</h2>
    <p style="font-size:14px;color:var(--muted);margin-bottom:16px">
      WITHHELD = digest committed in the capsule; payload not provided here.<br>
      REVEALED = payload provided; hash recomputed and checked against the committed digest.
    </p>
    <div id="privlogContent"></div>
  </div>
</section>

<section id="inclusionSection" class="band" style="display:none">
  <div class="wrap">
    <div class="sec-eyebrow">Witnessed Entry</div>
    <h2 class="sec-title">Entry witnessed in transparency log</h2>
    <table class="etable" style="max-width:640px;margin-bottom:16px">
      <tbody>
        <tr><td>digest</td><td><code id="inclDigest" style="word-break:break-all;font-size:12px"></code></td></tr>
        <tr><td>leaf</td><td id="inclLeaf"></td></tr>
        <tr><td>tree-size</td><td id="inclTree"></td></tr>
        <tr><td>receipt</td><td id="inclReceipt"></td></tr>
        <tr><td>format</td><td style="color:var(--muted)">unrecognized — opaque bytes</td></tr>
      </tbody>
    </table>
    <p class="opaque-note">
      This entry's payload is in an unrecognized format. The witnessing is verified;
      the bytes are untouched and not displayed here.
      Your format, witnessed, untouched.
    </p>
  </div>
</section>

<section id="pasteSection" class="band">
  <div class="wrap">
    <div class="sec-eyebrow">Capsule data</div>
    <h2 class="sec-title">Paste capsule JSON to render the graph and privilege log</h2>
    <p style="font-size:14px;color:var(--muted);margin-bottom:16px">
      The JSON goes into the URL fragment only — never sent to this server.<br>
      <strong>Unknown artifact types render VERIFIED-BUT-OPAQUE</strong>: verification is
      uniform across all types; only the rendering is profile-specific.
    </p>
    <div class="tool">
      <div class="tool-body">
        <div class="field">
          <label>Capsule JSON
            <span class="opt">bilateral binding or single capsule</span>
          </label>
          <textarea id="capsuleJson" style="min-height:120px"
            placeholder='{{"buyer_capsule": {{...}}, "seller_capsule": {{...}}, "sealed_terms_hash": "...", "terms": {{...}}}}'></textarea>
        </div>
        <p id="parseErr" style="color:var(--fail);font-family:var(--mono);font-size:12px;margin:8px 0;min-height:18px"></p>
        <div class="actions">
          <button class="verify-btn" id="loadBtn">Load capsule &#x2192;</button>
          <button class="verify-btn" id="linkBtn" disabled style="opacity:.5">Copy permalink</button>
        </div>
      </div>
    </div>
    <div class="note" style="margin-top:16px">
      <strong>Permalink:</strong> paste JSON → Load → Copy permalink.
      The link embeds the full capsule JSON in the URL fragment so anyone can re-verify
      without trusting this server.
    </div>
  </div>
</section>

<section id="regPanelSection" class="band" style="display:none">
  <div class="wrap">
    <div id="regPanelMount"></div>
  </div>
</section>

<footer>
  <div class="wrap">
    <div class="foot-in">
      <div class="foot-brand">
        <a class="brand" href="https://agentactioncapsule.org">
          <span class="glyph"></span> Agent Action Capsule <span class="svc">Verifier</span>
        </a>
        <p>Stateless public verification surface for Agent Action Capsule records.
        Anchor: <a href="https://anchor.agentactioncapsule.org">anchor.agentactioncapsule.org</a>.</p>
      </div>
      <div class="foot-cols">
        <div class="foot-col">
          <h5>Standard</h5>
          <a href="https://agentactioncapsule.org">Overview</a>
          <a href="https://agentactioncapsule.org/docs/">Docs</a>
          <a href="https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/">Internet-Draft &#x2197;</a>
        </div>
        <div class="foot-col">
          <h5>Services</h5>
          <a href="https://anchor.agentactioncapsule.org">Transparency Log</a>
          <a href="/">Verifier</a>
        </div>
        <div class="foot-col">
          <h5>Privacy</h5>
          <a href="/instrumentation-policy">Instrumentation policy</a>
          <a href="{_esc(REPO_URL)}">Source &#x2197;</a>
        </div>
      </div>
    </div>
    <div class="foot-note">Stateless &#xb7; retains nothing &#xb7; Apache-2.0 &#xb7; Action State Group</div>
  </div>
</footer>

<script src="/static/capsule.js"></script>
</body>
</html>
"""


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
    <a class="brand" href="https://agentactioncapsule.org"><span class="glyph"></span> Agent Action Capsule <span class="svc">Verifier</span></a>
    <div class="nav-links">
      <a href="https://agentactioncapsule.org">Standard</a>
      <a href="https://anchor.agentactioncapsule.org">Transparency Log</a>
      <a class="active" href="/">Verifier</a>
      <a href="https://agentactioncapsule.org/docs/">Docs</a>
      <a class="nav-ghost" href="https://github.com/action-state-group">Source ↗</a>
      <a href="https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/">Draft (IETF) ↗</a>
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
      <div class="foot-brand">
        <a class="brand" href="https://agentactioncapsule.org"><span class="glyph"></span> Agent Action Capsule <span class="svc">Verifier</span></a>
        <p>An open profile on IETF SCITT for verifiable records of agent actions. Neutral substrate for the agent ecosystem, stewarded by Action State Group.</p>
      </div>
      <div class="foot-cols">
        <div class="foot-col">
          <h5>Standard</h5>
          <a href="https://agentactioncapsule.org">Overview</a>
          <a href="https://agentactioncapsule.org/docs/">Docs</a>
          <a href="https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/">Internet-Draft ↗</a>
        </div>
        <div class="foot-col">
          <h5>Services</h5>
          <a href="https://anchor.agentactioncapsule.org">Transparency Log</a>
          <a href="/">Verifier</a>
        </div>
        <div class="foot-col">
          <h5>Source</h5>
          <a href="https://github.com/action-state-group">GitHub ↗</a>
          <a href="https://github.com/ietf-wg-scitt/examples">Test vectors ↗</a>
        </div>
      </div>
    </div>
    <div class="foot-note">Stateless SCITT/COSE verifier · {license_} · operated by {operated_by} · {foundation}</div>
  </div>
</footer>

<script src="/static/verify.js"></script>
</body>
</html>
"""


#: Token replaced client-side (``BUNDLE_JS``'s download button) or by a
#: producer-side embed (capsule-ledger's ``--with-viewer``, shipped in its #28;
#: flag — see the PR description) with the real base64url bundle fragment.
#: Chosen with an ``@`` so it can never collide with real base64url content.
_BUNDLE_FRAGMENT_PLACEHOLDER = "@@BUNDLE_FRAGMENT@@"


def _bundle_page_body(*, embed_placeholder: bool) -> str:
    """The DOM shared by both delivery modes of the bundle-open page —
    ``render_bundle_page``'s hosted mode (``GET /bundle``, script src tags,
    loads from the URL fragment) and its offline mode (``GET
    /bundle/offline-shell``, JS inlined, loads from an embedded fragment).
    Carries no bundle data either way — ``BUNDLE_JS`` fills everything in
    client-side from whichever source it finds (embedded global, else
    ``location.hash``); this function never receives or touches bundle bytes.
    """
    embed_script = (
        f'<script>window.__BUNDLE_FRAGMENT_B64U__={json.dumps(_BUNDLE_FRAGMENT_PLACEHOLDER)};</script>\n'
        if embed_placeholder
        else ""
    )
    return f"""{embed_script}<nav>
  <div class="nav-in">
    <a class="brand" href="https://agentactioncapsule.org">
      <span class="glyph"></span> Agent Action Capsule <span class="svc">Verifier</span>
    </a>
    <div class="nav-links">
      <a href="https://agentactioncapsule.org">Standard</a>
      <a href="https://anchor.agentactioncapsule.org">Transparency Log</a>
      <a href="/">Verifier</a>
      <a href="/bundle" class="active">Bundle</a>
      <a href="https://agentactioncapsule.org/docs/">Docs</a>
    </div>
  </div>
</nav>

<div class="wrap" style="padding:32px 0 16px">
  <div class="pill">ledger bundle · completeness certificate</div>
  <h1 style="margin-top:12px">Ledger bundle verifier</h1>
  <p class="mono" id="bundleSummary" style="font-size:13px;color:var(--muted);margin-top:6px">No bundle loaded yet.</p>
</div>

<div class="wrap">
  <div class="share-row">
    <span class="mono" id="permalinkText">(open a bundle to see its permalink)</span>
    <span class="btnrow">
      <button class="verify-btn" id="copyLinkBtn" disabled style="opacity:.5;padding:9px 16px;font-size:13px">Copy permalink</button>
      <button class="verify-btn" id="downloadBtn" disabled style="opacity:.5;padding:9px 16px;font-size:13px">Download self-contained copy</button>
    </span>
  </div>
</div>

<div class="wrap" id="emptyState" style="display:none">
  <div class="bundle-empty">No bundle data in this URL. Open the full shared link (the part after
    <code class="mono">#</code>) that <code class="mono">capsule bundle</code> printed, or paste bundle
    JSON below — this viewer never fetches bundle data from a server.</div>
</div>

<div class="wrap" id="completenessMount"></div>

<section id="ritualSection" class="band" style="padding-top:16px">
  <div class="wrap">
    <div class="sec-eyebrow">Verification ritual</div>
    <h2 class="sec-title">Integrity · Sequence · Completeness · Cross-check</h2>
    <p style="font-size:14px;color:var(--muted);margin-bottom:16px">
      Failure is precise: the stage that failed is named, and everything that still verifies keeps its
      verdict. A missing completeness certificate is reported honestly as unavailable, never as a pass.
    </p>
    <div id="ritualMount"></div>
    <div style="margin-top:16px" id="recordsTableContent"></div>
  </div>
</section>

<section id="privlogSection" class="band" style="display:none">
  <div class="wrap">
    <div class="sec-eyebrow">Privilege Log</div>
    <h2 class="sec-title">Disclosed vs. withheld artifacts — all records</h2>
    <p style="font-size:14px;color:var(--muted);margin-bottom:16px">
      WITHHELD = digest committed in the record; payload not provided here.<br>
      REVEALED = payload provided; hash recomputed and checked against the committed digest.
    </p>
    <div id="privlogContent"></div>
  </div>
</section>

<section class="band">
  <div class="wrap">
    <div class="sec-eyebrow">Bundle data</div>
    <h2 class="sec-title">Paste bundle JSON to render</h2>
    <p style="font-size:14px;color:var(--muted);margin-bottom:16px">
      The JSON goes into the URL fragment only — never sent to this server.
    </p>
    <div class="tool">
      <div class="tool-body">
        <div class="field">
          <label>Bundle JSON <span class="opt">output of <code>capsule bundle</code></span></label>
          <textarea id="bundleJson" style="min-height:120px"
            placeholder='{{"bundle_version":"1","records":[...],"range":[1,4],"checkpoint":{{"tree_size":4}}}}'></textarea>
        </div>
        <p id="parseErr" style="color:var(--fail);font-family:var(--mono);font-size:12px;margin:8px 0;min-height:18px"></p>
        <div class="actions">
          <button class="verify-btn" id="loadBtn">Load bundle &#x2192;</button>
        </div>
      </div>
    </div>
  </div>
</section>

<footer>
  <div class="wrap">
    <div class="foot-in">
      <div class="foot-brand">
        <a class="brand" href="https://agentactioncapsule.org">
          <span class="glyph"></span> Agent Action Capsule <span class="svc">Verifier</span>
        </a>
        <p>Stateless public verification surface for capsule-ledger bundles.
        Free and neutral for any capsule-ledger installation — self-hosted or hosted, no account, no gating.</p>
      </div>
      <div class="foot-cols">
        <div class="foot-col">
          <h5>Standard</h5>
          <a href="https://agentactioncapsule.org">Overview</a>
          <a href="https://agentactioncapsule.org/docs/">Docs</a>
        </div>
        <div class="foot-col">
          <h5>Services</h5>
          <a href="https://anchor.agentactioncapsule.org">Transparency Log</a>
          <a href="/">Verifier</a>
        </div>
        <div class="foot-col">
          <h5>Privacy</h5>
          <a href="{_esc(REPO_URL)}">Source &#x2197;</a>
        </div>
      </div>
    </div>
    <div class="foot-note">Stateless &#xb7; retains nothing &#xb7; Apache-2.0 &#xb7; Action State Group</div>
  </div>
</footer>"""


def render_bundle_page(*, offline: bool = False) -> str:
    """Return the HTML for the bundle-open page — the recipient-side viewer
    for a ``capsule bundle`` export (capsule-ledger's
    ``capsule_ledger/cli/bundle_cmd.py``).

    Two delivery modes, one codebase (this function, ``MMR_JS``, ``BUNDLE_JS``):

    * ``offline=False`` — served at ``GET /bundle`` (the exact path
      capsule-ledger's ``bundle_cmd.DEFAULT_VERIFY_BASE_URL`` points its
      permalinks at). Scripts are ``<script src=...>`` tags so the page can
      carry the same CSP (``script-src 'self'``, no ``unsafe-inline``) as
      every other page this module serves. Loads bundle data from
      ``location.hash`` only — the server never sees it (see
      ``docs/hosted-verifier-design.md``'s stateless/payload-opaque design
      constraints; this route reads no request body at all).
    * ``offline=True`` — served at ``GET /bundle/offline-shell``: the exact
      same DOM and JS, but inlined (no external requests at all, mirroring
      capsule-ledger's own ``report/render.py`` zero-network HTML-shell
      pattern) with a placeholder token in place of the fragment.
      ``BUNDLE_JS``'s download button fetches this once, replaces the
      placeholder with the currently-loaded bundle's fragment, and offers
      it as a single self-contained downloadable file — no build step,
      trivially embeddable by a future producer-side ``--with-viewer`` flag.
    """
    scripts = (
        f"<script>{MMR_JS}</script>\n<script>{BUNDLE_JS}</script>"
        if offline
        else '<script src="/static/mmr.js"></script>\n<script src="/static/bundle.js"></script>'
    )
    body = _bundle_page_body(embed_placeholder=offline)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ledger bundle verifier — capsule-ledger</title>
<style>
{_PAGE_CSS}
{_CAPSULE_CSS}
{_BUNDLE_CSS}
</style>
</head>
<body>
{body}
{scripts}
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
            elif self.path == "/static/capsule.js":
                self._send_js(200, CAPSULE_JS)
            elif self.path == "/static/mmr.js":
                self._send_js(200, MMR_JS)
            elif self.path == "/static/bundle.js":
                self._send_js(200, BUNDLE_JS)
            elif self.path.rstrip("/") == "/bundle":
                self._send_html(200, render_bundle_page())
            elif self.path == "/bundle/offline-shell":
                self._send_html(200, render_bundle_page(offline=True))
            elif self.path.rstrip("/") in ("", "/verify"):
                # Browsers get the landing page (boundary table on the page
                # itself); API clients get the same data as JSON.
                if "text/html" in (self.headers.get("Accept") or ""):
                    self._send_html(200, render_landing_page())
                else:
                    self._send_json(
                        200, {"service": "stateless SCITT/COSE verifier", **CAPABILITIES}
                    )
            elif self.path == "/instrumentation-policy":
                self._send_json(200, INSTRUMENTATION_POLICY)
            elif (cid := _capsule_id_from_path(self.path, "v/")) is not None:
                referer = self.headers.get("Referer") or ""
                _instrument_capsule_view(referer)
                self._send_html(200, render_capsule_page(cid))
            elif (cid := _capsule_id_from_path(self.path, "anchor-status/")) is not None:
                self._send_json(200, _anchor_proxy_json(cid))
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
        if method == "GET" and path == "/static/capsule.js":
            await send_js(200, CAPSULE_JS)
            return
        if method == "GET" and path == "/static/mmr.js":
            await send_js(200, MMR_JS)
            return
        if method == "GET" and path == "/static/bundle.js":
            await send_js(200, BUNDLE_JS)
            return
        if method == "GET" and path == "/bundle":
            await send_html(200, render_bundle_page())
            return
        if method == "GET" and path == "/bundle/offline-shell":
            await send_html(200, render_bundle_page(offline=True))
            return
        if method == "GET" and path in ("/", "/verify"):
            # Browsers get the landing page (boundary table on the page itself);
            # API clients get the same data as JSON.
            if _accepts_html():
                await send_html(200, render_landing_page())
            else:
                await send_json(200, {"service": "stateless SCITT/COSE verifier", **CAPABILITIES})
            return
        if method == "GET" and path == "/instrumentation-policy":
            await send_json(200, INSTRUMENTATION_POLICY)
            return
        if method == "GET":
            cid = _capsule_id_from_path(path, "v/")
            if cid is not None:
                referer = ""
                for hname, hval in scope.get("headers", []):
                    if hname == b"referer":
                        referer = hval.decode("utf-8", errors="replace")
                _instrument_capsule_view(referer)
                await send_html(200, render_capsule_page(cid))
                return
            cid = _capsule_id_from_path(path, "anchor-status/")
            if cid is not None:
                await send_json(200, _anchor_proxy_json(cid))
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
    "CAPSULE_JS",
    "MMR_JS",
    "BUNDLE_JS",
    "INSTRUMENTATION_POLICY",
    "render_landing_page",
    "render_capsule_page",
    "render_bundle_page",
    "_capsule_has_hitl",
    "_capsule_has_sd",
    "_unwrap_envelope",
    "_render_reg_panel",
    "verify_payload",
    "verify_request_bytes",
    "make_handler",
    "make_asgi_app",
    "serve",
    # instrumentation
    "_CAPSULE_VIEW_COUNTER",
    "_REFERRER_COUNTER",
]
