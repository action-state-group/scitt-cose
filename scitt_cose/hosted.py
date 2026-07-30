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
from .machine_mandate import MM_RENDER_JS as _MM_RENDER_JS
from .receipt import verify_receipt
from .statement import parse_signed_statement

#: One sentence, the whole offering. Served on the page and in the JSON.
SUMMARY = (
    "A free, stateless verification endpoint for SCITT receipts and signed "
    "statements (RFC9162_SHA256 profile). It verifies; it stores nothing; "
    "it issues nothing."
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
.anchor-banner.anchor-unknown{background:var(--fail-soft);border-color:var(--fail);color:var(--fail)}
.anchor-banner.anchor-loading{color:var(--muted);background:var(--paper-2)}
.anchor-ok{color:var(--pass);font-weight:700}
.anchor-err{color:var(--fail);font-weight:700}
.anchor-none{color:var(--muted)}
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
var KNOWN_TYPES={"capsule":1,"offer_terms":1,"wicket_manifest":1,"response":1,
  "gate_checks":1,"subject":1,"bilateral_subject":1,"compute_attestation":1,
  "agent_input":1,"agent_output":1};

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
  if(d&&(d.capsule_id||d.buyer_capsule))return"aac";
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
function sh(d){return d.slice(0,8)+"…"+d.slice(-4);}
function safe(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function $(id){return document.getElementById(id);}

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
  function extractCap(cap,capId,pfx){
    var p=pfx?pfx+".":"";
    var chain=cap.chain||{};
    var prior=chain.parent_capsule_id||"";
    if(isH64(prior)&&addN(prior,"capsule","prior capsule "+sh(prior),false,null))
      addEdge(capId,prior,"chains_to");
    var ma=cap.model_attestation||{},ca=ma.compute_attestation||{},subj=ca.subject_digest||"";
    if(isH64(subj)){addArt(subj,"subject","subject",p+"compute_attestation.subject_digest");addEdge(capId,subj,"attests_over");}
    var _actxW=p+"compute_attestation — payload not carried in the record";
    var _actxR="payload carried in fragment; recomputed against committed digest";
    var ai=ca.agent_input_digest||"",aiPre=ca.agent_input,aiRev=aiPre!=null;
    if(isH64(ai)&&addN(ai,"agent_input","agent input "+sh(ai),!aiRev,aiRev?aiPre:null)){
      privlog.push({id:"agent input",type:"agent_input",digest:ai,withheld:!aiRev,isKnown:true,matchOk:null,
                    ctx:aiRev?_actxR:_actxW,_revPayload:aiRev?aiPre:null});addEdge(capId,ai,"attests_over");}
    var ao=ca.agent_output_digest||"",aoPre=ca.agent_output,aoRev=aoPre!=null;
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
    if(isH64(bid))extractCap(bc,bid,"buyer");
    if(isH64(sid))extractCap(sc,sid,"seller");
  }else{
    var cid=data.capsule_id||"";
    if(isH64(cid)){addN(cid,"capsule","capsule "+sh(cid),false,null);extractCap(data,cid,"");}
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
  var h="<table class='pltable'><thead><tr><th>artifact</th><th>type</th><th>digest</th><th>status</th><th>context</th></tr></thead><tbody>";
  g.privlog.forEach(function(e){
    var st=e.withheld?"<span class='pl-withheld'>WITHHELD</span>":
            e.matchOk===true?"<span class='pl-match'>REVEALED · ✓ match</span>":
            e.matchOk===false?"<span class='pl-mismatch'>REVEALED · ✗ MISMATCH</span>":
            "<span class='pl-revealed'>REVEALED</span>";
    h+="<tr data-dig='"+safe(e.digest)+"'><td>"+safe(e.id)+"</td><td>"+safe(e.type)+(e.isKnown?"":' <em class="opaque-badge">OPAQUE</em>')+"</td>";
    h+="<td><code>"+safe(e.digest.slice(0,16))+"…</code></td><td class='pl-st'>"+st+"</td><td class='pl-ctx'>"+safe(e.ctx)+"</td></tr>";
  });
  h+="</tbody></table>";
  if(g.unk.length)h+="<p class='opaque-note' style='margin-top:12px'>Unknown types (verified-but-opaque): "+g.unk.map(safe).join(", ")+"</p>";
  el.innerHTML=h;$("privlogSection").style.display="block";
  /* async SHA-256 recompute for revealed rows (objects: canonical JSON; strings: raw UTF-8) */
  if(crypto&&crypto.subtle){
    g.privlog.forEach(function(e){
      if(!e._revPayload||e.withheld)return;
      var _bytes=typeof e._revPayload==="string"
        ?new TextEncoder().encode(e._revPayload)
        :new TextEncoder().encode(JSON.stringify(e._revPayload,Object.keys(e._revPayload).sort()));
      crypto.subtle.digest("SHA-256",_bytes).then(function(buf){
        var hex=Array.from(new Uint8Array(buf)).map(function(b){return b.toString(16).padStart(2,"0");}).join("");
        var matchOk=hex===e.digest;
        var cell=el.querySelector("tr[data-dig='"+e.digest+"'] td.pl-st");
        if(cell)cell.innerHTML=matchOk?"<span class='pl-match'>REVEALED · ✓ match</span>":
                                       "<span class='pl-mismatch'>REVEALED · ✗ MISMATCH</span>";
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

  /* detect properties from capsule data */
  var activeProps={"per-action-attribution":1};
  if(hasReceipt)activeProps["tamper-evident-log"]=1;
  /* human-oversight: disposition + human_disposed on any capsule */
  function checkHitl(cap){
    return cap&&cap.disposition&&(cap.human_disposed===true||(cap.disposition&&cap.disposition.approver==="human"));
  }
  if(checkHitl(data)||checkHitl(data&&data.buyer_capsule)||checkHitl(data&&data.seller_capsule))
    activeProps["human-oversight-record"]=1;
  /* disclosure: withheld_commitments or sealed_terms_hash with no terms */
  function checkSd(cap){
    var _ca=cap&&((cap.model_attestation||{}).compute_attestation)||{};
    return cap&&(cap.withheld_commitments
      ||(cap.constraints&&cap.constraints.some(function(c){return c.evidence_digest;}))
      ||isH64(_ca.agent_input_digest)||isH64(_ca.agent_output_digest));
  }
  if((data&&data.sealed_terms_hash&&!data.terms)||checkSd(data)||checkSd(data&&data.buyer_capsule)||checkSd(data&&data.seller_capsule))
    activeProps["disclosure-transparency-record"]=1;

  var propsShown=Object.keys(activeProps).sort().join(", ");
  var rows="";
  REG_ROWS.forEach(function(r){
    if(!activeProps[r[2]])return;
    rows+="<tr><td>"+safe(r[0])+"</td><td>"+safe(r[1])+"</td><td><span class='reg-prop'>"+safe(r[2])+"</span></td></tr>";
  });

  mount.innerHTML="<details class='reg-panel' id='regPanelDetails'>"
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

/* ---------- load + permalink ---------- */
function loadCapsule(data){
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
    var _fragData=JSON.parse(decodeURIComponent(escape(atob(hash))));
    if(!Array.isArray(_fragData)){loadCapsule(_fragData);}
  }catch(ex){$("parseErr").textContent="Fragment decode error: "+ex.message;}
}

/* anchor status (same-origin proxy avoids CORS) */
if(capsuleId){
  fetch("/anchor-status/"+capsuleId)
    .then(function(r){return r.json();})
    .then(function(s){
      var b=$("anchorBanner");
      if(s.error){b.innerHTML="<span class='anchor-err'>Anchor unreachable: "+safe(s.error)+"</span>";b.className="anchor-banner anchor-unknown";return;}
      if(s.anchored){
        b.innerHTML="<span class='anchor-ok'>✓ Anchored</span> log index <code>"+s.log_index+"</code>"+
          (s.receipt_verified?" · <span class='anchor-ok'>inclusion proof verified (RFC 9162)</span>":"");
        if(s.logged_at)b.innerHTML+=" · "+safe(s.logged_at);
        b.className="anchor-banner anchor-ok";
        /* upgrade reg panel with tamper-evident-log rows now that receipt is confirmed */
        if(_regLastData)renderRegPanel(_regLastData,true);
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
            if(document.title)document.title="Entry "+capsuleId.slice(0,8)+"\u2026 \u2014 Witnessed";
          }
        }
      }else{
        b.innerHTML="<span class='anchor-none'>Not found in anchor transparency log</span>";
        b.className="anchor-banner anchor-none";
      }
    })
    .catch(function(ex){
      var b=$("anchorBanner");
      b.innerHTML="Anchor unreachable: "+safe(ex.message);
      b.className="anchor-banner anchor-unknown";
    });
}

/* paste form */
$("loadBtn").addEventListener("click",function(){
  var txt=$("capsuleJson").value.trim();
  try{loadCapsule(JSON.parse(txt));}
  catch(ex){$("parseErr").textContent="JSON error: "+ex.message;}
});
$("linkBtn").addEventListener("click",function(){
  if(navigator.clipboard){
    var txt=_bundle?btoa(unescape(encodeURIComponent(JSON.stringify(_bundle)))):location.hash.slice(1);
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
}

$("chainPrevBtn")&&$("chainPrevBtn").addEventListener("click",function(){navigateBundle(_bundleIdx-1);});
$("chainNextBtn")&&$("chainNextBtn").addEventListener("click",function(){navigateBundle(_bundleIdx+1);});

/* prior-capsule graph nodes become clickable when bundle contains them */
function _patchGraphPriorLinks(){
  if(!_bundle)return;
  var byId={};
  _bundle.forEach(function(cap,i){if(cap.capsule_id)byId[cap.capsule_id]=i;});
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

/* auto-load bundle from fragment (array) */
var hash=location.hash.slice(1);
if(hash){
  try{
    var decoded=JSON.parse(decodeURIComponent(escape(atob(hash))));
    if(Array.isArray(decoded)&&decoded.length>0){
      _bundle=decoded;
      _bundleIdx=0;
      renderChainTable(decoded,0);
      loadCapsule(decoded[0]);
    }
  }catch(ex){}
}
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
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)

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

    return f"""<details class="reg-panel">
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
<title>Capsule {sid} — AAC Verifier</title>
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
  <div class="pill">capsule · AAC profile</div>
  <h1 style="margin-top:12px">Capsule <code class="mono" style="font-size:1.1rem">{sid}</code></h1>
  <p class="mono" style="font-size:11.5px;word-break:break-all;color:var(--muted);margin-top:6px">{cid}</p>
</div>

<div class="wrap" style="margin-bottom:8px">
  <div class="anchor-banner anchor-loading" id="anchorBanner">Checking anchor status…</div>
</div>

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
        <p>Stateless public verification surface for AAC capsule-bound records.
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
    "INSTRUMENTATION_POLICY",
    "render_landing_page",
    "render_capsule_page",
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
