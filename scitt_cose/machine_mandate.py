# SPDX-License-Identifier: Apache-2.0
"""MachineMandate profile parser and renderer for the P1 verification surface.

Renders MachineMandate vocabulary as published by the Tyche Institute:
  https://github.com/tyche-institute/machine-mandate
  Pinned commit: 524e6a3129b7f1ab850dd9471967458d3cb6f4cd

This module renders MachineMandate's own vocabulary (vct, action_hash, scope,
eat_profile, EAR structure, four-gate results, etc.) accurately, without
AAC-ification.  Verification path is identical to the AAC profile: same
SCITT/COSE receipt and signed-statement checks; only rendering is profile-specific.

Boundary:
  Accurate rendering of MachineMandate's published vocabulary and fixtures.
  This is NOT a claim of endorsement, production readiness, or equivalence with
  any other profile.  This module uses Tyche Institute's own published field names
  exactly as they appear in tyche-institute/machine-mandate@524e6a3.

Profile detection:
  A payload is recognised as MachineMandate when it contains ``vct`` ==
  ``https://vocab.tyche.institute/vct/machine-mandate`` OR ``eat_profile``
  containing ``eatf.eu/aep`` OR ``eat_profile`` containing ``veraison/ear``
  OR top-level ``action_hash`` starting with ``sha256:``.

No external dependencies beyond the stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# MachineMandate-specific vocabulary constants (from published fixtures/src)
# ---------------------------------------------------------------------------

#: VCT URI used in MachineMandate run credentials.
MM_VCT = "https://vocab.tyche.institute/vct/machine-mandate"

#: eat_profile values recognised in MachineMandate fixtures.
_AEP_EAT_PROFILE = "https://eatf.eu/aep/v1"
_EAR_EAT_PROFILE_PREFIX = "tag:github.com,2023:veraison/ear"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def is_machine_mandate(data: object) -> bool:
    """Return True if *data* looks like a MachineMandate payload."""
    if not isinstance(data, dict):
        return False
    vct = data.get("vct", "")
    if isinstance(vct, str) and vct == MM_VCT:
        return True
    eat = data.get("eat_profile", "")
    if isinstance(eat, str) and ("eatf.eu/aep" in eat or "veraison/ear" in eat):
        return True
    ah = data.get("action_hash", "")
    if isinstance(ah, str) and ah.startswith("sha256:"):
        return True
    # Mint record: has credential_claims (with vct or action_hash) and credential_preimage
    cred = data.get("credential_claims")
    if isinstance(cred, dict):
        inner_vct = cred.get("vct", "")
        if isinstance(inner_vct, str) and inner_vct == MM_VCT:
            return True
        inner_ah = cred.get("action_hash", "")
        if isinstance(inner_ah, str) and inner_ah.startswith("sha256:"):
            return True
    return False


# ---------------------------------------------------------------------------
# Data model — profile-specific fields rendered in their own vocabulary
# ---------------------------------------------------------------------------

@dataclass
class MMFieldGroup:
    """One logical group of MachineMandate fields for display."""
    label: str          # e.g. "Credential identity", "Scope", "EAR status"
    fields: list[tuple[str, Any]]   # (field_name, value) pairs, using MM vocabulary


@dataclass
class MachineMandate:
    """Parsed MachineMandate payload (AEP token or EAR or run-credential claims)."""
    profile_label: str                  # "MachineMandate AEP" / "MachineMandate EAR" / "MachineMandate"
    source_commit: str = "524e6a3129b7f1ab850dd9471967458d3cb6f4cd"
    source_repo: str = "tyche-institute/machine-mandate"
    field_groups: list[MMFieldGroup] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    parse_note: str = ""


# ---------------------------------------------------------------------------
# Parsers — one per fixture class
# ---------------------------------------------------------------------------

def _parse_aep(data: dict) -> MachineMandate:
    """Parse an AEP (Agent Execution Proof) token fixture."""
    mm = MachineMandate(profile_label="MachineMandate AEP", raw=data)
    mm.field_groups.append(MMFieldGroup(
        label="Token identity",
        fields=[
            ("eat_profile", data.get("eat_profile")),
            ("iss", data.get("iss")),
            ("sub", data.get("sub")),
            ("iat", data.get("iat_iso") or data.get("iat")),
            ("nonce", data.get("nonce")),
        ],
    ))
    mm.field_groups.append(MMFieldGroup(
        label="Action",
        fields=[
            ("action_id", data.get("action_id")),
            ("status", data.get("status")),
            ("swname", data.get("swname")),
            ("oemid", data.get("oemid")),
        ],
    ))
    mm.field_groups.append(MMFieldGroup(
        label="Binding",
        fields=[
            ("receipt_hash", data.get("receipt_hash")),
            ("_output_binding_note", data.get("_output_binding_note")),
        ],
    ))
    return mm


def _parse_ear(data: dict) -> MachineMandate:
    """Parse an EAR (EAT Attestation Result) fixture (Veraison output)."""
    mm = MachineMandate(profile_label="MachineMandate EAR (Veraison)", raw=data)
    mm.field_groups.append(MMFieldGroup(
        label="EAR header",
        fields=[
            ("eat_profile", data.get("eat_profile")),
            ("iat", data.get("iat")),
            ("eat_nonce", data.get("eat_nonce")),
            ("ear.verifier-id", data.get("ear.verifier-id")),
        ],
    ))
    submods = data.get("submods", {})
    for submod_name, submod in (submods.items() if isinstance(submods, dict) else []):
        submod_fields: list[tuple[str, Any]] = [
            ("ear.status", submod.get("ear.status")),
            ("ear.appraisal-policy-id", submod.get("ear.appraisal-policy-id")),
        ]
        tv = submod.get("ear.trustworthiness-vector", {})
        if isinstance(tv, dict):
            submod_fields.append(("ear.trustworthiness-vector", tv))
        ae = submod.get("ear.veraison.annotated-evidence", {})
        if isinstance(ae, dict):
            submod_fields.append(("ear.veraison.annotated-evidence", ae))
        mm.field_groups.append(MMFieldGroup(
            label=f"Submodule: {submod_name}",
            fields=submod_fields,
        ))
    return mm


def _parse_run_credential(data: dict) -> MachineMandate:
    """Parse MachineMandate run-credential claims (from mint-record credential_claims)."""
    mm = MachineMandate(profile_label="MachineMandate Run Credential", raw=data)
    mm.field_groups.append(MMFieldGroup(
        label="Credential identity",
        fields=[
            ("vct", data.get("vct")),
            ("jti", data.get("jti")),
            ("iss", data.get("iss") or data.get("issuer_jwk_thumbprint")),
            ("sub_agent_id", data.get("sub_agent_id")),
            ("iat", data.get("iat_utc") or data.get("iat")),
            ("exp", data.get("exp_utc") or data.get("exp")),
        ],
    ))
    mm.field_groups.append(MMFieldGroup(
        label="Action seal",
        fields=[
            ("action_hash", data.get("action_hash")),
        ],
    ))
    scope = data.get("scope", {})
    if isinstance(scope, dict):
        mm.field_groups.append(MMFieldGroup(
            label="Scope",
            fields=[
                ("allowed_actions", scope.get("allowed_actions")),
                ("max_spend", scope.get("max_spend")),
                ("action_commitments", scope.get("action_commitments")),
            ],
        ))
    return mm


def _parse_mint_record(data: dict) -> MachineMandate:
    """Parse a MachineMandate mint record (run-credential-mint-record.json)."""
    mm = MachineMandate(profile_label="MachineMandate Mint Record", raw=data)
    mm.field_groups.append(MMFieldGroup(
        label="Record identity",
        fields=[
            ("artifact", data.get("artifact")),
            ("minted_at_utc", data.get("minted_at_utc")),
            ("status", data.get("status")),
            ("boundary", data.get("boundary")),
        ],
    ))
    cred = data.get("credential_claims", {})
    if isinstance(cred, dict):
        mm.field_groups.append(MMFieldGroup(
            label="Credential claims",
            fields=[
                ("vct", cred.get("vct")),
                ("jti", cred.get("jti")),
                ("sub_agent_id", cred.get("sub_agent_id")),
                ("action_hash", cred.get("action_hash")),
                ("iat_utc", cred.get("iat_utc")),
                ("exp_utc", cred.get("exp_utc")),
            ],
        ))
        scope = cred.get("scope", {})
        if isinstance(scope, dict):
            mm.field_groups.append(MMFieldGroup(
                label="Scope",
                fields=[
                    ("allowed_actions", scope.get("allowed_actions")),
                    ("max_spend", scope.get("max_spend")),
                    ("action_commitments", scope.get("action_commitments")),
                ],
            ))
    preimage = data.get("credential_preimage", {})
    if isinstance(preimage, dict):
        mm.field_groups.append(MMFieldGroup(
            label="Preimage commitment",
            fields=[
                ("digest", preimage.get("digest")),
                ("digest_alg", preimage.get("digest_alg")),
                ("preimage_length_bytes", preimage.get("preimage_length_bytes")),
                ("invariant_across_presentations", preimage.get("invariant_across_presentations")),
            ],
        ))
    self_check = data.get("self_check", {})
    if isinstance(self_check, dict):
        mm.field_groups.append(MMFieldGroup(
            label="Self-check",
            fields=[
                ("all_verdicts_as_expected", self_check.get("all_verdicts_as_expected")),
            ],
        ))
        cases = self_check.get("cases", [])
        for c in (cases if isinstance(cases, list) else []):
            mm.field_groups.append(MMFieldGroup(
                label=f"Gate case: {c.get('case_id', '?')}",
                fields=[
                    ("verdict", c.get("verdict")),
                    ("expected_verdict", c.get("expected_verdict")),
                    ("match", c.get("match")),
                    ("L1_crypto", c.get("L1_crypto")),
                    ("L2_attested", c.get("L2_attested")),
                    ("L3_endorser_role", c.get("L3_endorser_role")),
                    ("L4_in_scope", c.get("L4_in_scope")),
                    ("reasons", c.get("reasons")),
                ],
            ))
    return mm


def parse_machine_mandate(data: dict) -> MachineMandate:
    """Dispatch to the right sub-parser based on MachineMandate payload shape."""
    if not isinstance(data, dict):
        return MachineMandate(profile_label="MachineMandate", parse_note="not a JSON object")

    # AEP token (Agent Execution Proof)
    eat = data.get("eat_profile", "")
    if isinstance(eat, str) and "eatf.eu/aep" in eat:
        return _parse_aep(data)

    # EAR (EAT Attestation Result from Veraison)
    if isinstance(eat, str) and "veraison/ear" in eat:
        return _parse_ear(data)

    # Mint record (full freeze record)
    if "credential_claims" in data and "credential_preimage" in data:
        return _parse_mint_record(data)

    # Run credential claims (direct)
    vct = data.get("vct", "")
    if isinstance(vct, str) and vct == MM_VCT:
        return _parse_run_credential(data)

    # action_hash-bearing payload (generic)
    ah = data.get("action_hash", "")
    if isinstance(ah, str) and ah.startswith("sha256:"):
        return _parse_run_credential(data)

    return MachineMandate(
        profile_label="MachineMandate",
        raw=data,
        parse_note="unrecognised MachineMandate sub-type; rendering raw fields",
    )


# ---------------------------------------------------------------------------
# GraphView adapter — wraps MachineMandate render into the AAC graph model
# ---------------------------------------------------------------------------

def parse_as_graph_view(data: dict) -> Any:
    """Parse MachineMandate data into a GraphView for the P1 surface.

    The verification path is identical to AAC: the SCITT/COSE receipt and
    signed-statement checks run unchanged.  This function provides the
    profile-specific parse result that the capsule page renderer uses.

    Returns a GraphView with profile="machine-mandate" and a single synthetic
    node carrying the MachineMandate render result in revealed_payload.
    """
    import hashlib as _h
    import json as _j

    from .aac import GraphNode, GraphView  # local import to avoid circular

    mm = parse_machine_mandate(data)
    blob = _j.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    digest = _h.sha256(blob).hexdigest()

    view = GraphView(profile="machine-mandate", is_binding=False)
    view.raw_capsules = [data]
    view.nodes.append(GraphNode(
        id=digest,
        node_type="machine-mandate",
        digest=digest,
        label=f"{mm.profile_label} {digest[:8]}…{digest[-4:]}",
        is_known_type=True,
        is_withheld=False,
        revealed_payload=mm,
    ))
    if mm.parse_note:
        view.parse_error = mm.parse_note
    return view


# ---------------------------------------------------------------------------
# PROFILE_PARSERS entry — callable matching aac.parse_capsule signature
# ---------------------------------------------------------------------------

def parser_entry(data: dict) -> Any:
    """Entry point for PROFILE_PARSERS['machine-mandate'].

    Mirrors the aac.parse_capsule(data) -> GraphView signature so the detect +
    dispatch loop in the capsule page works uniformly.
    """
    return parse_as_graph_view(data)


# ---------------------------------------------------------------------------
# Client-side renderer (JavaScript fragment injected into CAPSULE_JS)
# ---------------------------------------------------------------------------

#: JavaScript renderer for MachineMandate payloads.
#: Injected into CAPSULE_JS at the PROFILE_RENDERERS plug-point.
#: Uses MachineMandate's own vocabulary — no AAC fields.
MM_RENDER_JS = r"""
function renderMachineMandate(data){
  /* MachineMandate renderer — uses Tyche Institute vocabulary exactly.
   * Source: tyche-institute/machine-mandate@524e6a3
   * Not an endorsement; accurate rendering only. */
  var el=document.getElementById("graphContent");if(!el)return;
  var h="<div style='margin-bottom:16px'>";
  h+="<div style='font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--muted);margin-bottom:8px'>MachineMandate</div>";

  /* detect sub-type and pick field groups */
  var eat=data.eat_profile||"";
  var isAep=eat.indexOf("eatf.eu/aep")>=0;
  var isEar=eat.indexOf("veraison/ear")>=0;
  var isRunCred=data.vct==="https://vocab.tyche.institute/vct/machine-mandate";
  var isMintRecord=!!(data.credential_claims&&data.credential_preimage);

  function fmtVal(v){
    if(v===null||v===undefined)return"—";
    if(typeof v==="boolean")return v?"true":"false";
    if(typeof v==="object")return"<code style='font-family:var(--mono);font-size:11px;white-space:pre-wrap'>"+safe(JSON.stringify(v,null,2))+"</code>";
    return safe(String(v));
  }

  function kv(label,val){
    return"<dt style='color:var(--muted);font-family:var(--mono);font-size:12px'>"+safe(label)+"</dt>"+
           "<dd style='font-family:var(--mono);font-size:12.5px;word-break:break-all'>"+fmtVal(val)+"</dd>";
  }

  function group(title,fields){
    var inner=fields.map(function(f){return kv(f[0],f[1]);}).join("");
    return"<div style='border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin-bottom:10px;background:#fff'>"+
      "<div style='font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;color:var(--muted);margin-bottom:8px'>"+safe(title)+"</div>"+
      "<dl style='display:grid;grid-template-columns:200px 1fr;gap:5px 12px'>"+inner+"</dl></div>";
  }

  if(isAep){
    h+=group("Token identity",[["eat_profile",data.eat_profile],["iss",data.iss],["sub",data.sub],["iat",data.iat_iso||data.iat],["nonce",data.nonce]]);
    h+=group("Action",[["action_id",data.action_id],["status",data.status],["swname",data.swname],["oemid",data.oemid]]);
    h+=group("Binding",[["receipt_hash",data.receipt_hash],["_output_binding_note",data._output_binding_note]]);
  }else if(isEar){
    h+=group("EAR header",[["eat_profile",data.eat_profile],["iat",data.iat],["eat_nonce",data.eat_nonce],["ear.verifier-id",data["ear.verifier-id"]]]);
    var submods=data.submods||{};
    Object.keys(submods).forEach(function(k){
      var s=submods[k];
      h+=group("Submodule: "+k,[
        ["ear.status",s["ear.status"]],
        ["ear.appraisal-policy-id",s["ear.appraisal-policy-id"]],
        ["ear.trustworthiness-vector",s["ear.trustworthiness-vector"]],
        ["ear.veraison.annotated-evidence",s["ear.veraison.annotated-evidence"]]
      ]);
    });
  }else if(isMintRecord){
    h+=group("Record identity",[["artifact",data.artifact],["minted_at_utc",data.minted_at_utc],["status",data.status]]);
    var cred=data.credential_claims||{};
    h+=group("Credential claims",[["vct",cred.vct],["jti",cred.jti],["sub_agent_id",cred.sub_agent_id],["action_hash",cred.action_hash],["iat_utc",cred.iat_utc],["exp_utc",cred.exp_utc]]);
    var scope=cred.scope||{};
    h+=group("Scope",[["allowed_actions",scope.allowed_actions],["max_spend",scope.max_spend],["action_commitments",scope.action_commitments]]);
    var pre=data.credential_preimage||{};
    h+=group("Preimage commitment",[["digest",pre.digest],["digest_alg",pre.digest_alg],["preimage_length_bytes",pre.preimage_length_bytes],["invariant_across_presentations",pre.invariant_across_presentations]]);
    var sc=data.self_check||{};
    h+=group("Self-check",[["all_verdicts_as_expected",sc.all_verdicts_as_expected]]);
    (sc.cases||[]).forEach(function(c){
      h+=group("Gate case: "+c.case_id,[
        ["verdict",c.verdict],["expected_verdict",c.expected_verdict],["match",c.match],
        ["L1_crypto",c.L1_crypto],["L2_attested",c.L2_attested],
        ["L3_endorser_role",c.L3_endorser_role],["L4_in_scope",c.L4_in_scope],
        ["reasons",c.reasons]
      ]);
    });
  }else if(isRunCred){
    h+=group("Credential identity",[["vct",data.vct],["jti",data.jti],["sub_agent_id",data.sub_agent_id],["iat_utc",data.iat_utc||data.iat],["exp_utc",data.exp_utc||data.exp]]);
    h+=group("Action seal",[["action_hash",data.action_hash]]);
    var scope2=data.scope||{};
    h+=group("Scope",[["allowed_actions",scope2.allowed_actions],["max_spend",scope2.max_spend],["action_commitments",scope2.action_commitments]]);
  }else{
    /* generic fallback — render top-level keys using MM vocabulary */
    var genericFields=Object.keys(data).map(function(k){return[k,data[k]];});
    h+=group("MachineMandate fields",genericFields);
  }

  h+="<div style='font-family:var(--mono);font-size:10.5px;color:var(--muted-2);margin-top:8px'>"+
    "Source: tyche-institute/machine-mandate@524e6a3 &middot; "+
    "Accurate rendering of published vocabulary. Not an endorsement.</div>";
  h+="</div>";
  el.innerHTML=h;
  document.getElementById("graphSection").style.display="block";
}
"""


# ---------------------------------------------------------------------------
# detect_machine_mandate — the Python-side detect function for PROFILE_PARSERS
# ---------------------------------------------------------------------------

def detect_machine_mandate(data: dict) -> str:
    """Return 'machine-mandate' if data matches, else 'unknown'."""
    if is_machine_mandate(data):
        return "machine-mandate"
    return "unknown"


__all__ = [
    "MM_VCT",
    "is_machine_mandate",
    "MachineMandate",
    "MMFieldGroup",
    "parse_machine_mandate",
    "parse_as_graph_view",
    "parser_entry",
    "detect_machine_mandate",
    "MM_RENDER_JS",
]
