# SPDX-License-Identifier: Apache-2.0
"""The bundle-open page — the recipient-side viewer for capsule-ledger's
``capsule bundle`` export.

Acceptance cases (see the task brief):
1. Privilege log: withheld fields render as a provable commitment (digest),
   never as if the field silently doesn't exist.
2. Completeness certificate: absent -> honest "skip", never a fabricated
   pass; present+genuine -> "pass"; present+corrupted -> "fail" (mutant test).
3. Every record's own structural integrity is checked independently of the
   bundle producer's self-reported ``verification`` field (cross-check).
4. Both delivery modes (hosted route, offline self-contained file) render
   from the exact same ``BUNDLE_JS``/``MMR_JS`` — checked by asserting the
   offline shell inlines the identical script bodies the hosted routes serve.
5. Ported AAC helpers (``isH64``/``sh``/``safe``/``KNOWN_TYPES``/``parseAac``/
   ``_capMismatched``/``findChainGaps``/``annotateRecords``) are byte-for-byte
   identical to their originals in ``CAPSULE_JS`` — a pinned drift guard, not
   an inspection-time claim.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
from http.server import HTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import pytest

from hosted_profiles.hosted import (
    BUNDLE_JS,
    CAPSULE_JS,
    MMR_JS,
    REPO_URL,
    make_asgi_app,
    make_handler,
    render_bundle_page,
)

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_bundle.mjs"

pytestmark_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


# ---------------------------------------------------------------------------
# Drift guard: ported AAC helpers stay byte-identical to CAPSULE_JS
# ---------------------------------------------------------------------------


def _slice_between(src: str, start: str, end: str) -> str:
    i = src.index(start)
    j = src.index(end, i) + len(end)
    return src[i:j]


def _line_from(src: str, start: str) -> str:
    i = src.index(start)
    j = src.index("\n", i)
    return src[i:j]


def test_bundle_js_shared_helpers_match_capsule_js():
    for name, start in (("isH64", "function isH64("), ("sh", "function sh("), ("safe", "function safe(")):
        assert _line_from(CAPSULE_JS, start) == _line_from(BUNDLE_JS, start), name

    assert _slice_between(CAPSULE_JS, "var KNOWN_TYPES={", "};") == _slice_between(
        BUNDLE_JS, "var KNOWN_TYPES={", "};"
    )

    parse_aac_end = "return{nodes:nodes,edges:edges,privlog:privlog,unk:unk,isB:isB};\n}"
    assert _slice_between(CAPSULE_JS, "function parseAac(data){", parse_aac_end) == _slice_between(
        BUNDLE_JS, "function parseAac(data){", parse_aac_end
    )

    chain_end = 'return{note:cites?"cites an altered record":"verifies",isAltered:false,citesAltered:cites};\n  });\n}'
    assert _slice_between(CAPSULE_JS, "function _capMismatched(cap){", chain_end) == _slice_between(
        BUNDLE_JS, "function _capMismatched(cap){", chain_end
    )

    # capsule_id recompute (RFC 8785 JCS + SHA-256) — same drift-guard: both
    # files carry a byte-identical hand-port of agent_action_capsule.canonical.
    capid_end = "return{ok:false,stated:stated,recomputed:null,error:ex.message};\n  }\n}"
    assert _slice_between(CAPSULE_JS, "var CHAIN_LINKAGE_FIELDS=", capid_end) == _slice_between(
        BUNDLE_JS, "var CHAIN_LINKAGE_FIELDS=", capid_end
    )

    # disclosed-payload rendering (canonicalPayloadText/payloadPreview/payloadCellHtml) —
    # same drift-guard: the bytes hashed and the bytes shown must come from one helper,
    # identical in both files, never two independently-maintained copies.
    payload_end = '</div></div></details>";\n}'
    assert _slice_between(CAPSULE_JS, "/* ---------- disclosed-payload rendering", payload_end) == _slice_between(
        BUNDLE_JS, "/* ---------- disclosed-payload rendering", payload_end
    )


# ---------------------------------------------------------------------------
# render_bundle_page: routes, CSP, offline self-containment
# ---------------------------------------------------------------------------


def test_hosted_bundle_page_is_csp_safe():
    import re

    html = render_bundle_page()
    assert '<script src="/static/mmr.js">' in html
    assert '<script src="/static/bundle.js">' in html
    assert not re.search(r"<script[^>]*>[^<]", html)  # no inline script bodies
    assert "<link" not in html
    assert "@import" not in html
    hrefs = re.findall(r'href="([^"]*)"', html)
    external = {h for h in hrefs if h.startswith("http")}
    allowed = {
        REPO_URL,
        "https://agentactioncapsule.org",
        "https://agentactioncapsule.org/docs/",
        "https://anchor.agentactioncapsule.org",
        f"{REPO_URL}/blob/main/docs/verification-trust-model.md",
    }
    assert not (external - allowed), external - allowed


def test_bundle_page_links_trust_model_doc_in_both_modes():
    """A stranger with a bundle permalink has no reason to find our GitHub —
    the trust model must be reachable from the page itself, hosted or offline."""
    assert "docs/verification-trust-model.md" in render_bundle_page()
    assert "docs/verification-trust-model.md" in render_bundle_page(offline=True)


def test_offline_bundle_shell_is_self_contained_and_reusable_template():
    html = render_bundle_page(offline=True)
    assert "<script src=" not in html  # nothing external — fully inlined
    assert MMR_JS in html
    assert BUNDLE_JS in html
    # 3 occurrences: 1 embed point (first in document order) + 2 internal
    # BUNDLE_JS references (the sentinel check + the download button's own
    # replace() call) -- BUNDLE_JS itself only ever replaces the first
    # (single-argument String.replace semantics), so a future embedder
    # (this viewer's own download button, or capsule-ledger's planned
    # --with-viewer flag) can safely do the same single substitution.
    assert html.count("@@BUNDLE_FRAGMENT@@") == 3
    fragment = "eyJoZWxsbyI6MX0"
    spliced = html.replace("@@BUNDLE_FRAGMENT@@", fragment, 1)
    assert spliced.count(fragment) == 1
    assert spliced.count("@@BUNDLE_FRAGMENT@@") == 2  # BUNDLE_JS's own internal literals untouched


def test_hosted_and_offline_pages_share_identical_dom_ids():
    """Both delivery modes must render the same page — checked by requiring
    every data/id hook the offline page's JS looks for is present in the
    hosted page's DOM (and vice versa isn't needed since both bodies come
    from the same ``_bundle_page_body`` helper)."""
    hosted = render_bundle_page()
    offline = render_bundle_page(offline=True)
    for hook in ("bundleSummary", "permalinkText", "downloadBtn", "copyLinkBtn",
                 "completenessMount", "ritualMount", "recordsTableContent",
                 "privlogSection", "privlogContent", "bundleJson", "loadBtn", "emptyState"):
        assert f'id="{hook}"' in hosted, hook
        assert f'id="{hook}"' in offline, hook


def _get(url: str):
    with urlopen(Request(url), timeout=10) as resp:
        return resp.headers.get("Content-Type", ""), resp.read()


def test_stdlib_routes_wired():
    httpd = HTTPServer(("127.0.0.1", 0), make_handler())
    host, port = httpd.server_address
    try:
        for path, needle in (
            ("/bundle", "Ledger bundle verifier"),
            ("/bundle/offline-shell", "Ledger bundle verifier"),
            ("/static/mmr.js", "verifyInclusion"),
            ("/static/bundle.js", "checkCompleteness"),
        ):
            t = threading.Thread(target=httpd.handle_request)
            t.start()
            ctype, body = _get(f"http://{host}:{port}{path}")
            t.join(timeout=10)
            assert needle in body.decode()
    finally:
        httpd.server_close()


def _drive_asgi(app, path):
    import asyncio

    async def run():
        scope = {"type": "http", "method": "GET", "path": path, "root_path": "", "headers": []}
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        await app(scope, receive, send)
        start = next(m for m in sent if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        return start["status"], body

    return asyncio.run(run())


def test_asgi_routes_wired():
    app = make_asgi_app()
    status, body = _drive_asgi(app, "/bundle")
    assert status == 200 and "Ledger bundle verifier" in body.decode()
    status, body = _drive_asgi(app, "/bundle/offline-shell")
    assert status == 200 and "@@BUNDLE_FRAGMENT@@" in body.decode()
    status, body = _drive_asgi(app, "/static/mmr.js")
    assert status == 200 and "verifyInclusion" in body.decode()
    status, body = _drive_asgi(app, "/static/bundle.js")
    assert status == 200 and "checkCompleteness" in body.decode()


def test_bundle_route_matches_capsule_ledger_default_permalink_base():
    """capsule-ledger's asg_ledger/cli/bundle_cmd.py hardcodes
    DEFAULT_VERIFY_BASE_URL = "https://verify.agentactioncapsule.org/bundle" --
    confirm the path this module serves at is exactly "/bundle", no trailing
    segment, so that permalink resolves here unmodified."""
    app = make_asgi_app()
    status, _ = _drive_asgi(app, "/bundle")
    assert status == 200


# ---------------------------------------------------------------------------
# Node-level behavioral tests: privilege log, completeness cert, cross-check
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def js_paths():
    mmr_f = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
    mmr_f.write(MMR_JS)
    mmr_f.close()
    bundle_f = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
    bundle_f.write(BUNDLE_JS)
    bundle_f.close()
    yield Path(mmr_f.name), Path(bundle_f.name)
    Path(mmr_f.name).unlink(missing_ok=True)
    Path(bundle_f.name).unlink(missing_ok=True)


def _run_js(js_paths, op: dict):
    mmr_path, bundle_path = js_paths
    result = subprocess.run(
        ["node", str(HARNESS), str(mmr_path), str(bundle_path)],
        input=json.dumps(op),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


CAPSULE_A = {
    "capsule_id": "a" * 64,
    "chain": {},
    "model_attestation": {"compute_attestation": {
        "subject_digest": "b" * 64,
        "agent_input_digest": "c" * 64,  # withheld: no agent_input payload alongside
    }},
}


@pytestmark_node
def test_withheld_field_renders_as_provable_commitment_never_absent(js_paths):
    """A withheld field must show up in the privilege log as a WITHHELD
    commitment (digest present) -- never simply missing from the log."""
    g = _run_js(js_paths, {"fn": "parseAac", "data": CAPSULE_A})
    ai_rows = [e for e in g["privlog"] if e["type"] == "agent_input"]
    assert len(ai_rows) == 1
    assert ai_rows[0]["withheld"] is True
    assert ai_rows[0]["digest"] == "c" * 64  # the commitment survives even though withheld


@pytestmark_node
def test_revealed_field_recomputes_and_matches(js_paths):
    import hashlib

    payload = "hello agent input"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    envelope = {"capsule": cap, "disclosures": {"agent_input": payload}}
    g = _run_js(js_paths, {"fn": "parseAac", "data": envelope})
    ai_rows = [e for e in g["privlog"] if e["type"] == "agent_input"]
    assert ai_rows[0]["withheld"] is False
    assert ai_rows[0]["_revPayload"] == payload


@pytestmark_node
def test_verify_capsule_digests_confirms_a_genuine_match(js_paths):
    import hashlib

    payload = "hello agent input"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": payload}})
    ai_rows = [e for e in g["privlog"] if e["type"] == "agent_input"]
    assert ai_rows[0]["matchOk"] is True


@pytestmark_node
def test_verify_capsule_digests_catches_a_genuine_mismatch(js_paths):
    """The bug this locks in: an earlier version only ever computed the
    revealed-payload digest inside the DOM-rendering path, *after* the
    ritual/cross-check verdicts had already been decided from privlog
    entries whose matchOk was still unconditionally null -- so a real
    mismatch could never flip either verdict. verifyCapsuleDigests is the
    single, awaited source of truth both now read."""
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = "c" * 64
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": "not the preimage"}})
    ai_rows = [e for e in g["privlog"] if e["type"] == "agent_input"]
    assert ai_rows[0]["matchOk"] is False


@pytestmark_node
def test_completeness_skip_when_certificate_absent(js_paths):
    bundle = {"records": [CAPSULE_A], "checkpoint": {"tree_size": 1}}
    got = _run_js(js_paths, {"fn": "checkCompleteness", "bundle": bundle})
    assert got["status"] == "skip"
    assert "no completeness certificate" in got["detail"]


@pytestmark_node
def test_completeness_pass_with_genuine_certificate(js_paths):
    vectors = json.loads((HERE.parent / "test-vectors" / "mmr" / "proof-vectors.json").read_text())
    c0, c1 = vectors["inclusion_cases"][0], vectors["inclusion_cases"][-1]
    records = [
        {"capsule_id": c0["body_digest"], "chain": {}},
        {"capsule_id": c1["body_digest"], "chain": {}},
    ]
    bundle = {
        "records": records,
        "checkpoint": {"tree_size": vectors["full_size"]},
        "completeness_certificate": {
            "v": 1,
            "range_proof": {
                "from_seq": 1, "to_seq": 2, "size": vectors["full_size"],
                "inclusion_from": c0["proof"], "inclusion_to": c1["proof"],
            },
            "range_root": vectors["full_root"],
            "checkpoint_size": vectors["full_size"],
            "checkpoint_root": vectors["full_root"],
            "consistency_proof": None,
        },
    }
    got = _run_js(js_paths, {"fn": "checkCompleteness", "bundle": bundle})
    assert got["status"] == "pass", got


@pytestmark_node
def test_completeness_fails_on_corrupted_certificate_byte(js_paths):
    vectors = json.loads((HERE.parent / "test-vectors" / "mmr" / "proof-vectors.json").read_text())
    c0, c1 = vectors["inclusion_cases"][0], vectors["inclusion_cases"][-1]
    records = [
        {"capsule_id": c0["body_digest"], "chain": {}},
        {"capsule_id": c1["body_digest"], "chain": {}},
    ]
    tampered_proof = json.loads(json.dumps(c0["proof"]))
    b = bytearray(bytes.fromhex(tampered_proof["witness"][0]))
    b[0] ^= 0xFF
    tampered_proof["witness"][0] = b.hex()
    bundle = {
        "records": records,
        "checkpoint": {"tree_size": vectors["full_size"]},
        "completeness_certificate": {
            "v": 1,
            "range_proof": {
                "from_seq": 1, "to_seq": 2, "size": vectors["full_size"],
                "inclusion_from": tampered_proof, "inclusion_to": c1["proof"],
            },
            "range_root": vectors["full_root"],
            "checkpoint_size": vectors["full_size"],
            "checkpoint_root": vectors["full_root"],
            "consistency_proof": None,
        },
    }
    got = _run_js(js_paths, {"fn": "checkCompleteness", "bundle": bundle})
    assert got["status"] == "fail", got


@pytestmark_node
def test_cross_check_flags_producer_disagreement(js_paths):
    # producer claims ok=True but the capsule's own committed digest doesn't match --
    # our independent recompute must catch this and flag the disagreement.
    tampered = json.loads(json.dumps(CAPSULE_A))
    tampered["model_attestation"]["compute_attestation"]["agent_input_digest"] = "c" * 64
    bundle = {
        "verification": {tampered["capsule_id"]: {"ok": True, "findings": []}},
        "disclosures": {tampered["capsule_id"]: {"agent_input": "not the preimage"}},
    }
    got = _run_js(js_paths, {"fn": "crossCheckSelfReport", "bundle": bundle, "records": [tampered]})
    assert got["status"] == "fail"


@pytestmark_node
def test_cross_check_passes_when_no_self_report_present(js_paths):
    bundle = {}
    got = _run_js(js_paths, {"fn": "crossCheckSelfReport", "bundle": bundle, "records": [CAPSULE_A]})
    assert got["status"] == "pass"


@pytestmark_node
def test_ritual_integrity_stage_fails_on_a_genuine_digest_mismatch(js_paths):
    """End-to-end mutant test at the ritual layer (not just the digest-verify
    unit): a real mismatch must flip the Integrity stage to fail and produce
    a finding naming the field — the ritual banner a recipient actually reads."""
    tampered = json.loads(json.dumps(CAPSULE_A))
    tampered["model_attestation"]["compute_attestation"]["agent_input_digest"] = "c" * 64
    completeness = {"status": "skip", "detail": "n/a"}
    cross_check = {"status": "pass", "detail": "n/a"}
    disclosures = {tampered["capsule_id"]: {"agent_input": "not the preimage"}}
    got = _run_js(js_paths, {
        "fn": "evaluateBundleRitual", "records": [tampered],
        "completeness": completeness, "crossCheck": cross_check, "disclosures": disclosures,
    })
    integrity = next(s for s in got["stages"] if s["name"] == "Integrity")
    assert integrity["status"] == "fail"
    assert got["finding"] is not None
    assert "agent input" in got["finding"]["text"]


@pytestmark_node
def test_ritual_integrity_stage_passes_on_genuine_records(js_paths):
    completeness = {"status": "skip", "detail": "n/a"}
    cross_check = {"status": "pass", "detail": "n/a"}
    got = _run_js(js_paths, {
        "fn": "evaluateBundleRitual", "records": [CAPSULE_A],
        "completeness": completeness, "crossCheck": cross_check,
    })
    integrity = next(s for s in got["stages"] if s["name"] == "Integrity")
    assert integrity["status"] == "pass"
    assert got["finding"] is None


@pytestmark_node
def test_disclosure_envelope_wrapper_never_changes_capsule_id(js_paths):
    """Disclosure Envelope acceptance: capsule_id is identical across
    withheld/match/mismatch — a disclosure never touches the anchored bytes."""
    import hashlib

    payload = "hello agent input"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest

    withheld = _run_js(js_paths, {"fn": "parseAac", "data": cap})
    matching = _run_js(js_paths, {"fn": "parseAac", "data": {"capsule": cap, "disclosures": {"agent_input": payload}}})
    mismatching = _run_js(js_paths, {"fn": "parseAac", "data": {"capsule": cap, "disclosures": {"agent_input": "not the preimage"}}})

    for g in (withheld, matching, mismatching):
        cap_node = next(n for n in g["nodes"] if n["type"] == "capsule")
        assert cap_node["digest"] == cap["capsule_id"]

    w = next(e for e in withheld["privlog"] if e["type"] == "agent_input")
    m = next(e for e in matching["privlog"] if e["type"] == "agent_input")
    assert w["withheld"] is True
    assert m["withheld"] is False and m["_revPayload"] == payload

    mismatch_verified = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": "not the preimage"}})
    mm_entry = next(e for e in mismatch_verified["privlog"] if e["type"] == "agent_input")
    assert mm_entry["matchOk"] is False


# ---------------------------------------------------------------------------
# [ldg-viewer-disclosed-payload-render]: disclosed-payload rendering in the
# privilege log — render the payload only on a genuine match, never on a
# mismatch or a withheld row, with the committed/recomputed digests shown
# alongside it and the same canonicalization used for the hash.
# ---------------------------------------------------------------------------


@pytestmark_node
def test_payload_cell_renders_on_genuine_match(js_paths):
    import hashlib

    payload = {"b": 2, "a": 1}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": payload}})
    entry = next(e for e in g["privlog"] if e["type"] == "agent_input")
    assert entry["matchOk"] is True

    html = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": entry, "recomputedDigest": entry["_recomputedDigest"]})
    assert "<details" in html
    assert '"a": 1' in html and '"b": 2' in html  # pretty-printed, sorted keys
    assert f"committed <code>{digest}</code>" in html
    assert f"recomputed <code>{entry['_recomputedDigest']}</code>" in html
    assert "truncated" not in html


@pytestmark_node
def test_payload_cell_renders_text_not_json_for_string_payload(js_paths):
    import hashlib

    payload = "hello agent input"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": payload}})
    entry = next(e for e in g["privlog"] if e["type"] == "agent_input")
    html = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": entry, "recomputedDigest": entry["_recomputedDigest"]})
    assert "<pre>hello agent input</pre>" in html


@pytestmark_node
def test_payload_cell_renders_nothing_on_mismatch(js_paths):
    """A REVEALED · MISMATCH row must never render the unverified payload —
    an unverified payload next to a green digest is exactly the confusion
    the privilege log exists to prevent."""
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = "c" * 64
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": "not the preimage"}})
    entry = next(e for e in g["privlog"] if e["type"] == "agent_input")
    assert entry["matchOk"] is False

    html = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": entry, "recomputedDigest": entry.get("_recomputedDigest")})
    assert html == ""


@pytestmark_node
def test_payload_cell_renders_nothing_when_withheld(js_paths):
    g = _run_js(js_paths, {"fn": "parseAac", "data": CAPSULE_A})
    entry = next(e for e in g["privlog"] if e["type"] == "agent_input")
    assert entry["withheld"] is True
    html = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": entry, "recomputedDigest": None})
    assert html == ""


@pytestmark_node
def test_bundle_privlog_renders_payload_per_record(js_paths):
    """Bundle path: one record with a genuine match, one withheld — each
    record's row must reflect its own reveal state independently."""
    import hashlib

    payload = "record zero payload"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    rec0 = json.loads(json.dumps(CAPSULE_A))
    rec0["capsule_id"] = "1" * 64
    rec0["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    rec1 = json.loads(json.dumps(CAPSULE_A))
    rec1["capsule_id"] = "2" * 64

    rows = _run_js(js_paths, {
        "fn": "buildBundlePrivlog", "records": [rec0, rec1],
        "disclosures": {rec0["capsule_id"]: {"agent_input": payload}},
    })
    r0 = next(r for r in rows if r["record_index"] == 0 and r["entry"]["type"] == "agent_input")
    r1 = next(r for r in rows if r["record_index"] == 1 and r["entry"]["type"] == "agent_input")
    assert r0["entry"]["matchOk"] is True
    assert r1["entry"]["withheld"] is True

    html0 = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": r0["entry"], "recomputedDigest": r0["entry"]["_recomputedDigest"]})
    html1 = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": r1["entry"], "recomputedDigest": None})
    assert "record zero payload" in html0
    assert html1 == ""


@pytestmark_node
def test_oversized_payload_truncates_with_note(js_paths):
    import hashlib

    payload = {"blob": "x" * 20000}  # pretty-printed JSON exceeds PAYLOAD_TRUNCATE_BYTES (8192)
    canon = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canon.encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": payload}})
    entry = next(e for e in g["privlog"] if e["type"] == "agent_input")
    assert entry["matchOk"] is True

    html = _run_js(js_paths, {"fn": "payloadCellHtml", "entry": entry, "recomputedDigest": entry["_recomputedDigest"]})
    assert "truncated for display, full payload is in the URL fragment" in html
    assert "pl-payload-truncated" in html
    # the full 20000-char blob must not appear verbatim -- it was actually cut
    assert "x" * 20000 not in html


@pytestmark_node
def test_canonicalization_shared_with_digest_path(js_paths):
    """The exact bytes canonicalPayloadText produces for display must be the
    exact bytes verifyCapsuleDigests hashed -- one helper, not two rules that
    could silently diverge."""
    import hashlib

    payload = {"z": [3, 2, 1], "a": "first"}
    canon_from_js = _run_js(js_paths, {"fn": "canonicalPayloadText", "payload": payload})
    assert canon_from_js == json.dumps(payload, sort_keys=True, separators=(",", ":"))

    digest = hashlib.sha256(canon_from_js.encode()).hexdigest()
    cap = json.loads(json.dumps(CAPSULE_A))
    cap["model_attestation"]["compute_attestation"]["agent_input_digest"] = digest
    g = _run_js(js_paths, {"fn": "verifyCapsuleDigests", "data": cap, "disclosures": {"agent_input": payload}})
    entry = next(e for e in g["privlog"] if e["type"] == "agent_input")
    assert entry["matchOk"] is True
    assert entry["_recomputedDigest"] == digest
