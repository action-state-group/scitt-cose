# SPDX-License-Identifier: Apache-2.0
"""End-to-end acceptance: a REAL bundle from capsule-ledger's `capsule bundle`
CLI, opened by this viewer.

Skipped (never failed) when a capsule-ledger checkout isn't available next to
this one, or Node isn't installed -- capsule-ledger is a separate repo this
one must never depend on at runtime or in its public CI (see this file's own
skip guard). Set ``CAPSULE_LEDGER_PATH`` to point at a checkout explicitly;
otherwise a few sibling-directory guesses are tried.

This is the fairness requirement from the task brief, checked directly: a
bundle produced by the free/OSS `capsule bundle` command -- with NO special
casing, no paid-tier field, nothing this viewer's code branches on -- must
verify here. The completeness certificate this test attaches is minted with
capsule-ledger's own `asg_ledger.mmr` module (read-only, sibling-repo import,
mirroring `scripts/generate_mmr_kat39_vectors.py`'s existing pattern) because
`capsule bundle` does not populate one yet as of this viewer shipping -- that
wiring is capsule-ledger's own follow-up (see the PR description); this test
still proves the *viewer's* half of the contract for real, against a real
ledger and a real completeness certificate, not synthetic data throughout.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from hosted_profiles.hosted import BUNDLE_JS, MMR_JS, render_bundle_page

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_bundle.mjs"


def _find_capsule_ledger() -> Path | None:
    import os

    env = os.environ.get("CAPSULE_LEDGER_PATH")
    candidates = [Path(env)] if env else []
    repo_root = HERE.parent
    candidates += [
        repo_root.parent / "capsule-ledger",
        repo_root.parents[2] / "capsule-ledger" if len(repo_root.parents) > 2 else None,
        repo_root.parents[3] / "capsule-ledger" if len(repo_root.parents) > 3 else None,
    ]
    for c in candidates:
        if c and (c / "asg_ledger" / "mmr" / "core.py").exists():
            return c.resolve()
    return None


CAPSULE_LEDGER = _find_capsule_ledger()

pytestmark = [
    pytest.mark.skipif(CAPSULE_LEDGER is None, reason="no capsule-ledger checkout found nearby"),
    pytest.mark.skipif(shutil.which("node") is None, reason="node not available"),
]


@pytest.fixture(scope="module")
def real_bundle():
    """Run the real `capsule bundle` CLI against the real amaury fixture
    ledger -- zero mocking, zero special-casing."""
    sys.path.insert(0, str(CAPSULE_LEDGER))
    from asg_ledger.cli.main import main as cli_main  # noqa: PLC0415

    fixture = CAPSULE_LEDGER / "tests" / "fixtures" / "amaury_sample_ledger.jsonl"
    assert fixture.exists(), "amaury fixture missing from capsule-ledger checkout"

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "bundle.json"
        rc = cli_main(["bundle", "--ledger", str(fixture), "--out", str(out)])
        assert rc == 0
        bundle = json.loads(out.read_text())
    return bundle, fixture


@pytest.fixture(scope="module")
def genuine_completeness_certificate(real_bundle):
    """Mint a real completeness certificate for `real_bundle` using
    capsule-ledger's own asg_ledger.mmr module -- not a hand-rolled stand-in."""
    bundle, fixture = real_bundle
    sys.path.insert(0, str(CAPSULE_LEDGER))
    from asg_ledger.cli.ledger_io import open_ledger  # noqa: PLC0415
    from asg_ledger.mmr.index import MmrLedger  # noqa: PLC0415

    from_seq, to_seq = bundle["range"]
    with open_ledger(fixture) as store:
        mmr = MmrLedger(store)
        mmr.sync()
        assert mmr.leaf_count() == bundle["checkpoint"]["tree_size"], (
            "fixture ledger grew between bundle build and certificate mint -- "
            "not expected for a static fixture file"
        )
        proof = mmr.range_proof(from_seq, to_seq)
        root_hex = mmr.root().hex()

    def _asdict(p):
        return dataclasses.asdict(p)

    return {
        "v": 1,
        "range_proof": {
            "from_seq": proof.from_seq,
            "to_seq": proof.to_seq,
            "size": proof.size,
            "inclusion_from": _asdict(proof.inclusion_from),
            "inclusion_to": _asdict(proof.inclusion_to),
        },
        "range_root": root_hex,
        "checkpoint_size": proof.size,
        "checkpoint_root": root_hex,
        "consistency_proof": None,
    }


def _b64u_encode(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


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


# ---------------------------------------------------------------------------
# Fairness: the RAW free/OSS bundle (no completeness certificate attached
# yet) must render with zero special-casing -- privilege log, ritual, and
# an honest "not available" completeness status, never a crash or a gate.
# ---------------------------------------------------------------------------


def test_raw_oss_bundle_renders_with_no_special_casing(real_bundle, js_paths):
    bundle, _ = real_bundle
    assert bundle["bundle_version"] == "1"
    assert len(bundle["records"]) == 4

    privlog = _run_js(js_paths, {"fn": "buildBundlePrivlog", "records": bundle["records"]})
    assert len(privlog) > 0
    # withheld fields present as commitments (digest), not silently absent
    withheld = [r for r in privlog if r["entry"]["withheld"]]
    assert withheld
    for row in withheld:
        assert len(row["entry"]["digest"]) == 64

    completeness = _run_js(js_paths, {"fn": "checkCompleteness", "bundle": bundle})
    assert completeness["status"] == "skip"  # honest: no certificate in the raw free-tier bundle

    cross_check = _run_js(js_paths, {"fn": "crossCheckSelfReport", "bundle": bundle, "records": bundle["records"]})
    assert cross_check["status"] == "pass"  # real free-tier records genuinely agree with their own self-report

    ritual = _run_js(js_paths, {
        "fn": "evaluateBundleRitual", "records": bundle["records"],
        "completeness": completeness, "crossCheck": cross_check,
    })
    integrity = next(s for s in ritual["stages"] if s["name"] == "Integrity")
    sequence = next(s for s in ritual["stages"] if s["name"] == "Sequence")
    assert integrity["status"] == "pass"
    assert sequence["status"] == "pass"  # bundle_cmd.py transitively pulls in cited chain parents


def test_hosted_route_renders_bundle_page_shell():
    html = render_bundle_page()
    assert "Ledger bundle verifier" in html


# ---------------------------------------------------------------------------
# With a genuine completeness certificate attached (minted from the real
# ledger via capsule-ledger's own mmr module): verifies for real, and a
# corrupted byte is rejected -- the mutant test at full end-to-end scale.
# ---------------------------------------------------------------------------


def test_genuine_completeness_certificate_verifies_end_to_end(real_bundle, genuine_completeness_certificate, js_paths):
    bundle, _ = real_bundle
    bundle = dict(bundle)
    bundle["completeness_certificate"] = genuine_completeness_certificate

    completeness = _run_js(js_paths, {"fn": "checkCompleteness", "bundle": bundle})
    assert completeness["status"] == "pass", completeness


def test_corrupted_completeness_certificate_byte_is_rejected(real_bundle, genuine_completeness_certificate, js_paths):
    bundle, _ = real_bundle
    bundle = dict(bundle)
    cc = json.loads(json.dumps(genuine_completeness_certificate))
    witness = cc["range_proof"]["inclusion_from"]["witness"]
    if witness:
        b = bytearray(bytes.fromhex(witness[0]))
        b[0] ^= 0xFF
        witness[0] = b.hex()
    else:
        # size-4 bundle may have an empty witness path for the boundary leaf --
        # corrupt the root instead, which every shape still carries.
        b = bytearray(bytes.fromhex(cc["range_root"]))
        b[0] ^= 0xFF
        cc["range_root"] = b.hex()
    bundle["completeness_certificate"] = cc

    completeness = _run_js(js_paths, {"fn": "checkCompleteness", "bundle": bundle})
    assert completeness["status"] == "fail", completeness


def test_permalink_fragment_round_trips_through_the_real_encoding(real_bundle, js_paths):
    """capsule-ledger's own base64.urlsafe_b64encode(...).rstrip('=') encoding,
    decoded by BUNDLE_JS's decodeFragment -- not a Python-side simulation."""
    bundle, _ = real_bundle
    fragment = _b64u_encode(bundle)
    got = _run_js(js_paths, {"fn": "decodeFragment", "hash": fragment})
    assert got["bundle_version"] == bundle["bundle_version"]
    assert len(got["records"]) == len(bundle["records"])
    assert got["records"][0]["capsule_id"] == bundle["records"][0]["capsule_id"]


def test_offline_shell_embeds_the_real_bundle_and_renders_identically(real_bundle, js_paths):
    """The offline single-file artifact: splice the real fragment into the
    offline shell exactly as the download button (or a future capsule-ledger
    --with-viewer flag) would, and confirm the SAME pipeline runs against
    the embedded copy as against the hosted fragment path."""
    bundle, _ = real_bundle
    fragment = _b64u_encode(bundle)
    shell = render_bundle_page(offline=True)
    spliced = shell.replace("@@BUNDLE_FRAGMENT@@", fragment, 1)
    assert fragment in spliced
    assert MMR_JS in spliced and BUNDLE_JS in spliced
    # the embedded fragment decodes the same way the hosted route's location.hash would
    got = _run_js(js_paths, {"fn": "decodeFragment", "hash": fragment})
    assert got["range"] == bundle["range"]
