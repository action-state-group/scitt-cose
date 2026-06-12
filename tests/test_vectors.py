# SPDX-License-Identifier: Apache-2.0
"""The committed test-vector set must pass under this implementation.

The authoritative entry point is ``python -m scitt_cose.vectors`` (and the Go
``vectors_test.go``) — this unit test wires the same runner into the pytest
suite so a regression in the library against the FROZEN vector bytes is caught
even outside the dedicated CI vectors job.
"""
from __future__ import annotations

import json
from pathlib import Path

from scitt_cose.vectors import check_vector, main

VECTORS = Path(__file__).resolve().parents[1] / "test-vectors"


def test_manifest_is_append_only_and_complete():
    manifest = json.loads((VECTORS / "manifest.json").read_text())
    assert manifest["version"] == "v1"
    assert manifest["stability"] == "append-only"
    ids = [v["id"] for v in manifest["vectors"]]
    # v1 ships at least the five requested vectors; append-only means this
    # list may GROW but existing entries never change or disappear.
    for required in ("valid-eddsa", "valid-es256", "fail-tampered-path",
                     "fail-unsupported-vds", "fail-bad-statement-sig"):
        assert required in ids
    for v in manifest["vectors"]:
        d = VECTORS / v["dir"]
        for fname in ("statement.cose", "payload.bin", "receipt.cose",
                      "issuer-key.pub", "log-key.pub", "expected.json"):
            assert (d / fname).is_file(), f"{v['id']}: missing {fname}"
        if v["expected_result"] == "INVALID":
            assert v.get("failure_code"), f"{v['id']}: INVALID vector needs failure_code"


def test_every_vector_passes():
    manifest = json.loads((VECTORS / "manifest.json").read_text())
    for v in manifest["vectors"]:
        d = VECTORS / v["dir"]
        expected = json.loads((d / "expected.json").read_text())
        mismatches = check_vector(d, expected)
        assert not mismatches, f"{v['id']}: {mismatches}"


def test_runner_cli_exits_zero():
    assert main([str(VECTORS)]) == 0


def test_runner_fails_on_corrupted_expectation(tmp_path):
    """The runner must FAIL when an expectation doesn't hold — i.e. it must be
    able to fail, including on a negative vector that unexpectedly verifies."""
    import shutil

    shutil.copytree(VECTORS, tmp_path / "test-vectors")
    bad = tmp_path / "test-vectors" / "v1" / "fail-tampered-path" / "expected.json"
    exp = json.loads(bad.read_text())
    exp["receipt_valid"] = True  # claim the tampered receipt should verify
    exp["result"] = "VALID"
    bad.write_text(json.dumps(exp))
    assert main([str(tmp_path / "test-vectors")]) == 1
