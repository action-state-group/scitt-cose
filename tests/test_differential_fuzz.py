# SPDX-License-Identifier: Apache-2.0
"""Bounded differential-fuzz smoke test wired into the unit suite.

The full corpus runs in the dedicated CI `fuzz` job (scripts/differential_fuzz.py
with a larger iteration budget). This test runs a small deterministic batch so a
NEW Python-vs-Go verifier divergence (one not in tests/fuzz/baseline.json) is
caught even in a plain `pytest` run.

Like test_crosslang_go.py it SKIPS when Go is unavailable and FAILS that skip
when SCITT_REQUIRE_GO=1 (CI), so the cross-language fuzz can never silently
vanish.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GO_DIR = REPO / "scitt-cose-go-verify"
_REQUIRE_GO = os.environ.get("SCITT_REQUIRE_GO") == "1"


def _skip_or_fail(reason: str) -> None:
    if _REQUIRE_GO:
        pytest.fail(f"SCITT_REQUIRE_GO=1 but differential fuzz unavailable: {reason}")
    pytest.skip(reason)


@pytest.fixture(scope="session")
def go_binary(tmp_path_factory: pytest.TempPathFactory) -> str:
    go = shutil.which("go")
    if go is None:
        _skip_or_fail("go is not on PATH")
    out = tmp_path_factory.mktemp("gv") / "scitt-cose-go-verify"
    proc = subprocess.run([go, "build", "-o", str(out), "."], cwd=str(GO_DIR),
                          capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:  # pragma: no cover - env
        _skip_or_fail(f"go build failed: {proc.stderr}")
    return str(out)


def test_no_new_verifier_divergence(go_binary):
    """A small deterministic fuzz batch must surface no divergence outside the
    committed baseline. (The big run is the CI `fuzz` job.)"""
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "differential_fuzz.py"),
         "--go-binary", go_binary, "--iterations", "120", "--seed", "20250612"],
        capture_output=True, text=True, timeout=600,
    )
    assert proc.returncode == 0, (
        "differential fuzz found a NEW Python<->Go verifier divergence "
        f"not in tests/fuzz/baseline.json:\n{proc.stdout}\n{proc.stderr}"
    )
