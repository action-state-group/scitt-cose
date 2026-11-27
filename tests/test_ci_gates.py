# SPDX-License-Identifier: Apache-2.0
"""The CI gates fail when they should: no silent pass on an error or a skip.

Each required check here once had a path that reported success without
checking anything (a pipe without pipefail, a negated grep that hid grep's own
error, a commit listing whose failure the loop never saw). These tests pin the
fixed behavior.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def test_every_workflow_runs_steps_with_pipefail():
    # An unset `shell:` runs `bash -e {0}`, without pipefail, so a failing
    # command piped into another one passes the step.
    files = sorted(WORKFLOWS.glob("*.yml"))
    assert files
    for f in files:
        text = f.read_text(encoding="utf-8")
        if not re.search(r"^\s+(- )?run:", text, re.M):
            continue
        assert re.search(r"^defaults:\n  run:\n    shell: bash\n", text, re.M), (
            f"{f.name} has run steps but no top-level `defaults: run: shell: bash`"
        )


def _run(cmd, cwd=ROOT, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)


@needs_bash
def test_neutrality_gate_passes_clean_tree(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    r = _run(["bash", str(ROOT / "scripts/neutrality_gate.sh"), str(tmp_path)])
    assert r.returncode == 0, r.stdout + r.stderr


@needs_bash
def test_neutrality_gate_fails_on_reference(tmp_path):
    (tmp_path / "bad.py").write_text("import " + "goph" + "er_ai\n")
    r = _run(["bash", str(ROOT / "scripts/neutrality_gate.sh"), str(tmp_path)])
    assert r.returncode == 1
    assert "reference found" in r.stdout


@needs_bash
def test_neutrality_gate_fails_on_missing_dir(tmp_path):
    r = _run(["bash", str(ROOT / "scripts/neutrality_gate.sh"), str(tmp_path / "missing")])
    assert r.returncode == 1
    assert "tree not checked" in r.stdout


@needs_bash
@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="root reads a mode-000 file")
def test_neutrality_gate_fails_when_grep_errors(tmp_path):
    unreadable = tmp_path / "secret.py"
    unreadable.write_text("x = 1\n")
    unreadable.chmod(0)
    try:
        r = _run(["bash", str(ROOT / "scripts/neutrality_gate.sh"), str(tmp_path)])
    finally:
        unreadable.chmod(0o644)
    assert r.returncode == 1
    assert "grep failed" in r.stdout


def _git(repo, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _head(repo):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "commit", "-q", "--allow-empty", "-m", "base")
    return tmp_path


TRAILER = "Signed-off" + "-by: T <t@example.com>"


@needs_bash
@needs_git
def test_dco_passes_signed_commits(repo):
    base = _head(repo)
    _git(repo, "commit", "-q", "--allow-empty", "-m", f"feat: a\n\n{TRAILER}")
    r = _run(["bash", str(ROOT / "scripts/dco_check.sh"), base, _head(repo)], cwd=repo)
    assert r.returncode == 0, r.stdout + r.stderr


@needs_bash
@needs_git
def test_dco_fails_unsigned_commit(repo):
    base = _head(repo)
    _git(repo, "commit", "-q", "--allow-empty", "-m", f"feat: a\n\n{TRAILER}")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "feat: unsigned")
    r = _run(["bash", str(ROOT / "scripts/dco_check.sh"), base, _head(repo)], cwd=repo)
    assert r.returncode == 1
    assert "feat: unsigned" in r.stdout


@needs_bash
@needs_git
def test_dco_fails_when_commit_listing_fails(repo):
    bad = "0" * 40
    r = _run(["bash", str(ROOT / "scripts/dco_check.sh"), bad, _head(repo)], cwd=repo)
    assert r.returncode != 0
    assert "All commits signed off" not in r.stdout


def _oracle_without_pycose(tmp_path, require):
    # A `pycose` module that fails to import stands in for a missing oracle.
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "pycose.py").write_text('raise ImportError("blocked for this test")\n')
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(shim), env.get("PYTHONPATH", "")])
    env.pop("SCITT_REQUIRE_PYCOSE", None)
    if require:
        env["SCITT_REQUIRE_PYCOSE"] = "1"
    return _run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                 "tests/test_thirdparty_cose.py"], env=env)


def test_oracle_skips_without_pycose_by_default(tmp_path):
    r = _oracle_without_pycose(tmp_path, require=False)
    # Exit 5: the module skipped, so pytest collected no test. Not a failure.
    assert r.returncode == 5, r.stdout + r.stderr
    assert "skipped" in r.stdout


def test_oracle_fails_without_pycose_when_required(tmp_path):
    r = _oracle_without_pycose(tmp_path, require=True)
    assert r.returncode != 0
    assert "SCITT_REQUIRE_PYCOSE=1" in r.stdout
