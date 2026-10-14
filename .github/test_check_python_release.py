# SPDX-License-Identifier: Apache-2.0
"""Tests for check_python_release.py, the PyPI publish guard."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import check_python_release as guard

SCRIPT = Path(__file__).parent / "check_python_release.py"


@pytest.fixture
def pyproject(tmp_path: Path) -> Path:
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nname = "scitt-cose"\nversion = "0.4.0"\n')
    return path


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo whose `main` has two commits and whose `side` branch forks off it."""
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "commit", "-q", "--allow-empty", "-m", "one")
    git(path, "commit", "-q", "--allow-empty", "-m", "two")
    git(path, "checkout", "-q", "-b", "side", "HEAD~1")
    git(path, "commit", "-q", "--allow-empty", "-m", "off main")
    return path


def test_accepts_matching_tag(pyproject: Path) -> None:
    guard.check_tag("v0.4.0", pyproject)


def test_accepts_matching_prerelease(tmp_path: Path) -> None:
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nversion = "0.5.0rc1"\n')
    guard.check_tag("v0.5.0rc1", path)


@pytest.mark.parametrize(
    "tag",
    [
        "rust-scitt-cose-v0.4.0",
        "vectors-ietf126",
        "python/v0.4.0",
        "go/v0.4.0",
        "0.4.0",
        "v0.4",
        "v0.4.0-rc.1",
        "v04.0.0",
        "v0.4.0 ",
    ],
)
def test_rejects_other_namespaces_and_malformed_tags(tag: str, pyproject: Path) -> None:
    with pytest.raises(ValueError, match="not a Python release tag"):
        guard.check_tag(tag, pyproject)


@pytest.mark.parametrize("tag", ["v0.3.0", "v0.4.1", "v0.4.0rc1", "v1.4.0"])
def test_rejects_version_mismatch(tag: str, pyproject: Path) -> None:
    with pytest.raises(ValueError, match="does not match pyproject version"):
        guard.check_tag(tag, pyproject)


def test_accepts_commit_on_main(repo: Path) -> None:
    guard.check_on_main("main~1", "main", repo)
    guard.check_on_main("main", "main", repo)


def test_rejects_commit_off_main(repo: Path) -> None:
    with pytest.raises(ValueError, match="not an ancestor"):
        guard.check_on_main("side", "main", repo)


def test_unknown_ref_is_an_error_not_an_answer(repo: Path) -> None:
    with pytest.raises(ValueError, match="git merge-base failed"):
        guard.check_on_main("HEAD", "origin/main", repo)


def run_cli(repo: Path, pyproject: Path, tag: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), tag, "--pyproject", str(pyproject), "--main", "main"],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_passes_matching_tag_on_main(repo: Path, pyproject: Path) -> None:
    git(repo, "checkout", "-q", "main")
    assert run_cli(repo, pyproject, "v0.4.0").returncode == 0


@pytest.mark.parametrize("tag", ["rust-scitt-cose-v0.1.0", "vectors-ietf126", "v0.3.0"])
def test_cli_fails_bad_tag(repo: Path, pyproject: Path, tag: str) -> None:
    git(repo, "checkout", "-q", "main")
    result = run_cli(repo, pyproject, tag)
    assert result.returncode == 2
    assert "error:" in result.stderr


def test_cli_fails_matching_tag_off_main(repo: Path, pyproject: Path) -> None:
    result = run_cli(repo, pyproject, "v0.4.0")  # repo is checked out on `side`
    assert result.returncode == 2
    assert "not an ancestor" in result.stderr
