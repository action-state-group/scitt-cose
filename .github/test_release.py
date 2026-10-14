# SPDX-License-Identifier: Apache-2.0
"""Tests for release.py: version bumps, change detection and the publish guard."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import release

SCRIPT = Path(__file__).parent / "release.py"

CONFIG = {
    "python": {"kind": "python", "manifest": "python/pyproject.toml",
               "tag_prefix": "python/v", "workflow": "publish-python.yml"},
    "ts": {"kind": "npm", "manifest": "ts/package.json",
           "tag_prefix": "ts/v", "workflow": "publish-ts.yml"},
    "crates/demo": {"kind": "cargo", "manifest": "rust/Cargo.toml", "lockfile": "rust/Cargo.lock",
                    "tag_prefix": "crates/demo-v", "workflow": "publish-rust.yml"},
}

PYPROJECT = """[build-system]
requires = ["hatchling"]

[project]
name = "demo"
version = "0.7.0"
dependencies = ["dep>=1.0"]

[tool.other]
version = "9.9.9"
"""

CARGO = """[package]
name = "demo"
version = "0.2.3"
edition = "2021"

[dependencies]
serde = { version = "1" }
"""

CARGO_LOCK = """version = 4

[[package]]
name = "demo"
version = "0.2.3"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "0.2.3"
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo with one package of each kind, committed on `main`."""
    root = tmp_path / "repo"
    for path, text in {
        ".github/releases.json": json.dumps(CONFIG),
        "python/pyproject.toml": PYPROJECT,
        "ts/package.json": json.dumps({"name": "demo", "version": "0.1.0", "private": False}, indent=2) + "\n",
        "ts/package-lock.json": json.dumps(
            {"name": "demo", "version": "0.1.0", "lockfileVersion": 3,
             "packages": {"": {"name": "demo", "version": "0.1.0"}}}, indent=2) + "\n",
        "rust/Cargo.toml": CARGO,
        "rust/Cargo.lock": CARGO_LOCK,
    }.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text)
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "one")
    return root


@pytest.mark.parametrize(
    ("kind", "current", "bump", "expected"),
    [
        ("python", "0.7.0", "patch", "0.7.1"),
        ("python", "0.7.3", "minor", "0.8.0"),
        ("python", "0.7.3", "major", "1.0.0"),
        ("python", "0.8.0rc1", "patch", "0.8.1"),
        ("npm", "1.2.3-rc.1", "minor", "1.3.0"),
    ],
)
def test_next_version(kind: str, current: str, bump: str, expected: str) -> None:
    assert release.next_version(kind, current, bump) == expected


def test_next_version_refuses_a_malformed_current_version() -> None:
    with pytest.raises(ValueError, match="not a release version"):
        release.next_version("python", "0.7", "patch")


def test_bump_python_changes_only_the_project_version(repo: Path) -> None:
    assert release.bump(repo, CONFIG["python"], "minor") == "0.8.0"
    assert (repo / "python/pyproject.toml").read_text() == PYPROJECT.replace(
        'name = "demo"\nversion = "0.7.0"', 'name = "demo"\nversion = "0.8.0"')


def test_bump_npm_updates_package_and_lockfile(repo: Path) -> None:
    assert release.bump(repo, CONFIG["ts"], "patch") == "0.1.1"
    assert json.loads((repo / "ts/package.json").read_text())["version"] == "0.1.1"
    lock = json.loads((repo / "ts/package-lock.json").read_text())
    assert lock["version"] == lock["packages"][""]["version"] == "0.1.1"


def test_bump_cargo_updates_manifest_and_own_lock_entry(repo: Path) -> None:
    assert release.bump(repo, CONFIG["crates/demo"], "major") == "1.0.0"
    assert 'version = "1.0.0"' in (repo / "rust/Cargo.toml").read_text()
    assert 'serde = { version = "1" }' in (repo / "rust/Cargo.toml").read_text()
    lock = (repo / "rust/Cargo.lock").read_text()
    assert 'name = "demo"\nversion = "1.0.0"' in lock
    assert 'name = "serde"\nversion = "0.2.3"' in lock


def test_bump_cargo_updates_path_dependents_lockfiles(repo: Path) -> None:
    """A crate used by another crate's path dependency is bumped in that lock too."""
    (repo / "book").mkdir()
    (repo / "book/Cargo.toml").write_text(CARGO.replace('name = "demo"', 'name = "book"'))
    (repo / "book/Cargo.lock").write_text(CARGO_LOCK + '\n[[package]]\nname = "book"\nversion = "0.2.3"\n')
    config = {**CONFIG, "crates/book": {"kind": "cargo", "manifest": "book/Cargo.toml",
                                        "lockfile": "book/Cargo.lock", "tag_prefix": "crates/book-v",
                                        "workflow": "publish-rust.yml"}}
    assert release.bump(repo, config["crates/demo"], "patch", config) == "0.2.4"
    book_lock = (repo / "book/Cargo.lock").read_text()
    assert 'name = "demo"\nversion = "0.2.4"' in book_lock
    assert 'name = "book"\nversion = "0.2.3"' in book_lock
    assert 'name = "serde"\nversion = "0.2.3"' in book_lock


def test_bump_refuses_an_inherited_version(repo: Path) -> None:
    (repo / "rust/Cargo.toml").write_text(CARGO.replace('version = "0.2.3"', "version.workspace = true"))
    with pytest.raises((ValueError, KeyError)):
        release.bump(repo, CONFIG["crates/demo"], "patch")


def test_changed_reports_only_packages_whose_version_moved(repo: Path) -> None:
    before = git(repo, "rev-parse", "HEAD")
    release.bump(repo, CONFIG["python"], "minor")
    (repo / "ts/README.md").write_text("docs only\n")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "two")
    after = git(repo, "rev-parse", "HEAD")
    assert release.changed(repo, CONFIG, before, after) == [
        ("python", "0.8.0", "python/v0.8.0", "publish-python.yml"),
    ]
    assert release.changed(repo, CONFIG, after, after) == []


@pytest.mark.parametrize("before", ["0" * 40, "1234567890abcdef1234567890abcdef12345678"])
def test_changed_refuses_an_unknown_commit(repo: Path, before: str) -> None:
    head = git(repo, "rev-parse", "HEAD")
    with pytest.raises(ValueError, match="unknown commit"):
        release.changed(repo, CONFIG, before, head)


def test_changed_reports_a_newly_added_package(repo: Path) -> None:
    before = git(repo, "rev-parse", "HEAD")
    config = {**CONFIG, "extra": {**CONFIG["python"], "manifest": "extra/pyproject.toml",
                                  "tag_prefix": "extra/v"}}
    (repo / "extra").mkdir()
    (repo / "extra/pyproject.toml").write_text(PYPROJECT)
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "add extra")
    after = git(repo, "rev-parse", "HEAD")
    assert release.changed(repo, config, before, after) == [
        ("extra", "0.7.0", "extra/v0.7.0", "publish-python.yml"),
    ]


def move_cargo_manifest(repo: Path, version: str | None = None) -> dict:
    """Move the crate to rust/demo/ in the layout's workspace and commit it."""
    config = {**CONFIG, "crates/demo": {**CONFIG["crates/demo"], "manifest": "rust/demo/Cargo.toml"}}
    (repo / "rust/demo").mkdir()
    git(repo, "mv", "rust/Cargo.toml", "rust/demo/Cargo.toml")
    (repo / "rust/Cargo.toml").write_text('[workspace]\nmembers = ["demo"]\n')
    if version is not None:
        manifest = repo / "rust/demo/Cargo.toml"
        manifest.write_text(manifest.read_text().replace('version = "0.2.3"', f'version = "{version}"', 1))
    (repo / ".github/releases.json").write_text(json.dumps(config))
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "move the crate")
    return config


def test_changed_ignores_a_manifest_that_only_moved(repo: Path) -> None:
    before = git(repo, "rev-parse", "HEAD")
    config = move_cargo_manifest(repo)
    after = git(repo, "rev-parse", "HEAD")
    assert release.changed(repo, config, before, after) == []


def test_changed_reports_a_moved_manifest_whose_version_moved(repo: Path) -> None:
    before = git(repo, "rev-parse", "HEAD")
    config = move_cargo_manifest(repo, "0.3.0")
    after = git(repo, "rev-parse", "HEAD")
    assert release.changed(repo, config, before, after) == [
        ("crates/demo", "0.3.0", "crates/demo-v0.3.0", "publish-rust.yml"),
    ]


def test_changed_without_a_previous_config_reads_the_current_paths(repo: Path) -> None:
    git(repo, "rm", "-q", ".github/releases.json")
    git(repo, "commit", "-q", "-m", "no config yet")
    before = git(repo, "rev-parse", "HEAD")
    (repo / ".github").mkdir(exist_ok=True)
    (repo / ".github/releases.json").write_text(json.dumps(CONFIG))
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "adopt the release flow")
    after = git(repo, "rev-parse", "HEAD")
    assert release.changed(repo, CONFIG, before, after) == []


@pytest.mark.parametrize(
    ("name", "tag"),
    [("python", "python/v0.7.0"), ("ts", "ts/v0.1.0"), ("crates/demo", "crates/demo-v0.2.3")],
)
def test_check_accepts_the_matching_tag_on_main(repo: Path, name: str, tag: str) -> None:
    release.check(repo, CONFIG[name], tag, main="main")


@pytest.mark.parametrize(
    ("name", "tag", "message"),
    [
        ("python", "v0.7.0", "not a python/v"),
        ("python", "go/v0.7.0", "not a python/v"),
        ("python", "ts/v0.7.0", "not a python/v"),
        ("python", "legacy-verify/v0.7.0", "not a python/v"),
        ("python", "python/v0.7", "not a python/v"),
        ("python", "python/v0.7.0 ", "not a python/v"),
        ("python", "python/v0.6.0", "does not match"),
        ("python", "python/v0.7.0rc1", "does not match"),
        ("ts", "ts/v0.1.1", "does not match"),
        ("ts", "python/v0.1.0", "not a ts/v"),
        ("crates/demo", "crates/other-v0.2.3", "not a crates/demo-v"),
        ("crates/demo", "crates/demo-v0.2.3-rc.1", "not a crates/demo-v"),
    ],
)
def test_check_rejects_foreign_and_mismatched_tags(repo: Path, name: str, tag: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        release.check(repo, CONFIG[name], tag, main="main")


def test_check_rejects_a_commit_off_main(repo: Path) -> None:
    git(repo, "checkout", "-q", "-b", "side")
    git(repo, "commit", "-q", "--allow-empty", "-m", "off main")
    with pytest.raises(ValueError, match="not an ancestor"):
        release.check(repo, CONFIG["python"], "python/v0.7.0", main="main")


def test_check_reports_an_unknown_main_as_an_error(repo: Path) -> None:
    with pytest.raises(ValueError, match="git merge-base failed"):
        release.check(repo, CONFIG["python"], "python/v0.7.0", main="origin/main")


def run_cli(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=repo, check=False,
                          capture_output=True, text=True)


def test_cli_round_trip(repo: Path) -> None:
    before = git(repo, "rev-parse", "HEAD")
    bumped = run_cli(repo, "bump", "ts", "minor")
    assert bumped.returncode == 0 and bumped.stdout == "0.2.0\n"
    git(repo, "commit", "-q", "-am", "release")
    after = git(repo, "rev-parse", "HEAD")
    listed = run_cli(repo, "changed", before, after)
    assert listed.stdout == "ts 0.2.0 ts/v0.2.0 publish-ts.yml\n"
    assert run_cli(repo, "check", "ts", "ts/v0.2.0", "--main", "main").returncode == 0
    refused = run_cli(repo, "check", "ts", "ts/v0.1.0", "--main", "main")
    assert refused.returncode == 2 and "does not match" in refused.stderr


def test_cli_rejects_an_unknown_package(repo: Path) -> None:
    result = run_cli(repo, "bump", "go", "patch")
    assert result.returncode == 2 and "unknown package" in result.stderr
