#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release helper shared, as identical copies, by the action-state-group repos.

Each repository lists the packages it publishes in ``.github/releases.json``::

    {"python": {"kind": "python", "manifest": "python/pyproject.toml",
                "tag_prefix": "python/v", "workflow": "publish-python.yml"}}

``kind`` is ``python`` (pyproject.toml), ``npm`` (package.json, plus the
sibling package-lock.json) or ``cargo`` (Cargo.toml, plus the ``lockfile``
the entry names). A crate's bump also updates its entry in the other cargo
entries' lockfiles, where another crate depends on it by path. A package
releases under ``tag_prefix + version``.

Commands:

``bump PACKAGE major|minor|patch``
    Raise the manifest version (and lockfile) and print the new version.
``changed BEFORE AFTER``
    Print ``package version tag workflow`` for each package whose manifest
    version differs between two commits. A package whose manifest moved is
    read at BEFORE from the path BEFORE's ``releases.json`` gave it, so a
    move alone releases nothing.
``check PACKAGE TAG``
    Fail unless TAG is the package's prefix plus its manifest version and
    the checked-out commit is an ancestor of ``origin/main``. Publish
    workflows run this before uploading.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11; pytest depends on tomli there.
    import tomli as tomllib

CONFIG = Path(".github/releases.json")
CORE = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
VERSION = {
    # PEP 440 pre-releases in normalized form, as pyproject would declare them.
    "python": re.compile(rf"{CORE}(?:(?:a|b|rc)(?:0|[1-9][0-9]*))?"),
    "npm": re.compile(rf"{CORE}(?:-[0-9A-Za-z.-]+)?"),
    # publish-rust.yml publishes only major.minor.patch crate versions.
    "cargo": re.compile(CORE),
}
TABLE = {"python": "project", "cargo": "package"}


def load_config(repo: Path) -> dict:
    return json.loads((repo / CONFIG).read_text())


def package(config: dict, name: str) -> dict:
    if name not in config:
        raise ValueError(f"unknown package {name!r}; .github/releases.json lists {sorted(config)}")
    return config[name]


def read_version(kind: str, text: str) -> str:
    if kind == "npm":
        version = json.loads(text)["version"]
    else:
        version = tomllib.loads(text)[TABLE[kind]]["version"]
    if not isinstance(version, str):
        # A bad manifest, not a programming error: the CLI reports ValueError.
        raise ValueError(f"the {TABLE.get(kind, 'package')} version must be a literal string")  # noqa: TRY004
    return version


def next_version(kind: str, current: str, bump: str) -> str:
    match = VERSION[kind].fullmatch(current)
    if match is None:
        raise ValueError(f"current version {current!r} is not a release version")
    major, minor, patch = (int(part) for part in match.groups())
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"unknown bump {bump!r}")


def replace_toml_version(text: str, table: str, old: str, new: str) -> str:
    """Replace ``version = "old"`` inside ``[table]``, keeping the rest verbatim."""
    header = re.search(rf"^\[{table}\][ \t]*$", text, re.MULTILINE)
    if header is None:
        raise ValueError(f"no [{table}] table")
    end = re.search(r"^\[", text[header.end():], re.MULTILINE)
    stop = header.end() + end.start() if end else len(text)
    body, count = re.subn(
        rf'^(version[ \t]*=[ \t]*"){re.escape(old)}(")',
        rf"\g<1>{new}\g<2>",
        text[header.end():stop],
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise ValueError(f"no literal version in [{table}]")
    return text[: header.end()] + body + text[stop:]


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def bump(repo: Path, entry: dict, kind_bump: str, config: dict | None = None) -> str:
    kind = entry["kind"]
    manifest = repo / entry["manifest"]
    current = read_version(kind, manifest.read_text())
    new = next_version(kind, current, kind_bump)
    if kind == "npm":
        data = json.loads(manifest.read_text())
        data["version"] = new
        write_json(manifest, data)
        lock_path = manifest.with_name("package-lock.json")
        if lock_path.exists():
            lock = json.loads(lock_path.read_text())
            lock["version"] = new
            lock["packages"][""]["version"] = new
            write_json(lock_path, lock)
        return new
    manifest.write_text(replace_toml_version(manifest.read_text(), TABLE[kind], current, new))
    if kind == "cargo":
        name = tomllib.loads(manifest.read_text())["package"]["name"]
        others = {e["lockfile"] for e in (config or {}).values()
                  if e["kind"] == "cargo" and e.get("lockfile") and e is not entry}
        if entry.get("lockfile"):
            if not replace_lock_version(repo / entry["lockfile"], name, current, new):
                raise ValueError(f"{entry['lockfile']} has no {name} {current} entry")
            others.discard(entry["lockfile"])
        for lockfile in sorted(others):
            replace_lock_version(repo / lockfile, name, current, new)
    return new


def replace_lock_version(lock_path: Path, name: str, old: str, new: str) -> bool:
    """Set ``name``'s version in a Cargo.lock; report whether it had the entry."""
    lock, count = re.subn(
        rf'(\[\[package\]\]\nname = "{re.escape(name)}"\nversion = "){re.escape(old)}(")',
        rf"\g<1>{new}\g<2>",
        lock_path.read_text(),
    )
    if count:
        lock_path.write_text(lock)
    return bool(count)


def git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=repo, check=False, capture_output=True, text=True)


def require_commit(repo: Path, commit: str) -> None:
    # An unknown commit (an all-zero or unfetched push `before`, say) must not
    # read as "no previous version": that would release every package again.
    if git(repo, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        raise ValueError(f"unknown commit {commit!r}")


def version_at(repo: Path, entry: dict, commit: str) -> str | None:
    if git(repo, "cat-file", "-e", f"{commit}:{entry['manifest']}").returncode != 0:
        return None  # the manifest does not exist at that (known) commit
    shown = git(repo, "show", f"{commit}:{entry['manifest']}")
    if shown.returncode != 0:
        raise ValueError(f"git show failed: {shown.stderr.strip()}")
    return read_version(entry["kind"], shown.stdout)


def config_at(repo: Path, commit: str) -> dict:
    """The ``releases.json`` at a (known) commit, or ``{}`` if it has none."""
    if git(repo, "cat-file", "-e", f"{commit}:{CONFIG.as_posix()}").returncode != 0:
        return {}
    shown = git(repo, "show", f"{commit}:{CONFIG.as_posix()}")
    if shown.returncode != 0:
        raise ValueError(f"git show failed: {shown.stderr.strip()}")
    return json.loads(shown.stdout)


def changed(repo: Path, config: dict, before: str, after: str) -> list[tuple[str, str, str, str]]:
    require_commit(repo, before)
    require_commit(repo, after)
    # A package keeps its name when its manifest moves, so its previous
    # version is read where the previous configuration put it.
    previous = config_at(repo, before)
    released = []
    for name, entry in config.items():
        new = version_at(repo, entry, after)
        if new is not None and new != version_at(repo, previous.get(name, entry), before):
            released.append((name, new, entry["tag_prefix"] + new, entry["workflow"]))
    return released


def check(repo: Path, entry: dict, tag: str, commit: str = "HEAD", main: str = "origin/main") -> None:
    kind, prefix = entry["kind"], entry["tag_prefix"]
    if not tag.startswith(prefix) or VERSION[kind].fullmatch(tag[len(prefix):]) is None:
        raise ValueError(f"{tag!r} is not a {prefix}<version> release tag")
    version = read_version(kind, (repo / entry["manifest"]).read_text())
    if tag != prefix + version:
        raise ValueError(f"release tag {tag!r} does not match {entry['manifest']} version {version!r}")
    result = git(repo, "merge-base", "--is-ancestor", commit, main)
    # Exit 1 means "not an ancestor"; anything else is a git failure, such as
    # an unknown ref, and must not read as either answer.
    if result.returncode == 1:
        raise ValueError(f"{commit} is not an ancestor of {main}")
    if result.returncode != 0:
        raise ValueError(f"git merge-base failed: {result.stderr.strip()}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", type=Path, default=Path("."))
    commands = parser.add_subparsers(dest="command", required=True)
    bump_parser = commands.add_parser("bump")
    bump_parser.add_argument("package")
    bump_parser.add_argument("bump", choices=["major", "minor", "patch"])
    changed_parser = commands.add_parser("changed")
    changed_parser.add_argument("before")
    changed_parser.add_argument("after")
    check_parser = commands.add_parser("check")
    check_parser.add_argument("package")
    check_parser.add_argument("tag")
    check_parser.add_argument("--commit", default="HEAD")
    check_parser.add_argument("--main", default="origin/main")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.repo)
        if args.command == "bump":
            print(bump(args.repo, package(config, args.package), args.bump, config))
        elif args.command == "changed":
            for row in changed(args.repo, config, args.before, args.after):
                print(" ".join(row))
        else:
            check(args.repo, package(config, args.package), args.tag, args.commit, args.main)
    except (ValueError, KeyError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main(sys.argv[1:])
