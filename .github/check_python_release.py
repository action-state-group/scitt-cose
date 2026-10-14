#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse a PyPI publish unless the release tag is the Python package's own.

The Python package releases under bare ``v<version>`` tags (``v0.4.0``); the
other tags in this repository (``rust-scitt-cose-v*``, ``vectors-*``) belong to
other artifacts. A release passes only when its tag is exactly ``v`` + the
``[project].version`` in ``pyproject.toml`` and the tagged commit is an
ancestor of ``origin/main``. The workflow routes on the ``v``
prefix too; this check is the authority, so a tag the prefix lets through
still fails here.
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11; pytest depends on tomli there.
    import tomli as tomllib

SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
# PEP 440 pre-releases in normalized form, as pyproject would declare them.
TAG = re.compile(rf"v{SEMVER}(?:(?:a|b|rc)(?:0|[1-9][0-9]*))?")


def check_tag(tag: str, pyproject: Path) -> None:
    if TAG.fullmatch(tag) is None:
        raise ValueError(f"{tag!r} is not a Python release tag (v<version>)")
    with pyproject.open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    if tag != f"v{version}":
        raise ValueError(f"release tag {tag!r} does not match pyproject version {version!r}")


def check_on_main(commit: str, main: str, repo: Path) -> None:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, main],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    # Exit 1 means "not an ancestor"; anything else is a git failure, such as
    # an unknown ref, and must not read as either answer.
    if result.returncode == 1:
        raise ValueError(f"{commit} is not an ancestor of {main}")
    if result.returncode != 0:
        raise ValueError(f"git merge-base failed: {result.stderr.strip()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--main", default="origin/main")
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        check_tag(args.tag, args.pyproject)
        check_on_main(args.commit, args.main, args.repo)
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
