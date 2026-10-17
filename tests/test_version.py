# SPDX-License-Identifier: Apache-2.0
"""``scitt_cose.__version__`` tracks the released version.

0.4.1 to 0.4.3 shipped ``__version__ == "0.4.0"`` because the string was
hard-coded while Release · Prepare bumps only pyproject.toml.

The comparison reads installed metadata, so after a local version bump it
fails until ``pip install -e .`` refreshes it; CI installs fresh.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import pathlib
import re

import pytest

import scitt_cose

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    # tomllib is 3.11+; the [project] table's version line is all we need.
    text = REPO_ROOT.joinpath("pyproject.toml").read_text()
    project = re.search(r"^\[project\]$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    assert project, "pyproject.toml has no [project] table"
    match = re.search(r'^version\s*=\s*"([^"]+)"$', project.group(1), re.M)
    assert match, "[project] has no static version"
    return match.group(1)


def _installed() -> bool:
    try:
        importlib.metadata.version("scitt-cose")
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


@pytest.mark.skipif(not _installed(), reason="scitt-cose metadata is not installed")
def test_version_matches_pyproject():
    assert scitt_cose.__version__ == _pyproject_version()


def test_version_without_installed_metadata(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    try:
        assert importlib.reload(scitt_cose).__version__ == "0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(scitt_cose)
