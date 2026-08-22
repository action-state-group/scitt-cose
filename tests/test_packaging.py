# SPDX-License-Identifier: Apache-2.0
"""sdist-scope mirror of test_iana_codepoints.test_no_application_profile_renderers_in_package.

setuptools' sdist command adds `tests/test*.py` to every source distribution by
default, independent of MANIFEST.in (see distutils.command.sdist._add_defaults_optional).
Without an explicit exclusion, that default silently pulls hosted_profiles-dependent
tests (and would, if anyone "fixed" the resulting collection errors by widening the
sdist instead) back into the released source artifact -- undoing the neutrality
separation the wheel-level test above pins.

This builds a REAL sdist and inspects the actual tarball, not a reimplementation
of setuptools' inclusion rules, so a regression in the packaging config is what
trips this test, not a drift between two independent descriptions of the rule.

The forbidden-filename set below is computed from the repo's own tests/ tree
(via AST, not a hand-maintained list) -- round 2 caught five hosted_profiles-
dependent test files and hand-listed them in MANIFEST.in + here; round 3 found
a sixth (test_envelope_unwrap.py) had landed via an unrelated merge without
either list being updated, so this test silently passed while the file itself
still broke sdist collection. A hardcoded list can only ever be as current as
the last person who remembered to edit it; scanning the source tree for
`import hosted_profiles` / `from hosted_profiles import ...` closes that gap
structurally -- any future hosted_profiles-dependent test is forbidden
automatically, on the day it's added, whether or not anyone remembers this file.
"""
from __future__ import annotations

import ast
import pathlib
import subprocess
import sys
import tarfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _hosted_profiles_dependent_test_filenames() -> set[str]:
    """Filenames under tests/ whose module imports hosted_profiles (or a
    submodule of it), determined by parsing the actual source -- not a
    hand-maintained list that can silently fall behind the tree.
    """
    forbidden: set[str] = set()
    for path in sorted(REPO_ROOT.joinpath("tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and any(
                alias.name.split(".")[0] == "hosted_profiles" for alias in node.names
            ):
                forbidden.add(path.name)
                break
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.split(".")[0] == "hosted_profiles"
            ):
                forbidden.add(path.name)
                break
    return forbidden


def test_no_application_profile_content_in_sdist(tmp_path):
    result = subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"sdist build failed:\n{result.stdout}\n{result.stderr}"

    (sdist_path,) = tmp_path.glob("*.tar.gz")
    with tarfile.open(sdist_path) as tar:
        names = tar.getnames()

    assert not any("hosted_profiles" in name for name in names), (
        f"hosted_profiles/ must never ship in the sdist: {[n for n in names if 'hosted_profiles' in n]}"
    )

    shipped_test_filenames = {pathlib.Path(n).name for n in names if "/tests/" in n}
    offenders = _hosted_profiles_dependent_test_filenames() & shipped_test_filenames
    assert not offenders, (
        f"repository-oriented tests that import hosted_profiles must be excluded "
        f"from the sdist (see MANIFEST.in): {sorted(offenders)}"
    )

    # The exclusion assertions above don't guard the `include tests/conftest.py`
    # line in MANIFEST.in: removing it silently drops conftest from the sdist
    # (no forbidden filename to trip on) while every other assertion still passes.
    assert any(n.endswith("/tests/conftest.py") for n in names)
