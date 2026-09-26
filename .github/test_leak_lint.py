#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutant tests for leak_lint.py -- R4: every rule class demonstrated failing (mutant present,
lint exits 1) then passing (mutant removed / allowlisted, lint exits 0). Runs against an
isolated, throwaway `git init` tree, never this host repo's own content -- so a hit on a fixture
line can never be confused with a hit on this repo's real files, and the test is identical
whichever repo it is vendored into.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

LINT = Path(__file__).with_name("leak_lint.py")


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
    return repo


def _commit_all(repo: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "test"], cwd=repo, check=True)


def _run(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(LINT), str(repo)], capture_output=True, text=True
    )


def _write(repo: Path, rel: str, content: str) -> Path:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ---- rule 1: bracketed internal ids ----------------------------------------------------------

def test_bracketed_id_mutant_fails_then_passes(tmp_path):
    repo = _init_repo(tmp_path)
    doc = _write(repo, "NOTES.md", "See [totally-fake-internal-task-id] for context.\n")
    _commit_all(repo)
    red = _run(repo)
    assert red.returncode == 1
    assert "bracketed-id" in red.stdout

    doc.write_text("See the linked task for context.\n")
    _commit_all(repo)
    green = _run(repo)
    assert green.returncode == 0


def test_bracketed_id_does_not_fire_on_markdown_links(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "NOTES.md",
        "\n".join(
            [
                "[agent-action-capsule](https://example.invalid/agent-action-capsule)",
                "[agent-action-capsule][ref]",
                "[ref]: https://example.invalid/agent-action-capsule",
                "[RFC2119] and [I-D.foo] are citation tags.",
                "",
            ]
        ),
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_bracketed_id_reference_definition_exempt_only_at_line_start(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "NOTES.md",
        "\n".join(
            [
                # A genuine markdown reference-link DEFINITION: the id-shaped bracket is the
                # first thing on the line, followed by `:` then a URL -- exempt.
                "[some-fake-reference-id]: https://example.invalid/target",
                # The SAME shape (bracket immediately followed by `:`) but NOT at the start of
                # the line -- prose, not a reference definition, must still be flagged. This
                # is the case a blanket "never follows `:`" rule used to miss.
                '"""[some-fake-internal-id]: does X, then Y."""',
                "",
            ]
        ),
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1, result.stdout
    assert "some-fake-internal-id" in result.stdout
    assert "some-fake-reference-id" not in result.stdout


def test_bracketed_id_threshold_excludes_two_segment_and_pip_extra(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "pyproject.toml",
        "\n".join(
            [
                "[build-system]",
                'requires = ["capsule-emit[langchain]"]',
                "",
            ]
        ),
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_bracketed_id_does_not_fire_on_hyphenated_pip_extra(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "tests/test_optional.py",
        "\n".join(
            [
                'af = pytest.importorskip("agent_framework", '
                'reason="needs capsule-emit[msft-agent-framework]")',
                "",
            ]
        ),
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_bracketed_id_does_not_fire_on_hex_regex_character_class(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "hash.py",
        "\n".join(
            [
                'HEX64 = re.compile(r"^[0-9a-f]{64}$")',
                'def is_hex(s): return bool(re.match(r"[0-9a-f-A-F]+", s))',
                "",
            ]
        ),
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


# ---- rule 2: ops/lane vocabulary -------------------------------------------------------------

def test_ops_vocab_mutant_fails_then_passes(tmp_path):
    repo = _init_repo(tmp_path)
    doc = _write(repo, "README.md", "Ask in the lane's outbox if you need help.\n")
    _commit_all(repo)
    red = _run(repo)
    assert red.returncode == 1
    assert "ops-vocab" in red.stdout

    doc.write_text("Ask in the support channel if you need help.\n")
    _commit_all(repo)
    green = _run(repo)
    assert green.returncode == 0


# ---- rule 3: internal paths ------------------------------------------------------------------

def test_internal_path_mutant_fails_then_passes(tmp_path):
    repo = _init_repo(tmp_path)
    doc = _write(repo, "DEPLOY.md", "See the plan under _work/deploy-plan.md for details.\n")
    _commit_all(repo)
    red = _run(repo)
    assert red.returncode == 1
    assert "internal-path" in red.stdout

    doc.write_text("See the linked deploy plan for details.\n")
    _commit_all(repo)
    green = _run(repo)
    assert green.returncode == 0


# ---- rule 4: named-decider governance prose --------------------------------------------------

def test_named_decider_mutant_fails_then_passes(tmp_path):
    repo = _init_repo(tmp_path)
    doc = _write(repo, "GOVERNANCE.md", "In a dispute, Steven rules on the outcome.\n")
    _commit_all(repo)
    red = _run(repo)
    assert red.returncode == 1
    assert "named-decider" in red.stdout

    doc.write_text("In a dispute, the maintainers vote on the outcome.\n")
    _commit_all(repo)
    green = _run(repo)
    assert green.returncode == 0


# ---- allowlist + self-exclusion + committed-tree behavior ------------------------------------

def test_allowlist_exact_text_suppresses_a_hit(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "HISTORY.md", "Historical record: [an-old-fixed-task-id] was closed.\n")
    _write(
        repo,
        ".github/leak_lint_allowlist.txt",
        "Historical record: [an-old-fixed-task-id] was closed.\n",
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_allowlist_accepts_a_markdown_heading_line(tmp_path):
    # A CHANGELOG.md entry is itself a Markdown heading ("### Fixed — ..."). The allowlist
    # loader's comment-detection must not treat that leading "#"/"##"/"###" as a `# comment`
    # and silently drop the entry from the loaded set -- that would make it impossible to ever
    # allowlist the exact kind of historical-record line this file exists to hold.
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "CHANGELOG.md",
        "### Fixed — old bug closed out ([an-old-fixed-task-id])\n",
    )
    _write(
        repo,
        ".github/leak_lint_allowlist.txt",
        "### Fixed — old bug closed out ([an-old-fixed-task-id])\n",
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_lint_excludes_its_own_files_by_name(tmp_path):
    repo = _init_repo(tmp_path)
    # A copy of this very script's docstring, which legitimately names the patterns it bans,
    # must not trip itself.
    _write(repo, ".github/leak_lint.py", LINT.read_text())
    _write(
        repo,
        ".github/leak_lint_allowlist.txt",
        "# exact-text allowlist; add hits here only when they are genuine history, not drift\n",
    )
    _write(
        repo,
        ".github/workflows/leak-lint.yml",
        "# runs leak_lint.py -- names claim.sh/close.sh/outbox/inbox/_work/ in its own comment\n",
    )
    _write(repo, ".github/test_leak_lint.py", Path(__file__).read_text())
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_scans_committed_tree_not_working_tree(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "README.md", "clean\n")
    _commit_all(repo)
    # Untracked file present on disk but never `git add`ed -- must not be scanned (or,
    # equivalently, must not cause a false-clean result to be trusted): the detector's
    # contract is the COMMITTED tree, so an untracked leak is out of its scope, not a miss.
    _write(repo, "UNTRACKED.md", "See [some-untracked-internal-task-id] here.\n")
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_generated_artifact_suffixes_are_scanned(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "draft-out.txt", "See [rendered-artifact-leak-id] in the rendered output.\n")
    _write(repo, "draft-out.xml", "<t>See [rendered-artifact-leak-id-two] here.</t>\n")
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1
    assert "draft-out.txt" in result.stdout
    assert "draft-out.xml" in result.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
