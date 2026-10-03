#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutant tests for leak_lint.py: every rule demonstrated failing (mutant present, lint exits 1)
then passing (mutant removed or allowlisted, lint exits 0). Runs against an isolated, throwaway
`git init` tree, never this host repo's own content, so the test is identical whichever repo it
is vendored into.

The term list is a secret in CI, so these tests supply their own SYNTHETIC classes and terms
through LEAK_LINT_TERMS; none of them is a real entry.
"""
from __future__ import annotations

import json
import os
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


#: Synthetic term classes. Real class names and terms live only in the CI secret.
TERMS = {
    "class-alpha": ["SYNTHETIC_QUEUE_WORD", "synthetic-buffer"],
    "class-beta": ["/synthetic/private/path", "synthetic_dir/"],
    "class-gamma": ["Someone decides alone"],
}


def _run(repo: Path, *, terms=TERMS, reveal: bool = True) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("LEAK_LINT_")}
    if terms is not None:
        env["LEAK_LINT_TERMS"] = terms if isinstance(terms, str) else json.dumps(terms)
    if reveal:
        env["LEAK_LINT_REVEAL"] = "1"
    return subprocess.run(
        [sys.executable, str(LINT), str(repo)], capture_output=True, text=True, env=env
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


def test_bracketed_id_does_not_fire_on_html_attribute_selectors(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "report.test.ts",
        "\n".join(
            [
                "const d = root.querySelector('[data-report-date]');",
                "const rows = root.querySelectorAll('[data-case-id-row]');",
                'const tip = el.closest("[aria-describedby-id]");',
                "",
            ]
        ),
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


def test_attribute_selector_exemption_does_not_hide_a_real_task_id(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "notes.ts", "// fixed per [mesh-report-date-fix]\nconst d = q('[data-report-date]');\n")
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1, result.stdout
    assert "mesh-report-date-fix" in result.stdout


# ---- term classes (from LEAK_LINT_TERMS) -----------------------------------------------------

@pytest.mark.parametrize(
    "cls,leak,fixed",
    [
        ("class-alpha", "Ask in the synthetic-buffer if you need help.", "Ask in the support channel."),
        ("class-beta", "See the plan under synthetic_dir/plan.md.", "See the linked plan."),
        ("class-gamma", "In a dispute, Someone decides alone.", "In a dispute, maintainers vote."),
    ],
)
def test_term_class_mutant_fails_then_passes(tmp_path, cls, leak, fixed):
    repo = _init_repo(tmp_path)
    doc = _write(repo, "README.md", leak + "\n")
    _commit_all(repo)
    red = _run(repo)
    assert red.returncode == 1
    assert cls in red.stdout

    doc.write_text(fixed + "\n")
    _commit_all(repo)
    green = _run(repo)
    assert green.returncode == 0, green.stdout


def test_term_match_is_case_sensitive(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "README.md", "synthetic_queue_word in another casing is not the term.\n")
    _commit_all(repo)
    assert _run(repo).returncode == 0


# ---- fail-closed config ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "terms",
    [None, "", "   ", "not json", "[]", json.dumps({}), json.dumps({"class-alpha": []}),
     json.dumps({"class-alpha": "a-string"}), json.dumps({"class-alpha": [""]})],
)
def test_missing_or_empty_term_list_fails_closed(tmp_path, terms):
    repo = _init_repo(tmp_path)
    _write(repo, "README.md", "clean\n")
    _commit_all(repo)
    result = _run(repo, terms=terms)
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "leak-lint: clean" not in result.stdout


def test_double_encoded_term_list_is_accepted(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "README.md", "a synthetic-buffer here\n")
    _commit_all(repo)
    result = _run(repo, terms=json.dumps(json.dumps(TERMS)))
    assert result.returncode == 1
    assert "class-alpha" in result.stdout


# ---- redaction on untrusted runs -------------------------------------------------------------

def test_untrusted_run_with_a_term_hit_prints_only_a_constant_verdict(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "a.md", "one synthetic-buffer\n[some-fake-internal-id] too\n")
    _write(repo, "b.md", "/synthetic/private/path\n")
    _commit_all(repo)
    first = _run(repo, reveal=False)
    assert first.returncode == 1
    for secret in ("synthetic-buffer", "/synthetic/private/path", "class-", "a.md", "b.md",
                   "some-fake-internal-id"):
        assert secret not in first.stdout, first.stdout

    # Nothing in the output varies with which or how many terms matched.
    _write(repo, "b.md", "clean now\n")
    _commit_all(repo)
    second = _run(repo, reveal=False)
    assert second.returncode == 1
    assert second.stdout == first.stdout


def test_untrusted_run_prints_bracket_ids_when_no_term_matched(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "a.md", "See [some-fake-internal-id] here.\n")
    _commit_all(repo)
    result = _run(repo, reveal=False)
    assert result.returncode == 1
    assert "some-fake-internal-id" in result.stdout


def test_symlink_is_never_followed(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("synthetic-buffer and [some-fake-internal-id]\n")
    repo = _init_repo(tmp_path)
    (repo / "link.md").symlink_to(outside)
    _write(repo, "README.md", "clean\n")
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


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
        "# runs leak_lint.py -- names synthetic-buffer and synthetic_dir/ in its own comment\n",
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
