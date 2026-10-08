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

import base64
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


#: A synthetic term that fits inside a URL path, and its class.
LOCK_TERM = "synthetic_dir/"
LOCK_CLASS = "class-beta"
#: A synthetic term made only of base64 characters, so it can sit inside an SRI-shaped value.
DIGEST_TERM = "SyntheticDigestTerm"
DIGEST_CLASS = "class-gamma"


def _run_digest(repo: Path) -> subprocess.CompletedProcess:
    return _run(repo, terms={**TERMS, DIGEST_CLASS: [DIGEST_TERM]})

# ---- lockfile URL and hash values ------------------------------------------------------------
# A lockfile's dependency URL can contain any substring, so the value of a URL or hash field is
# exempt from term matching, but only when it is a public registry URL or a hash. Any other
# host, a file:/git+ssh:/link:/workspace: value, or a hash field holding anything but a hash,
# is matched as usual, and so is everything else in the file.

#: A URL on a public registry host, and the same path on a host that is not one.
LOCK_URL = "https://registry.npmjs.org/" + LOCK_TERM + "pkg/-/pkg-1.0.0.tgz"
PRIVATE_URL = "https://npm.internal.example.invalid/" + LOCK_TERM + "pkg/-/pkg-1.0.0.tgz"
#: Hash values in their real shapes: an SRI integrity value (a 64-byte sha512 digest) and a
#: yarn 2+ checksum.
SRI_HASH = "sha512-" + base64.b64encode(bytes(range(64))).decode()
YARN_CHECKSUM = "10c0/" + "0123abcd" * 8

LOCKFILE_URL_FIELDS = {
    "package-lock.json": (
        '{\n  "packages": {\n    "node_modules/pkg": {\n      "version": "1.0.0",\n'
        f'      "resolved": "{LOCK_URL}",\n'
        f'      "integrity": "{SRI_HASH}"\n'
        "    }\n  }\n}\n"
    ),
    "yarn.lock": (
        'pkg@^1.0.0:\n  version "1.0.0"\n'
        f'  resolved "https://registry.yarnpkg.com/{LOCK_TERM}pkg/-/pkg-1.0.0.tgz#abc"\n'
        f"  integrity {SRI_HASH}\n"
        '\n"other@npm:^2.0.0":\n  version: 2.0.0\n'
        '  resolution: "other@npm:2.0.0"\n'
        f"  checksum: {YARN_CHECKSUM}\n"
    ),
    "pnpm-lock.yaml": (
        "packages:\n  /pkg@1.0.0:\n"
        f"    resolution: {{integrity: {SRI_HASH}, tarball: {LOCK_URL}}}\n"
        "  /other@2.0.0:\n    resolution:\n"
        f"      integrity: {SRI_HASH}\n"
        f"      tarball: {LOCK_URL}\n"
    ),
}

#: Per lockfile, values that are NOT a public registry URL or a hash, each holding the term:
#: a private registry host, a path into a workspace, an ssh git URL, and a hash field holding
#: something that is not a hash.
LOCKFILE_NOT_EXEMPT = {
    "package-lock.json": {
        "private host": f'{{\n  "resolved": "{PRIVATE_URL}"\n}}\n',
        "file path": f'{{\n  "resolved": "file:../{LOCK_TERM}pkg"\n}}\n',
        "not a hash": f'{{\n  "integrity": "sha512-{LOCK_TERM}AAAA=="\n}}\n',
        "http, not https": f'{{\n  "resolved": "http://registry.npmjs.org/{LOCK_TERM}pkg.tgz"\n}}\n',
        "github tarball": f'{{\n  "resolved": "https://codeload.github.com/example/{LOCK_TERM}repo/tar.gz/abc123"\n}}\n',
    },
    "yarn.lock": {
        "private host": f'pkg@^1.0.0:\n  resolved "{PRIVATE_URL}#abc"\n',
        "term in the fragment": f'pkg@^1.0.0:\n  resolved "https://registry.yarnpkg.com/pkg/-/pkg-1.0.0.tgz#{LOCK_TERM}x"\n',
        "git+ssh": f'pkg@^1.0.0:\n  resolved "git+ssh://git@git.example.invalid/{LOCK_TERM}pkg.git"\n',
        "workspace": f'"pkg@workspace:.":\n  resolution: "pkg@workspace:{LOCK_TERM}pkg"\n',
        "not a checksum": f'"pkg@npm:1.0.0":\n  checksum: {LOCK_TERM}0123abcd\n',
    },
    "pnpm-lock.yaml": {
        "private host": f"packages:\n  /pkg@1.0.0:\n    resolution: {{integrity: {SRI_HASH}, tarball: {PRIVATE_URL}}}\n",
        "link": f"packages:\n  /pkg@1.0.0:\n    resolution:\n      tarball: link:{LOCK_TERM}pkg\n",
        "unanchored key": f"packages:\n  /pkg@1.0.0:\n    description: see the tarball: {LOCK_TERM}pkg\n",
    },
}


@pytest.mark.parametrize(
    "name,case", [(name, case) for name in sorted(LOCKFILE_NOT_EXEMPT) for case in sorted(LOCKFILE_NOT_EXEMPT[name])]
)
def test_a_term_in_a_lockfile_value_that_is_not_a_public_registry_or_a_hash_is_flagged(tmp_path, name, case):
    repo = _init_repo(tmp_path)
    _write(repo, name, LOCKFILE_NOT_EXEMPT[name][case])
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1, f"{name} {case}: {result.stdout}"
    assert LOCK_CLASS in result.stdout

#: SRI-shaped values holding a base64-clean term, with a digest the wrong length for their
#: algorithm: not a digest, so matched as usual.
SRI_WRONG_LENGTH = {
    "package-lock.json": f'{{\n  "integrity": "sha512-{DIGEST_TERM}=="\n}}\n',
    "yarn.lock": f"pkg@^1.0.0:\n  integrity sha256-{DIGEST_TERM}AAAA=\n",
    "pnpm-lock.yaml": f"packages:\n  /pkg@1.0.0:\n    resolution: {{integrity: sha384-{DIGEST_TERM}}}\n",
}


@pytest.mark.parametrize("name", sorted(SRI_WRONG_LENGTH))
def test_an_sri_shaped_value_that_is_not_a_digest_of_its_length_is_flagged(tmp_path, name):
    repo = _init_repo(tmp_path)
    _write(repo, name, SRI_WRONG_LENGTH[name])
    _commit_all(repo)
    result = _run_digest(repo)
    assert result.returncode == 1, result.stdout
    assert DIGEST_CLASS in result.stdout


@pytest.mark.parametrize("algorithm,size", [("sha1", 20), ("sha256", 32), ("sha384", 48), ("sha512", 64)])
def test_an_sri_digest_of_its_algorithms_length_is_exempt(tmp_path, algorithm, size):
    repo = _init_repo(tmp_path)
    digest = base64.b64encode(bytes(range(size))).decode()
    _write(repo, "package-lock.json", f'{{\n  "integrity": "{algorithm}-{digest}"\n}}\n')
    _commit_all(repo)
    assert _run_digest(repo).returncode == 0


LOCKFILE_OTHER_FIELD = {
    "package-lock.json": f'{{\n  "name": "{LOCK_TERM}app",\n  "version": "1.0.0"\n}}\n',
    "yarn.lock": (
        f'pkg@^1.0.0:\n  version "1.0.0"\n  dependencies:\n    {LOCK_TERM}dep "^1.0.0"\n'
    ),
    "pnpm-lock.yaml": f"importers:\n  .:\n    dependencies:\n      {LOCK_TERM}dep: 1.0.0\n",
}


@pytest.mark.parametrize("name", sorted(LOCKFILE_URL_FIELDS))
def test_a_term_inside_a_lockfile_url_or_hash_value_is_clean(tmp_path, name):
    repo = _init_repo(tmp_path)
    _write(repo, f"ts/{name}", LOCKFILE_URL_FIELDS[name])
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("name", sorted(LOCKFILE_OTHER_FIELD))
def test_a_term_in_another_lockfile_field_is_still_flagged(tmp_path, name):
    repo = _init_repo(tmp_path)
    _write(repo, name, LOCKFILE_OTHER_FIELD[name])
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1
    assert LOCK_CLASS in result.stdout


def test_the_same_term_in_prose_is_still_flagged(tmp_path):
    repo = _init_repo(tmp_path)
    _write(repo, "package-lock.json", LOCKFILE_URL_FIELDS["package-lock.json"])
    _write(repo, "README.md", f"Fetch it from {LOCK_URL}.\n")
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1
    assert "README.md" in result.stdout
    assert "package-lock.json" not in result.stdout


@pytest.mark.parametrize("name", ["data.json", "package.json", "config.yaml"])
def test_a_resolved_key_outside_a_lockfile_is_still_flagged(tmp_path, name):
    repo = _init_repo(tmp_path)
    if name.endswith(".json"):
        _write(repo, name, f'{{\n  "resolved": "{LOCK_URL}",\n  "integrity": "{LOCK_TERM}"\n}}\n')
    else:
        _write(repo, name, f"resolution:\n  integrity: {LOCK_TERM}\n  tarball: {LOCK_URL}\n")
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1
    assert LOCK_CLASS in result.stdout


def test_a_lockfile_url_value_is_still_checked_for_bracketed_ids(tmp_path):
    repo = _init_repo(tmp_path)
    _write(
        repo,
        "package-lock.json",
        '{\n  "resolved": "https://registry.npmjs.org/[lockfile-url-task-id]"\n}\n',
    )
    _commit_all(repo)
    result = _run(repo)
    assert result.returncode == 1
    assert "bracketed-id" in result.stdout


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
