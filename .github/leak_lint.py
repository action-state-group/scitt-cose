#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""leak-lint — fail the build if internal workflow text reaches this public repo.

This repo is donation-intended and public. It must not carry the ids, vocabulary or paths of
the private workspace that produces it: to an outside contributor or downstream adopter, that
reads as the "neutral" repo being steered from somewhere they cannot see.

Two kinds of rule:

  1. **Bracketed internal ids (public rule, always on)** -- `[` + 3-or-more hyphen-separated
     lowercase-alnum segments + `]`, e.g. `[some-internal-task-id]`. Generic, so it lives here.
     The 3-segment floor excludes TOML table headers (`[build-system]`) and the lowercase-only
     class excludes citation tags (`[RFC2119]`). Markdown links, reference links, pip extras
     and HTML attribute selectors are excluded by what surrounds the bracket (see
     `_has_bracket_id_leak`).
  2. **Term classes (from a secret)** -- literal substrings grouped into named classes. The
     list is deliberately NOT stored in this repository: a public gate that enumerated the
     terms would itself publish them. It is supplied at run time in the ``LEAK_LINT_TERMS``
     environment variable (a repository secret in CI), as a JSON object mapping a class name
     to its terms, e.g. ``{"class-a": ["term", ...], "class-b": [...]}``. Matching is
     case-sensitive.

Fail-closed: if ``LEAK_LINT_TERMS`` is unset, empty, malformed or carries no terms, the lint
exits 2 rather than passing on the public rule alone -- a missing list must never read as
"clean".

Output redaction (same model as the sibling ``neutrality_scan.py``): unless
``LEAK_LINT_REVEAL`` is truthy, a run on which any term matched prints one constant verdict --
no path, line, class or count -- because on a fork run the scanned content is the submitter's,
and anything that varies with which term matched would let a stranger read the list back out
of the public log one candidate at a time. Bracketed-id hits carry nothing secret and are
printed in full, but only when no term matched anywhere (otherwise which lines are printed
would itself be the oracle).

Design:
  - **Exact-text allowlist**, `leak_lint_allowlist.txt` next to this script, for genuine
    historical record. Never line numbers -- the exact stripped line text.
  - **Scans generated artifacts too** (`.txt`, `.xml`), not just sources.
  - **Excludes this script, its allowlist, its CI workflow and its tests by filename.**
  - **Scans the COMMITTED tree** (`git ls-files -z`) of ROOT, and never follows a symbolic link
    or reads outside ROOT: on a fork run ROOT is untrusted content.

Usage: python leak_lint.py [ROOT=.]
Exit 0 = clean; 1 = leak(s) found; 2 = misconfiguration (no term list).
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

SELF_NAMES = {
    "leak_lint.py",
    "leak_lint_allowlist.txt",
    "leak-lint.yml",
    "test_leak_lint.py",
}

SCAN_SUFFIXES = (
    ".py", ".go", ".rs", ".ts", ".js", ".mjs",
    ".md", ".rst", ".txt", ".xml",
    ".toml", ".cfg", ".yml", ".yaml", ".json",
    ".html", ".sh",
)

# Lowercase-alnum segments only (excludes uppercase citation tags structurally), each segment
# 2+ chars (excludes a hex regex character class like `[0-9a-f]`, which the hyphen-as-range
# operator would otherwise fake as hyphen-separated segments), 3+ segments (excludes 2-segment
# TOML headers like [build-system]).
BRACKET_ID = re.compile(r"\[[a-z0-9]{2,}(?:-[a-z0-9]{2,}){2,}\]")

BRACKET_CLASS = "bracketed-id"

UNTRUSTED_VERDICT = (
    "leak-lint: content check failed. Details are withheld on fork runs; a maintainer can "
    "re-run this check on a trusted event."
)


def load_terms() -> dict[str, tuple[str, ...]]:
    """The term classes from ``LEAK_LINT_TERMS``; exits 2 when there are none."""
    raw = os.environ.get("LEAK_LINT_TERMS", "").strip()
    if not raw:
        print(
            "error: LEAK_LINT_TERMS is empty or unset. leak-lint is fail-closed -- configure "
            "the repository secret. (On fork PRs a pull_request run gets no secrets; this "
            "check runs under pull_request_target for that reason.)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        cfg = json.loads(raw)
        if isinstance(cfg, str):
            # Some secret-setting paths double-encode the JSON.
            cfg = json.loads(cfg)
    except json.JSONDecodeError as exc:
        print(f"error: LEAK_LINT_TERMS is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if not isinstance(cfg, dict):
        print("error: LEAK_LINT_TERMS must decode to a JSON object.", file=sys.stderr)
        raise SystemExit(2)
    classes: dict[str, tuple[str, ...]] = {}
    for name, terms in cfg.items():
        if not isinstance(terms, list) or not all(isinstance(t, str) and t for t in terms):
            print(
                "error: each LEAK_LINT_TERMS class must be a list of non-empty strings.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        if terms:
            classes[str(name)] = tuple(terms)
    if not classes:
        print("error: LEAK_LINT_TERMS carries no terms.", file=sys.stderr)
        raise SystemExit(2)
    return classes


def reveal_matches() -> bool:
    """Whether matched lines may be printed. Redaction is the default; the workflow grants the
    opt-in only on trusted runs (not a fork's pull_request_target). This variable is the whole
    security boundary for the term list, not a convenience toggle."""
    return os.environ.get("LEAK_LINT_REVEAL", "").strip().lower() in ("1", "true", "yes", "on")


def _tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True)
    return [root / os.fsdecode(p) for p in out.stdout.split(b"\0") if p]


def _read_regular_file(root: Path, path: Path) -> str | None:
    """The text of *path* when it is safe to read, else ``None``: no component from *root* down
    is a symbolic link, it resolves inside *root*, and it is a regular file (checked again after
    opening without following a final link)."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        if not path.resolve().is_relative_to(root.resolve()):
            return None
        if not stat.S_ISREG(path.lstat().st_mode):
            return None
        fd = os.open(
            path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


#: A comment line in the allowlist file is `#` followed by whitespace or end-of-line -- NOT
#: just `#` as the first character, so an allowlisted Markdown heading (a CHANGELOG entry,
#: `### Fixed — ...`) is not silently dropped as a comment.
_COMMENT_LINE = re.compile(r"^#(\s|$)")


def _load_allowlist(root: Path) -> set[str]:
    text = _read_regular_file(root, root / ".github" / "leak_lint_allowlist.txt")
    if text is None:
        return set()
    return {
        line.rstrip("\n")
        for line in text.splitlines()
        if line.strip() and not _COMMENT_LINE.match(line.lstrip())
    }


def _has_bracket_id_leak(line: str) -> bool:
    """True if `line` contains a bracketed id that is NOT a markdown link/reference/citation.

    Checked per match, because the exempt shapes need different context:
      - a pip extra, e.g. `capsule-emit[msft-agent-framework]`: exempt when the match is
        immediately preceded by an identifier character (letter/digit/`_`/`-`). A real id in
        prose is set off by whitespace, a paren, a backtick or the start of the line.
      - inline link `[text](url)` or the first half of `[text][ref]`: exempt when the match is
        immediately followed by `(` or `[`.
      - reference-link DEFINITION `[ref]: url`: exempt only when the bracket is the first thing
        on the line and is followed by `:`. An id followed by `:` mid-sentence (a docstring
        opening with the id it documents) is still flagged.
      - uppercase citation tags (`[RFC2119]`, `[I-D.foo]`): excluded by BRACKET_ID's
        lowercase-only character class.
      - HTML attribute selectors (`[data-report-date]`, `[aria-describedby-id]`): exempt when
        the content starts with `data-` or `aria-`, prefixes HTML reserves for attributes.
    """
    for m in BRACKET_ID.finditer(line):
        if m.group(0)[1:].startswith(("data-", "aria-")):
            continue
        before = line[m.start() - 1 : m.start()]
        if before and (before.isalnum() or before in "_-"):
            continue
        after = line[m.end() : m.end() + 1]
        if after and after in "([":
            continue
        if after == ":" and line[: m.start()].strip() == "":
            continue
        return True
    return False


def classify(line: str, terms: dict[str, tuple[str, ...]]) -> tuple[bool, list[str]]:
    """(bracketed-id hit?, the term classes that match) for one line."""
    return _has_bracket_id_leak(line), [
        name for name, words in terms.items() if any(w in line for w in words)
    ]


def scan(root: Path, terms: dict[str, tuple[str, ...]]) -> tuple[list[str], list[str]]:
    """(bracket-only hits, hits on lines where a term matched), each `path:line:classes: text`."""
    allow = _load_allowlist(root)
    bracket_only: list[str] = []
    term_hits: list[str] = []
    for f in _tracked_files(root):
        if f.name in SELF_NAMES or f.suffix not in SCAN_SUFFIXES:
            continue
        text = _read_regular_file(root, f)
        if text is None:
            # Not a readable regular file inside ROOT (deleted-but-staged, a link, a
            # directory): not a leak either way.
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped in allow:
                continue
            bracket, classes = classify(line, terms)
            if not bracket and not classes:
                continue
            labels = ([BRACKET_CLASS] if bracket else []) + classes
            entry = f"{f.relative_to(root)}:{i}:{','.join(labels)}: {stripped}"
            (term_hits if classes else bracket_only).append(entry)
    return bracket_only, term_hits


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root = Path(argv[0] if argv else ".")
    terms = load_terms()
    bracket_only, term_hits = scan(root, terms)
    if term_hits and not reveal_matches():
        print(UNTRUSTED_VERDICT)
        return 1
    hits = term_hits + bracket_only
    if hits:
        print(f"leak-lint: {len(hits)} internal-leak hit(s) found in the committed tree.")
        print(
            "If a hit is a genuine historical record (not live drift), add its exact stripped "
            "line text to .github/leak_lint_allowlist.txt. Otherwise, fix it -- an allowlist "
            "seeded with a real leak teaches the next person the lint is advisory."
        )
        for h in hits:
            print(" ", h)
        return 1
    print("leak-lint: clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
