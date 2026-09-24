#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""leak-lint — fail the build if internal coordination-layer text reaches a public repo.

This repo is donation-intended and public. It must never carry the vocabulary, ids, or paths
of the private coordination workspace that produces it — a stray bracketed task id, a queue
script name, an internal path, or a sentence naming one person as decision-maker in governance
prose reads, to an outside contributor or downstream adopter, as evidence the "neutral" repo has
an owner steering it from behind the curtain. Four independent rule classes, each catching a
distinct leak shape seen in review:

  1. bracketed internal ids   -- `[` + 3-or-more hyphen-separated lowercase-alnum segments + `]`,
                                  e.g. `[public-repo-internal-leak-lint]`. The 3-segment floor
                                  excludes TOML table headers (`[build-system]`, 2 segments) and
                                  pip extras (`capsule-emit[langchain]`, 1 segment, no brackets
                                  around the whole token). Never fires on markdown inline links
                                  (`[text](url)`), reference links (`[text][ref]` / `[ref]: url`),
                                  or uppercase citation tags (`[RFC2119]`, `[I-D.foo]`) -- those
                                  are excluded structurally: citation tags fail the lowercase-only
                                  character class, and link/reference forms are excluded by what
                                  immediately follows the closing bracket.
  2. ops/lane vocabulary      -- coordination-script and buffer names that only make sense next
                                  to a private queue.
  3. internal paths           -- workspace-relative paths that do not exist outside the private
                                  checkout.
  4. named-decider prose      -- governance text naming one person as the decision authority,
                                  which undercuts the neutrality optic a donatable repo exists to
                                  hold.

Design (same shape as the sibling `hostname_lint.py`):
  - **Exact-text allowlist**, `leak_lint_allowlist.txt` next to this script. Never line numbers
    (they rot the moment a file is edited above the hit) -- the exact stripped line text.
  - **Scans generated artifacts too** (`.txt`, `.xml` I-D outputs), not just `.md` sources -- a
    fix applied to source without a rebuild leaves the leak live in the rendered artifact.
  - **Excludes this script, its allowlist, its own CI workflow, and its own test fixtures by
    filename** -- they legitimately name the patterns they ban, in prose that describes the ban
    or in fixture data that exercises the ban.
  - **Scans the COMMITTED tree** (`git ls-files`), not the working tree -- an untracked file
    reads clean for the wrong reason.

Usage: python leak_lint.py [ROOT=.]
Exit 0 = clean; 1 = leak(s) found (prints file:line:class).
"""
from __future__ import annotations

import re
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

# Rule 1 -- bracketed internal ids. Lowercase-alnum segments only (excludes uppercase citation
# tags structurally), each segment 2+ chars (excludes a hex regex character class like
# `[0-9a-f]`, which the hyphen-as-range-operator would otherwise fake as 2 hyphen-separated
# segments -- a real task id is always built from meaningful words, never single hex digits),
# 3+ segments (excludes 2-segment TOML headers like [build-system]), and never immediately
# followed by `(`, `:`, or `[` -- which is what an inline link, a reference definition, or the
# first half of a `[text][ref]` pair look like.
BRACKET_ID = re.compile(r"\[[a-z0-9]{2,}(?:-[a-z0-9]{2,}){2,}\](?![(:\[])")

# Rule 2 -- ops/lane vocabulary. Literal substrings, matched case-sensitively as written in the
# spec (avoids false positives like an unrelated product's own "inbox" or "outbox" feature named
# in different casing/context).
OPS_VOCAB = (
    "QUEUE_PROTOCOL",
    "claim.sh",
    "close.sh",
    "decide.sh",
    "outbox",
    "inbox",
    "lane:",
    "worktree",
    "held for EM push",
    "coder-",
    "Needs decision",
    "Do line",
    "R4:",
)

# Rule 3 -- internal paths.
INTERNAL_PATHS = (
    "/dev/asg",
    "_work/",
    "_ops/",
    "action-state-ops",
)

# Rule 4 -- named-decider governance prose.
NAMED_DECIDER = (
    "Steven rules",
    "Steven ratifies",
    "Steven decides",
)


def _tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    )
    return [root / p for p in out.stdout.splitlines() if p]


def _load_allowlist(root: Path) -> set[str]:
    p = root / ".github" / "leak_lint_allowlist.txt"
    if not p.exists():
        return set()
    return {
        line.rstrip("\n")
        for line in p.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def _classify(line: str) -> list[str]:
    hits = []
    if BRACKET_ID.search(line):
        hits.append("bracketed-id")
    if any(term in line for term in OPS_VOCAB):
        hits.append("ops-vocab")
    if any(term in line for term in INTERNAL_PATHS):
        hits.append("internal-path")
    if any(term in line for term in NAMED_DECIDER):
        hits.append("named-decider")
    return hits


def scan(root: Path) -> list[str]:
    allow = _load_allowlist(root)
    hits: list[str] = []
    for f in _tracked_files(root):
        if f.name in SELF_NAMES:
            continue
        if f.suffix not in SCAN_SUFFIXES:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            # git ls-files can list a path that no longer exists on disk (deleted-but-staged,
            # a broken symlink) -- not a leak either way, so skip rather than fail the whole
            # scan on an unrelated repo-hygiene issue this lint isn't responsible for catching.
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped in allow:
                continue
            classes = _classify(line)
            if classes:
                hits.append(f"{f.relative_to(root)}:{i}:{','.join(classes)}: {stripped}")
    return hits


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    hits = scan(root)
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
