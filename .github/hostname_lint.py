#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""hostname-lint — fail the build if a stale verify.*/witness.*actionstate.* reference appears.

Canonical hosts (2026-09-23, corrected same day by Steven): verify and witness are NEUTRAL and
live on agentactioncapsule.org; countersign is OPERATED and stays on actionstate -- see
_work/countersign-service-deploy-plan-2026-09-17.md, section "Money-path / boundary", in the
action-state-ops workspace. This repo has drifted back to the old verify.actionstate.ai host
twice already (see PR #38); this check exists so a third recurrence fails CI instead of shipping.

Disallowed: verify.actionstate.<tld>, witness.actionstate.<tld> (case-insensitive, any TLD).
Exempt: countersign.actionstate.<tld> (correct -- the operated layer), and any
@actionstate.<tld> mailto address (spec@, steven@, conduct@, security@, opensource@ -- all
correct, unrelated to which host serves which service).

A line matching the DISALLOWED pattern is still exempt if its exact stripped text appears in
hostname_lint_allowlist.txt (same directory as this script) -- used for genuinely historical
records (a completed checklist entry, a before/after transcript) that legitimately name the old
host as part of documenting a fix, not as live drift. The allowlist is exact-text, not
line-number, so it self-invalidates the moment the surrounding prose changes.

Usage: python .github/hostname_lint.py [ROOT=.]
Exit 0 = clean; 1 = stale reference(s) found (prints file:line).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

DISALLOWED = re.compile(r"\b(verify|witness)\.actionstate\.[a-z]+", re.IGNORECASE)
SCAN_SUFFIXES = (
    ".html", ".py", ".go", ".md", ".rst", ".txt", ".xml", ".toml", ".cfg",
    ".yml", ".yaml", ".json",
)


def _tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    )
    return [root / p for p in out.stdout.splitlines() if p]


def _load_allowlist(root: Path) -> set[str]:
    p = root / ".github" / "hostname_lint_allowlist.txt"
    if not p.exists():
        return set()
    return {
        line.rstrip("\n")
        for line in p.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    allow = _load_allowlist(root)
    hits: list[str] = []
    for f in _tracked_files(root):
        if f.suffix not in SCAN_SUFFIXES:
            continue
        # This check's own files legitimately name the disallowed pattern in prose
        # (this docstring, the allowlist's comments, the workflow's explanatory header).
        if f.name in ("hostname_lint.py", "hostname_lint_allowlist.txt", "hostname-lint.yml"):
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            # git ls-files can list a path that no longer exists on disk (deleted-but-
            # staged, a submodule placeholder, a broken symlink) -- not a hostname hit
            # either way, so skip it rather than fail the whole scan on an unrelated repo
            # hygiene issue this lint isn't responsible for catching.
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if DISALLOWED.search(line) and line.strip() not in allow:
                hits.append(f"{f.relative_to(root)}:{i}: {line.strip()}")

    if hits:
        print(
            "hostname-lint: stale verify.actionstate.*/witness.actionstate.* reference(s) found."
        )
        print("Canonical: verify.agentactioncapsule.org / witness.agentactioncapsule.org.")
        print("(countersign.actionstate.* is correct and exempt -- it is the operated layer.)")
        print(
            "If a hit is a genuine historical record (not live drift), add its exact stripped "
            "line text to .github/hostname_lint_allowlist.txt."
        )
        for h in hits:
            print(" ", h)
        return 1

    print("hostname-lint: clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
