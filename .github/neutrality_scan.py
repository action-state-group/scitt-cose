#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Neutrality gate — fail the build if reserved vocabulary appears in this repo.

This repository is a neutral public surface (the vendor-neutral RFC9162_SHA256
SCITT receipt verifier). A small set of concepts is reserved and must not appear
here. The reserved list is deliberately NOT stored in this
repository — a public gate that enumerated the terms would itself disclose them.
Instead the list is supplied at run time via the ``NEUTRALITY_TERMS`` repository
secret, and this script is pure matching logic parameterized by that secret.

Fail-closed: if the secret is absent/empty the gate errors (exit 2) rather than
passing silently — a missing list must never read as "clean".

Secret schema (JSON):
    {"substring": [...], "word": [...], "allow_phrases": [...]}
  - substring   : matched case-insensitively anywhere
  - word        : matched case-insensitively at word boundaries (low-collision
                  short names that must not false-positive inside other words)
  - allow_phrases: already-public sentences that legitimately carry a token; a
                  match is exempt ONLY when it falls inside the span of such a
                  phrase on the same line — not every occurrence of the token on
                  the line (two-occurrence fix: track spans, not just presence).

Usage: python .github/neutrality_scan.py [ROOT=.]
       python .github/neutrality_scan.py --self-test
Exit 0 = clean; 1 = reserved vocabulary found (prints file:line); 2 = misconfig.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCAN_SUFFIXES = (
    ".html", ".py", ".go", ".md", ".rst", ".txt", ".xml", ".toml", ".cfg",
    ".yml", ".yaml", ".json",
)


def _load_config() -> tuple[re.Pattern[str], tuple[str, ...]]:
    raw = os.environ.get("NEUTRALITY_TERMS", "").strip()
    if not raw:
        print(
            "error: NEUTRALITY_TERMS secret is empty or unset. The neutrality "
            "gate is fail-closed — configure the repository secret. (On fork PRs "
            "secrets are withheld by design; run this gate on same-repo PRs.)",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: NEUTRALITY_TERMS is not valid JSON: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    substring = tuple(cfg.get("substring", ()))
    word = tuple(cfg.get("word", ()))
    allow = tuple(p.lower() for p in cfg.get("allow_phrases", ()))
    if not substring and not word:
        print("error: NEUTRALITY_TERMS carries no terms.", file=sys.stderr)
        raise SystemExit(2)
    parts = [re.escape(t) for t in substring]
    parts += [r"\b" + re.escape(t) + r"\b" for t in word]
    return re.compile("|".join(parts), re.IGNORECASE), allow


def _line_offenders(line: str, pattern: re.Pattern[str], allow: tuple[str, ...]) -> list[str]:
    """Return reserved-vocabulary hits in *line* that are NOT inside an allow-phrase span.

    Each allow-phrase match creates a character span [start, end) over the
    lowercased line.  A vocabulary hit is exempt only when its entire span falls
    inside one of those allow-phrase spans.  Two occurrences of the same term on
    one line are therefore handled correctly: one inside a phrase → exempt, one
    outside → flagged.
    """
    line_lower = line.lower()

    # Collect all allow-phrase spans (case-insensitive, over lowercased line).
    allow_spans: list[tuple[int, int]] = []
    for phrase in allow:
        start = 0
        while True:
            pos = line_lower.find(phrase, start)
            if pos < 0:
                break
            allow_spans.append((pos, pos + len(phrase)))
            start = pos + 1  # allow overlapping phrase matches

    hits: list[str] = []
    for m in pattern.finditer(line):
        ms, me = m.start(), m.end()
        # Exempt only if this hit's span is fully contained within an allow span.
        if any(s <= ms and me <= e for s, e in allow_spans):
            continue
        hits.append(m.group(0))
    return hits


def _git_tracked_files(root: Path) -> list[Path] | None:
    r = subprocess.run(
        ["git", "ls-files"],
        cwd=root, capture_output=True, text=True
    )
    if r.returncode != 0:
        return None
    return [root / f for f in r.stdout.splitlines() if f]


def scan(root: Path, pattern: re.Pattern[str], allow: tuple[str, ...]) -> list[str]:
    tracked = _git_tracked_files(root)
    candidates: list[Path] = tracked if tracked is not None else sorted(root.rglob("*"))
    offenders: list[str] = []
    for path in candidates:
        path = Path(path)
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if ".git/" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for token in _line_offenders(line, pattern, allow):
                offenders.append(f"{path.relative_to(root)}:{i}: {token!r}")
    return offenders


def _run_self_tests() -> None:
    """Anton two-occurrence test: span-based allow-phrase exemption.

    One occurrence of the term inside the allow-phrase span → exempt.
    One occurrence outside → flagged.  Both on the same line.
    """
    errors: list[str] = []
    pattern = re.compile(r"reserved", re.IGNORECASE)
    allow: tuple[str, ...] = ("use of reserved keyword",)

    # Occurrence entirely outside any allow-phrase → must be flagged.
    line1 = "reserved word found here"
    hits1 = _line_offenders(line1, pattern, allow)
    if hits1 != ["reserved"]:
        errors.append(
            f"two-occurrence test 1 failed: expected ['reserved'], got {hits1!r}"
        )

    # Occurrence inside the allow-phrase → must be exempt.
    line2 = "see use of reserved keyword in docs"
    hits2 = _line_offenders(line2, pattern, allow)
    if hits2 != []:
        errors.append(
            f"two-occurrence test 2 failed: expected [], got {hits2!r}"
        )

    # Two occurrences on the same line: one inside the phrase (exempt), one outside (flagged).
    line3 = "reserved is bad but use of reserved keyword is documented"
    hits3 = _line_offenders(line3, pattern, allow)
    if len(hits3) != 1 or hits3[0].lower() != "reserved":
        errors.append(
            f"two-occurrence test 3 failed: expected exactly one 'reserved', got {hits3!r}"
        )

    if errors:
        print("NEUTRALITY SELF-TEST FAILURES:")
        for e in errors:
            print(f"  {e}")
        raise SystemExit(1)

    print("neutrality self-test: OK (span-based allow-phrase exemption)")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if argv and argv[0] == "--self-test":
        _run_self_tests()
        return 0

    root = Path(argv[0]) if argv else Path(".")
    pattern, allow = _load_config()
    offenders = scan(root, pattern, allow)
    if offenders:
        print(f"NEUTRALITY VIOLATION: reserved vocabulary present ({len(offenders)} hit(s)):")
        for o in offenders:
            print(f"  {o}")
        print("\nThis public repo must carry none of the reserved vocabulary. "
              "Remove the flagged content.")
        return 1
    print("OK: no reserved vocabulary found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
