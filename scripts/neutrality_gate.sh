#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The shipped tree must contain no downstream/reserved code references. Run by
# ci.yml's neutrality-gate job and scripts/check.sh. Fails on a match and on a
# grep error (exit 2), so an unreadable tree never passes as clean.
# Usage: scripts/neutrality_gate.sh [dir]   (default: the current directory)
set -uo pipefail
dir="${1:-.}"
# BSD grep with --include exits 1 (no match) for a missing path; check it here.
[ -d "$dir" ] || { echo "neutrality gate: $dir is not a directory, tree not checked"; exit 1; }
# The pattern is split so this file doesn't match itself, in the tree or in
# `git grep` over history (see the launch checklist).
grep -rn "goph""er_ai" --include='*.py' --include='*.go' "$dir"
case $? in
  1) exit 0 ;;
  0) echo "reserved/downstream code reference found"; exit 1 ;;
  *) echo "neutrality gate: grep failed, tree not checked"; exit 1 ;;
esac
