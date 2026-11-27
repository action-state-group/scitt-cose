#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fails unless every commit in BASE..HEAD carries a DCO sign-off trailer.
# Run by dco.yml. A failed commit listing fails the check instead of passing as
# "no commits to check".
# Usage: scripts/dco_check.sh BASE_SHA HEAD_SHA
set -euo pipefail
base="$1" head="$2"
commits="$(git rev-list "$base..$head")"
trailer="^Signed-off""-by: .+ <.+@.+>"
missing=()
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  msg="$(git log --format=%B -n 1 "$sha")"
  if ! grep -qiE "$trailer" <<<"$msg"; then
    missing+=("$(git log --format='%h %s' -n 1 "$sha")")
  fi
done <<<"$commits"
if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: Missing DCO sign-off on the following commits:"
  printf '  %s\n' "${missing[@]}"
  echo
  echo "Fix: git commit --amend -s  (for last commit)"
  echo "     git rebase --signoff HEAD~N  (for N commits)"
  exit 1
fi
echo "All commits signed off. ✓"
