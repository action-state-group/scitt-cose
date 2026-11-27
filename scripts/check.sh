#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs locally what CI runs on pull requests and main: every job in
# .github/workflows/ci.yml, hostname-lint.yml, leak-lint.yml and
# neutrality.yml's scanner self-test. Not run: neutrality.yml's scan itself,
# which needs the NEUTRALITY_TERMS repository secret, and dco.yml's sign-off
# check. Needs uv (it provides Python 3.9 and 3.12), Go and the current
# stable Rust with clippy, as CI uses (`rustup update stable` if older).
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# ci.yml test, on Python 3.9 and 3.12.
for py in 3.9 3.12; do
  uv venv -q -p "$py" "$tmp/test-$py"
  VIRTUAL_ENV="$tmp/test-$py" uv pip install -q -e ".[dev,serve]"
  SCITT_REQUIRE_GO=1 SCITT_REQUIRE_RUST=1 "$tmp/test-$py/bin/python" -m pytest -q
  "$tmp/test-$py/bin/python" -m ruff check .
  "$tmp/test-$py/bin/python" -m pytest -q .github/test_release.py .github/test_leak_lint.py
done

# ci.yml third-party-oracle.
uv venv -q -p 3.12 "$tmp/oracle"
VIRTUAL_ENV="$tmp/oracle" uv pip install -q -e ".[dev]" "cbor2<6"
SCITT_REQUIRE_PYCOSE=1 "$tmp/oracle/bin/python" -m pytest tests/test_thirdparty_cose.py -q -rs

# ci.yml go-verifier.
(cd scitt-cose-go-verify && go vet ./... && go build -o "$tmp/gv-build" ./...)

# ci.yml rust-verifier.
(cd rust && cargo build --locked && cargo test --locked && cargo clippy --locked --all-targets -- -D warnings)

# ci.yml fuzz.
uv venv -q -p 3.12 "$tmp/runtime"
VIRTUAL_ENV="$tmp/runtime" uv pip install -q --reinstall-package scitt-cose .
(cd scitt-cose-go-verify && go build -o "$tmp/gv" .)
"$tmp/runtime/bin/python" scripts/differential_fuzz.py \
  --go-binary "$tmp/gv" \
  --iterations 600 --seed 20250612 \
  --write-findings "$tmp/fuzz-findings"

# ci.yml vectors.
(cd test-vectors && shasum -a 256 -c SHA256SUMS)
(cd test-vectors/receipt-v1 && shasum -a 256 -c SHA256SUMS)
(cd "$tmp" && "$tmp/runtime/bin/python" -m scitt_cose.vectors "$root/test-vectors")
(cd scitt-cose-go-verify && go test ./... -run TestVectors -v)
(cd rust && cargo test --locked -p scitt-cose-receipt --test vectors)

# ci.yml neutrality-gate.
scripts/neutrality_gate.sh .

# hostname-lint.yml, leak-lint.yml, neutrality.yml scanner self-test.
"$tmp/runtime/bin/python" .github/hostname_lint.py .
"$tmp/runtime/bin/python" .github/leak_lint.py .
"$tmp/runtime/bin/python" .github/neutrality_scan.py --self-test
