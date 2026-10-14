# CLAUDE.md

Guidance for coding agents working in this repository. Scope rules and the
review gates are in [CONTRIBUTING.md](CONTRIBUTING.md); read them before
changing library code.

## Commands

```bash
pip install -e ".[dev,serve]"
python3 -m pytest -q                       # unit + conformance suite
SCITT_REQUIRE_GO=1 python3 -m pytest -q    # also force the Go cross-check
python3 -m ruff check .
python3 -m pytest -q .github/test_release.py   # release helper
(cd rust && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked)
```

CI runs the suite on Python 3.9 and 3.12 with the Go and Rust cross-language
checks required, plus the pycose oracle, fuzzing and the vector checksums.
Code must stay Python 3.9 compatible.

## Layout

- `scitt_cose/` is the published package. Its only runtime dependencies are
  `cbor2` and `cryptography`; a test enforces this.
- `scitt-cose-go-verify/` and `rust/scitt-cose/` are independent
  cross-verifiers. `rust/Cargo.toml` is the Cargo workspace root (one
  `Cargo.lock`); each crate lives in `rust/<crate>/`. `hosted_profiles/`,
  `viewer/`, `demo/` and `interop/` are not part of the package.
- `test-vectors/` is pinned by `test-vectors/SHA256SUMS`; CI fails on any byte
  change without a matching checksum update.

## Rules

- Keep the library profile-agnostic: statement payloads stay opaque bytes, and
  no transparency-service (write) code.
- Never cite an unassigned RFC number; a test scans source and docs for it.
- Commits use conventional commit messages and a DCO sign-off
  (`git commit -s`). Do not add AI attribution trailers.

## Releases

Follow [RELEASING.md](RELEASING.md). In short: the package releases under
`v<version>` tags, created by the Release · Tag workflow when a version bump
merges, never by hand. Do not rename `.github/workflows/release.yml`: the PyPI
trusted publisher names it, so publishing breaks until PyPI is updated first.
`.github/release.py` is an identical copy shared with the other
action-state-group repositories; change it in all of them together.
