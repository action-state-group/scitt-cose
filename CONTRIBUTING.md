<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to scitt-cose

Thanks for your interest. This project is small on purpose: a generic,
profile-agnostic SCITT + COSE Receipts verification library. Contributions that
keep it small, neutral, and verifiable are very welcome.

## Ground rules (scope — these are review gates, not preferences)

1. **Neutral by design.** No application profile, no vendor coupling. The
   statement payload stays **opaque bytes**. PRs that add awareness of any
   specific profile's payload semantics will be declined — build that in a
   downstream package instead.
2. **No Transparency Service code.** This library verifies; it never registers,
   issues receipts, anchors, or stores. The hosted wrapper must stay stateless
   and read-only — no write path, no persistence, no key custody for issuance.
3. **Minimal dependencies.** Runtime imports are `cbor2`, `cryptography`, and
   the standard library — nothing else. A test enforces this
   (`tests/test_iana_codepoints.py`); don't add a COSE library at runtime.
4. **Standards honesty.** The SCITT architecture and COSE Receipts documents
   are Internet-Drafts (RFC Editor Queue), not published RFCs. Never claim an
   unassigned RFC number; a test scans shipped source and docs for exactly this
   (`tests/test_cli_and_status.py`). Wire code points are asserted against the
   IANA registries, not a library's enum.
5. **Conformance is external.** Correctness claims rest on agreement with
   things outside this library (published RFC 6962/9162 vectors, a third-party
   COSE library, an independent Go implementation). New wire-facing behavior
   should come with cross-checked evidence, not just round-trip tests.

## Developer Certificate of Origin (DCO)

This project requires the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Every commit must be signed off, certifying you have the right to submit the
work under Apache-2.0:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer. PRs with
unsigned commits will fail the DCO check. No CLA is required — the DCO is the
whole agreement.

## Developing

```bash
pip install -e ".[dev,serve]"
python3 -m pytest -q                  # unit + conformance suite
SCITT_REQUIRE_GO=1 python3 -m pytest -q   # force the Go cross-language check (needs Go)
python3 -m ruff check .
```

The Go cross-verifier lives in `scitt-cose-go-verify/` (a sibling directory of
this package); the test suite builds it automatically when `go` is on PATH. Set
`SCITT_GO_VERIFIER_DIR` if it lives elsewhere.

## Pull requests

- Keep changes focused; one concern per PR.
- Add or extend tests — including **negative** (MUST-reject) tests for any
  verification-path change.
- All commits signed off (`-s`), CI green (pytest with `SCITT_REQUIRE_GO=1`,
  ruff, Go build).
- License headers: new source files start with
  `# SPDX-License-Identifier: Apache-2.0`.

## Security

If you believe you've found a security issue in the verification logic, please
do not open a public issue — email security@actionstate.ai and we'll coordinate
a fix and disclosure.

## License

By contributing, you agree your contributions are licensed under
[Apache-2.0](LICENSE).
