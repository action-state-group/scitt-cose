<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- **GitHub:** use *Security → Report a vulnerability* on this repository
  (GitHub private vulnerability reporting), or
- **Email:** stevenmih88@gmail.com with `[scitt-cose security]` in the subject.

Please do not open a public issue for a suspected vulnerability. We aim to
acknowledge reports within 72 hours.

## Scope

- The `scitt_cose` Python package (statement/receipt verification, Merkle
  primitives, the stdlib/ASGI hosted wrappers) and the Go cross-verifier in
  `scitt-cose-go-verify/`.
- The hosted convenience endpoint (`verify.actionstate.ai`) runs this same
  library unchanged. It is stateless and retains nothing; reports about the
  hosted deployment are in scope and reach the same operators.

## What counts

Cryptographic verification bypasses (a statement/receipt that verifies but
should not), proof-handling flaws, parser memory-safety or resource-exhaustion
issues, and anything that would make the hosted endpoint retain or leak
submitted data. Honest-but-misleading prose about standards status is also
welcome as a (public) issue — this project treats standards honesty as a
correctness property.

## Supported versions

The latest released version on PyPI receives security fixes.
