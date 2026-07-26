# SPDX-License-Identifier: Apache-2.0
"""Draft-tracking status constants for :mod:`scitt_cose`.

The SCITT Architecture document is now **RFC 9943** (published June 2026).
The COSE Merkle-tree-proofs (Receipts) document remains an IETF Internet-Draft
in the RFC Editor Queue — **NOT yet an RFC**. The constants below are surfaced
in the README, the public API, and the CLI banner so a consumer is never
misled about the standards status of either document.

Honesty rules encoded here:

* Never claim an unassigned RFC number (the scan test enforces this).
* The public-facing notice states the published vs. draft status *positively* —
  it does not name numbers that don't exist.
* The COSE substrate that is published and relied upon: RFC 9052/9053 (COSE
  structures + algorithms), RFC 9162 (Certificate Transparency v2 Merkle tree /
  inclusion + consistency proofs), RFC 9597 (CWT Claims in COSE headers, header
  label 15), RFC 9943 (SCITT Architecture), and RFC 9964 (ML-DSA COSE code
  points — *recognized* here, signing not implemented).
"""
from __future__ import annotations

#: SCITT Architecture — published as RFC 9943 (June 2026).
#: (Was draft-ietf-scitt-architecture-22 before publication.)
RFC_SCITT_ARCHITECTURE = "RFC 9943"

#: Backward-compatibility alias; use RFC_SCITT_ARCHITECTURE in new code.
DRAFT_SCITT_ARCHITECTURE = RFC_SCITT_ARCHITECTURE

#: COSE Receipts / COSE Merkle Tree Proofs — still an Internet-Draft.
DRAFT_COSE_MERKLE_TREE_PROOFS = "draft-ietf-cose-merkle-tree-proofs-18"

#: Published RFCs whose mechanisms this library implements / relies on.
#: Titles verified against the RFC Editor / IANA registries (see README).
SUBSTRATE_RFCS = (
    "RFC 9052",  # COSE Structures and Process (COSE_Sign1, Sig_structure)
    "RFC 9053",  # COSE Initial Algorithms (EdDSA, ES256)
    "RFC 9162",  # Certificate Transparency v2: Merkle tree, inclusion+consistency
    "RFC 9597",  # CBOR Web Token (CWT) Claims in COSE Headers (label 15)
    "RFC 9943",  # SCITT Architecture: An Architecture for Trustworthy and Transparent Digital Supply Chains
    "RFC 9964",  # ML-DSA for JOSE and COSE (recognized; signing not implemented)
)

#: Single-line notice surfaced by the CLI banner and re-exported from the API.
DRAFT_TRACKING_NOTICE = (
    "scitt-cose implements " + RFC_SCITT_ARCHITECTURE + " (SCITT Architecture, "
    "published June 2026) and tracks " + DRAFT_COSE_MERKLE_TREE_PROOFS + " — "
    "an IETF Internet-Draft (Work in Progress), currently in the RFC Editor "
    "Queue, NOT yet published as RFCs. Substrate RFCs used: "
    + ", ".join(SUBSTRATE_RFCS) + " (9964 recognized, ML-DSA signing not "
    "implemented)."
)

__all__ = [
    "RFC_SCITT_ARCHITECTURE",
    "DRAFT_SCITT_ARCHITECTURE",
    "DRAFT_COSE_MERKLE_TREE_PROOFS",
    "SUBSTRATE_RFCS",
    "DRAFT_TRACKING_NOTICE",
]
