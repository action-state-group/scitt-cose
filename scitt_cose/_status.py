# SPDX-License-Identifier: Apache-2.0
"""Standards status constants for :mod:`scitt_cose`.

Both documents this library implements are published RFCs: the SCITT
Architecture is **RFC 9943** and COSE Receipts is **RFC 9942** (both were
Internet-Drafts before publication). The constants below are surfaced in the
README, the public API, and the CLI banner so a consumer is never misled about
the standards status of either document.

Honesty rules encoded here:

* Never claim an unassigned RFC number (the scan test enforces this).
* The public-facing notice states the published vs. draft status *positively* —
  it does not name numbers that don't exist.
* The COSE substrate that is published and relied upon: RFC 9052/9053 (COSE
  structures + algorithms), RFC 9162 (Certificate Transparency v2 Merkle tree /
  inclusion + consistency proofs), RFC 9597 (CWT Claims in COSE headers, header
  label 15), RFC 9942 (COSE Receipts), RFC 9943 (SCITT Architecture), and
  RFC 9964 (ML-DSA COSE code points — *recognized* here, signing not
  implemented).
"""
from __future__ import annotations

#: SCITT Architecture — published as RFC 9943 (June 2026).
#: (Was draft-ietf-scitt-architecture-22 before publication.)
RFC_SCITT_ARCHITECTURE = "RFC 9943"

#: Backward-compatibility alias; use RFC_SCITT_ARCHITECTURE in new code.
DRAFT_SCITT_ARCHITECTURE = RFC_SCITT_ARCHITECTURE

#: COSE Receipts — published as RFC 9942.
#: (Was draft-ietf-cose-merkle-tree-proofs-18 before publication; the wire
#: shape this library implements -- vds 395, vdp 396, RFC9162_SHA256 = 1 -- is
#: unchanged in the RFC.)
RFC_COSE_RECEIPTS = "RFC 9942"

#: Backward-compatibility alias; use RFC_COSE_RECEIPTS in new code.
DRAFT_COSE_MERKLE_TREE_PROOFS = RFC_COSE_RECEIPTS

#: Published RFCs whose mechanisms this library implements / relies on.
#: Titles verified against the RFC Editor / IANA registries (see README).
SUBSTRATE_RFCS = (
    "RFC 9052",  # COSE Structures and Process (COSE_Sign1, Sig_structure)
    "RFC 9053",  # COSE Initial Algorithms (EdDSA, ES256)
    "RFC 9162",  # Certificate Transparency v2: Merkle tree, inclusion+consistency
    "RFC 9597",  # CBOR Web Token (CWT) Claims in COSE Headers (label 15)
    "RFC 9942",  # COSE Receipts
    "RFC 9943",  # SCITT Architecture: An Architecture for Trustworthy and Transparent Digital Supply Chains
    "RFC 9964",  # ML-DSA for JOSE and COSE (recognized; signing not implemented)
)

#: Single-line notice surfaced by the CLI banner and re-exported from the API.
DRAFT_TRACKING_NOTICE = (
    "scitt-cose implements " + RFC_SCITT_ARCHITECTURE + " (SCITT Architecture) "
    "and " + RFC_COSE_RECEIPTS + " (COSE Receipts). Substrate RFCs used: "
    + ", ".join(SUBSTRATE_RFCS) + " (9964 recognized, ML-DSA signing not "
    "implemented)."
)

__all__ = [
    "RFC_SCITT_ARCHITECTURE",
    "DRAFT_SCITT_ARCHITECTURE",
    "RFC_COSE_RECEIPTS",
    "DRAFT_COSE_MERKLE_TREE_PROOFS",
    "SUBSTRATE_RFCS",
    "DRAFT_TRACKING_NOTICE",
]
