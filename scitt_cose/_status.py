# SPDX-License-Identifier: Apache-2.0
"""Draft-tracking status constants for :mod:`scitt_cose`.

The SCITT architecture and the COSE Merkle-tree-proofs (Receipts) documents are
IETF Internet-Drafts in the RFC Editor Queue — they are **NOT yet RFCs**. The
constants below are surfaced in the README, the public API, and the CLI banner
so a consumer is never misled into believing a stable RFC number exists when it
does not.

Honesty rules encoded here:

* Never claim an unassigned RFC number (the scan test enforces this). The
  public-facing notice states the draft status *positively* — it does not
  name numbers that don't exist.
* The COSE substrate that *is* published and relied upon: RFC 9052/9053 (COSE
  structures + algorithms), RFC 9162 (Certificate Transparency v2 Merkle tree /
  inclusion + consistency proofs), RFC 9597 (CWT Claims in COSE headers, header
  label 15), and RFC 9964 (ML-DSA COSE code points — *recognized* here, signing
  not implemented).
"""
from __future__ import annotations

#: The two IETF Internet-Drafts this library tracks (RFC Editor Queue).
DRAFT_SCITT_ARCHITECTURE = "draft-ietf-scitt-architecture-22"
DRAFT_COSE_MERKLE_TREE_PROOFS = "draft-ietf-cose-merkle-tree-proofs-18"

#: Published RFCs whose mechanisms this library implements / relies on.
#: Titles verified against the RFC Editor / IANA registries (see README).
SUBSTRATE_RFCS = (
    "RFC 9052",  # COSE Structures and Process (COSE_Sign1, Sig_structure)
    "RFC 9053",  # COSE Initial Algorithms (EdDSA, ES256)
    "RFC 9162",  # Certificate Transparency v2: Merkle tree, inclusion+consistency
    "RFC 9597",  # CBOR Web Token (CWT) Claims in COSE Headers (label 15)
    "RFC 9964",  # ML-DSA for JOSE and COSE (recognized; signing not implemented)
)

#: Single-line notice surfaced by the CLI banner and re-exported from the API.
#: Status wording verified against the IETF Datatracker (ship-date audit): both
#: documents are *Active Internet-Drafts* (Work in Progress) sitting in the RFC
#: Editor Queue — approved but NOT yet published as RFCs. Re-verify at publish
#: time: RFC-Ed-Queue documents can be published (and gain RFC numbers) anytime.
DRAFT_TRACKING_NOTICE = (
    "scitt-cose tracks " + DRAFT_SCITT_ARCHITECTURE + " and "
    + DRAFT_COSE_MERKLE_TREE_PROOFS + " — IETF Internet-Drafts (Work in "
    "Progress), currently in the RFC Editor Queue, NOT yet published as RFCs. "
    "Substrate RFCs used: "
    + ", ".join(SUBSTRATE_RFCS) + " (9964 recognized, ML-DSA signing not "
    "implemented)."
)

__all__ = [
    "DRAFT_SCITT_ARCHITECTURE",
    "DRAFT_COSE_MERKLE_TREE_PROOFS",
    "SUBSTRATE_RFCS",
    "DRAFT_TRACKING_NOTICE",
]
