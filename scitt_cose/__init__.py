# SPDX-License-Identifier: Apache-2.0
"""scitt-cose — a generic, profile-agnostic IETF SCITT + COSE Receipts substrate.

Build/verify COSE_Sign1 Signed Statements, verify Receipts and RFC 9162
inclusion / consistency proofs, with the Merkle + receipt-signing primitives.
Also verifies CLL (Checkpointed Local Log) inclusion, consistency, and range
proofs against a signed checkpoint — see :mod:`scitt_cose.cll` — a wholly
different tree construction (MMR, not RFC 9162) kept in its own namespace
rather than the top-level API to avoid colliding names with the RFC 9162
Merkle functions below.

It is **not** a transparency service (operating a log is a separate concern) and
it carries **no** application profile — bring your own statement semantics. The
only third-party imports anywhere in the package are :mod:`cbor2` and
:mod:`cryptography` (plus the standard library).

Draft-tracking: see :mod:`scitt_cose._status`. No unassigned RFC number is
claimed anywhere (test-enforced).
"""
from __future__ import annotations

from . import cll
from ._status import (
    DRAFT_COSE_MERKLE_TREE_PROOFS,
    DRAFT_SCITT_ARCHITECTURE,
    DRAFT_TRACKING_NOTICE,
    SUBSTRATE_RFCS,
)
from .cose_sign1 import CoseError, Sign1, sign_sign1, verify_sign1
from .merkle import (
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)
from .receipt import ReceiptResult, build_receipt, verify_receipt
from .statement import (
    attach_receipts,
    build_signed_statement,
    extract_receipts,
    parse_signed_statement,
)

__version__ = "0.2.0"

__all__ = [
    # version + status
    "__version__",
    "cll",
    "DRAFT_TRACKING_NOTICE",
    "DRAFT_SCITT_ARCHITECTURE",
    "DRAFT_COSE_MERKLE_TREE_PROOFS",
    "SUBSTRATE_RFCS",
    # COSE_Sign1
    "sign_sign1",
    "verify_sign1",
    "Sign1",
    "CoseError",
    # statements
    "build_signed_statement",
    "parse_signed_statement",
    "attach_receipts",
    "extract_receipts",
    # merkle
    "leaf_hash",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
    # receipts
    "build_receipt",
    "verify_receipt",
    "ReceiptResult",
]
