#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME append of ``synthetic-es256-iat-grade-observed-only`` to receipt-v1.

Witnesses now emit the grade label ``observed-only`` where they used to emit
``countersigned-observed`` (same meaning: existence and time, consistency not
checked). receipt-v1 is append-only, so ``synthetic-es256-iat-grade`` keeps
its published bytes and its ``countersigned-observed`` label; this script adds
a twin carrying the new label beside it. It refuses to run if the twin
already exists, writes only the new vector directory, and appends to
``manifest.json`` and ``SHA256SUMS`` without touching an existing line.

This library does not interpret grade values. The twin pins that a receipt
carrying the new label verifies and surfaces it exactly as the old one does.
"""
from __future__ import annotations

import hashlib
import json
import sys

from generate_receipt_grade_vectors import (
    OUT,
    VERSION,
    _build_receipt,
    _entries,
    _keys,
    _self_check,
    _write_vector,
)

from scitt_cose import merkle_root

VID = "synthetic-es256-iat-grade-observed-only"


def main() -> int:
    root = OUT / VERSION
    if (root / VID).exists():
        print(f"refusing to overwrite published {root / VID} -- receipt-v1 is append-only")
        return 1

    priv, pub = _keys("ES256")
    es = _entries(6)
    receipt = _build_receipt(
        leaf_entry_hex=es[3], leaf_index=3, tree_entries_hex=es, alg="ES256",
        log_private_key_pem=priv, iat=1700000500, grade="observed-only",
    )
    exp = _write_vector(
        VID,
        description="Twin of synthetic-es256-iat-grade carrying the grade label witnesses emit now, "
                    "observed-only (formerly countersigned-observed; same meaning).",
        alg="ES256", leaf_entry_hex=es[3], tree_size=6, leaf_index=3,
        receipt=receipt, log_pub=pub, expect_ok=True,
        expect_iat=1700000500, expect_grade="observed-only",
        expect_witness_time=True, expect_grade_bound=True,
        expect_root=merkle_root(es),
    )
    mismatches = _self_check(VID, exp)
    if mismatches:
        print("SELF-CHECK FAILED:", *mismatches, sep="\n  ")
        return 1

    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["vectors"].append({"id": VID, "dir": f"{VERSION}/{VID}", "ok": True})
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    sums_path = root / "SHA256SUMS"
    lines = [
        f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(root)}"
        for f in sorted((root / VID).iterdir())
    ]
    with sums_path.open("a") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"appended {VID} under {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
