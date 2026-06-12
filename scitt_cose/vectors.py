# SPDX-License-Identifier: Apache-2.0
"""Cross-implementation test-vector runner: ``python -m scitt_cose.vectors``.

Walks ``test-vectors/manifest.json``, runs every vector through the SAME public
verify functions the library exposes (:func:`parse_signed_statement`,
:func:`verify_receipt`), prints a per-vector PASS/FAIL table, and exits non-zero
on any mismatch — **including a negative vector that unexpectedly verifies**.
A wrongly-accepted invalid vector is just as much a conformance failure as a
wrongly-rejected valid one; rejection-agreement is half the point of the set.

No network access, no new dependencies: stdlib + this package only. The vector
bytes are read from disk exactly as committed.

Usage::

    python -m scitt_cose.vectors                 # ./test-vectors
    python -m scitt_cose.vectors path/to/test-vectors
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from .receipt import verify_receipt
from .statement import parse_signed_statement


def check_vector(vector_dir: Path, expected: dict) -> list[str]:
    """Run one vector; return a list of mismatch descriptions (empty == PASS)."""
    mismatches: list[str] = []

    payload = (vector_dir / "payload.bin").read_bytes()
    statement = (vector_dir / "statement.cose").read_bytes()
    receipt = (vector_dir / "receipt.cose").read_bytes()
    issuer_pub = (vector_dir / "issuer-key.pub").read_bytes()
    log_pub = (vector_dir / "log-key.pub").read_bytes()

    # 1. Payload digest pins the committed bytes.
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected["payload_sha256"]:
        mismatches.append(f"payload sha256 {digest} != expected {expected['payload_sha256']}")

    # 2. The statement<->tree binding is part of the contract, not just prose:
    #    the log's leaf entry must be the SHA-256 of the full statement bytes.
    leaf = hashlib.sha256(statement).hexdigest()
    if leaf != expected["leaf_entry"]:
        mismatches.append(
            f"leaf_entry {expected['leaf_entry']} is not SHA-256(statement.cose) ({leaf})"
        )

    # 3. Statement: signature verdict + every decoded protected-header field.
    exp_stmt = expected["protected_header"]["statement"]
    parse_error: str | None = None
    try:
        parsed = parse_signed_statement(statement, public_key_pem=issuer_pub)
    except Exception as exc:  # noqa: BLE001 - a vector must never crash the runner
        parsed = {"signature_verified": False}
        parse_error = f"{type(exc).__name__}: {exc}"
    if parsed.get("signature_verified") is not expected["statement_signature_valid"]:
        detail = f" (parse error: {parse_error})" if parse_error else ""
        mismatches.append(
            "statement signature_verified="
            f"{parsed.get('signature_verified')} != expected "
            f"{expected['statement_signature_valid']}{detail}"
        )
    if parse_error is None:
        # Decoded protected-header fields are part of the published contract and
        # are present whether or not the signature verified. They are surfaced as
        # authenticated values only when the signature is good; otherwise the
        # library fences them under `unverified` so a caller cannot mistake an
        # unverified claim for a signed one. Read from whichever applies.
        src = parsed if parsed.get("signature_verified") is True else (parsed.get("unverified") or {})
        for field, key in (("alg", "alg"), ("issuer", "issuer"),
                           ("subject", "subject"), ("content_type", "content_type")):
            if src.get(field) != exp_stmt[key]:
                mismatches.append(f"statement {field}={src.get(field)!r} != {exp_stmt[key]!r}")

    # 4. Receipt: verdict, and for valid receipts the reconstructed root must
    #    equal the published one (clean-room agreement on the Merkle fold).
    res = verify_receipt(receipt, leaf_entry_hex=expected["leaf_entry"],
                         log_public_key_pem=log_pub)
    if res.ok is not expected["receipt_valid"]:
        verdict = "verified" if res.ok else f"failed ({'; '.join(res.errors)})"
        mismatches.append(
            f"receipt unexpectedly {verdict}; expected receipt_valid="
            f"{expected['receipt_valid']}"
        )
    if expected["receipt_valid"] and res.ok:
        if res.root != expected["reconstructed_root"]:
            mismatches.append(
                f"reconstructed root {res.root} != expected {expected['reconstructed_root']}"
            )
        if res.tree_size != expected["tree_size"] or res.leaf_index != expected["leaf_index"]:
            mismatches.append(
                f"tree_size/leaf_index {res.tree_size}/{res.leaf_index} != "
                f"{expected['tree_size']}/{expected['leaf_index']}"
            )

    # 5. Overall result must agree (a negative vector that verifies is a FAIL).
    overall_valid = (
        parsed.get("signature_verified") is True and res.ok
    )
    expected_valid = expected["result"] == "VALID"
    if overall_valid is not expected_valid:
        mismatches.append(
            f"overall verdict valid={overall_valid} != expected result {expected['result']}"
        )

    return mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scitt_cose.vectors",
        description="Run the scitt-cose cross-implementation test-vector set.",
    )
    parser.add_argument(
        "vectors_dir", nargs="?", default="test-vectors",
        help="path to the test-vectors directory (default: ./test-vectors)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit a machine-readable JSON report instead of the table",
    )
    args = parser.parse_args(argv)

    root = Path(args.vectors_dir)
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text())

    report = []
    for v in manifest["vectors"]:
        vector_dir = root / v["dir"]
        expected = json.loads((vector_dir / "expected.json").read_text())
        mismatches = check_vector(vector_dir, expected)
        # The manifest is the advertised machine-readable index — it must never
        # drift from the per-vector expected.json it points at.
        if v["expected_result"] != expected["result"]:
            mismatches.append(
                f"manifest expected_result={v['expected_result']} != "
                f"expected.json result={expected['result']}"
            )
        if v.get("failure_code") != expected.get("failure_code"):
            mismatches.append(
                f"manifest failure_code={v.get('failure_code')} != "
                f"expected.json failure_code={expected.get('failure_code')}"
            )
        report.append({
            "id": v["id"],
            "status": "PASS" if not mismatches else "FAIL",
            "expected_result": expected["result"],
            "failure_code": expected.get("failure_code"),
            "mismatches": mismatches,
        })

    failed = sum(len(r["mismatches"]) for r in report)

    if args.json:
        print(json.dumps({
            "version": manifest["version"],
            "pass": failed == 0,
            "vectors": report,
        }, indent=2))
        return 1 if failed else 0

    width = max(len(r["id"]) for r in report) + 2
    print(f"scitt-cose test vectors {manifest['version']} "
          f"(stability: {manifest['stability']}) — {len(report)} vectors\n")
    for r in report:
        code = r["failure_code"]
        label = f"[{r['expected_result']}{' / ' + code if code else ''}]"
        print(f"  {r['status']}  {r['id']:<{width}} {label}")
        for m in r["mismatches"]:
            print(f"        - {m}")

    print()
    if failed:
        print(f"FAIL: {failed} mismatch(es). A mismatch against your implementation "
              "is exactly the report we want — please open an issue with this output.")
        return 1
    print("PASS: every vector matches expected.json under this implementation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
