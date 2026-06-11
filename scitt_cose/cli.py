# SPDX-License-Identifier: Apache-2.0
"""Command-line entry point for scitt-cose.

Verify a SCITT Signed Statement and/or a COSE Receipt from files. The CLI is
profile-agnostic: it reports the parsed issuer / subject / content-type / alg and
the signature verdict, and (optionally) verifies a Receipt's inclusion proof and
log signature against a leaf entry. It enforces no application profile.
"""
from __future__ import annotations

import argparse
import json
import sys

from ._status import DRAFT_TRACKING_NOTICE
from .cose_sign1 import CoseError
from .receipt import verify_receipt
from .statement import parse_signed_statement


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scitt-cose",
        description=(
            "Generic, profile-agnostic verifier for SCITT COSE_Sign1 Signed "
            "Statements and COSE Receipts (RFC 9162 inclusion proofs)."
        ),
        epilog=DRAFT_TRACKING_NOTICE,
    )
    parser.add_argument(
        "--statement", help="path to a COSE_Sign1 Signed Statement file"
    )
    parser.add_argument(
        "--statement-pubkey",
        help="PEM public key to verify the statement signature (optional)",
    )
    parser.add_argument("--receipt", help="path to a COSE Receipt file")
    parser.add_argument(
        "--receipt-log-pubkey",
        help="PEM public key of the transparency log (required with --receipt)",
    )
    parser.add_argument(
        "--leaf-entry-hex",
        help="hex of the leaf entry the receipt proves inclusion of (required with --receipt)",
    )
    parser.add_argument(
        "--json", dest="as_json", action="store_true", help="emit JSON"
    )
    return parser


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _verify_statement(args) -> dict | None:
    if not args.statement:
        return None
    msg = _read(args.statement)
    pub = _read(args.statement_pubkey) if args.statement_pubkey else None
    parsed = parse_signed_statement(msg, public_key_pem=pub)
    # Don't dump raw payload bytes into JSON; report length + hex preview.
    payload = parsed.get("payload")
    parsed = dict(parsed)
    parsed["payload_len"] = len(payload) if payload is not None else None
    parsed.pop("payload", None)
    parsed.pop("claims", None)  # may contain bytes; keep CLI output simple
    return parsed


def _verify_receipt(args) -> dict | None:
    if not args.receipt:
        return None
    if not args.receipt_log_pubkey or not args.leaf_entry_hex:
        return {
            "ok": False,
            "errors": ["--receipt requires --receipt-log-pubkey and --leaf-entry-hex"],
        }
    receipt = _read(args.receipt)
    log_pub = _read(args.receipt_log_pubkey)
    result = verify_receipt(
        receipt, leaf_entry_hex=args.leaf_entry_hex, log_public_key_pem=log_pub
    )
    return {
        "ok": result.ok,
        "root": result.root,
        "tree_size": result.tree_size,
        "leaf_index": result.leaf_index,
        "errors": list(result.errors),
    }


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.statement and not args.receipt:
        parser.error("supply at least one of --statement or --receipt")

    try:
        statement_report = _verify_statement(args)
        receipt_report = _verify_receipt(args)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except CoseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report = {
        "draft_tracking": DRAFT_TRACKING_NOTICE,
        "statement": statement_report,
        "receipt": receipt_report,
    }

    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_human(report)

    ok = True
    if statement_report is not None and statement_report.get("signature_verified") is False:
        ok = False
    if receipt_report is not None and not receipt_report.get("ok"):
        ok = False
    return 0 if ok else 1


def _print_human(report) -> None:
    print("scitt-cose")
    print(f"  {report['draft_tracking']}")
    print("-" * 72)
    s = report["statement"]
    if s is not None:
        print("  Signed Statement")
        print(f"    issuer (iss)   : {s.get('issuer')}")
        print(f"    subject (sub)  : {s.get('subject')}")
        print(f"    content_type   : {s.get('content_type')}")
        print(f"    alg            : {s.get('alg')}")
        sv = s.get("signature_verified")
        sv_text = "SKIPPED (no pubkey)" if sv is None else ("PASS" if sv else "FAIL")
        print(f"    signature      : {sv_text}")
        print(f"    payload_len    : {s.get('payload_len')}")
    r = report["receipt"]
    if r is not None:
        print("  Receipt")
        print(f"    ok             : {r.get('ok')}")
        print(f"    root           : {r.get('root')}")
        print(f"    tree_size      : {r.get('tree_size')}")
        print(f"    leaf_index     : {r.get('leaf_index')}")
        for e in r.get("errors", []):
            print(f"    [ERR] {e}")
    print("-" * 72)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
