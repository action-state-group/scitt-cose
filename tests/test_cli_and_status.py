# SPDX-License-Identifier: Apache-2.0
"""CLI verification + draft-tracking honesty checks."""
from __future__ import annotations

import pytest

from scitt_cose import _status
from scitt_cose.cli import main
from scitt_cose.receipt import build_receipt
from scitt_cose.statement import build_signed_statement


def test_no_positive_rfc_9942_claim():
    # The notice must never mention the unassigned number at all — neither
    # claiming it nor publicly denying it (an outsider-facing denial of a
    # specific nonexistent number reads as an internal scar; the positive
    # "NOT yet published as RFCs" statement carries the honesty).
    notice = _status.DRAFT_TRACKING_NOTICE
    assert "RFC 9942" not in notice
    assert "9942" not in notice
    assert "RFC 9942" not in _status.SUBSTRATE_RFCS
    assert "draft-ietf-scitt-architecture-22" in notice
    assert "draft-ietf-cose-merkle-tree-proofs-18" in notice


def test_substrate_rfcs_listed():
    for rfc in ("RFC 9052", "RFC 9162", "RFC 9597"):
        assert rfc in _status.SUBSTRATE_RFCS


def test_draft_versions_pinned():
    # Tracked drafts must be version-pinned to the exact revisions audited against
    # the IETF Datatracker at ship date (Active Internet-Drafts, NOT RFCs).
    assert _status.DRAFT_SCITT_ARCHITECTURE == "draft-ietf-scitt-architecture-22"
    assert _status.DRAFT_COSE_MERKLE_TREE_PROOFS == "draft-ietf-cose-merkle-tree-proofs-18"


def test_draft_status_is_internet_draft_work_in_progress():
    """The most visible claim for a spec verifier: get the status string right.

    Per the Datatracker, both documents are Active Internet-Drafts (Work in
    Progress) in the RFC Editor Queue and NOT yet published RFCs. The notice must
    say exactly that — never imply a published RFC exists.
    """
    notice = _status.DRAFT_TRACKING_NOTICE
    assert "Internet-Draft" in notice
    assert "Work in Progress" in notice
    assert "RFC Editor Queue" in notice
    assert "NOT yet published as RFCs" in notice
    # And must never mention the fictional RFC number in any form.
    assert "9942" not in notice


def test_no_unassigned_rfc_claim_anywhere_in_package():
    """No positive 'RFC 9942' (or other unassigned numbers) claim in source/docs.

    The drafts are NOT yet RFCs; claiming an unassigned RFC number is the exact
    standards-honesty error this project refuses to make.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1]
    # The ONLY RFC numbers this library may positively cite — every one is a
    # genuinely published RFC it implements or relies on. Anything else (notably
    # the fictional "RFC 9942") is a fabricated-conformance claim.
    allowed = {"6962", "8032", "8392", "9052", "9053", "9162", "9528", "9597", "9964"}
    rfc_ref = re.compile(r"\bRFC\s?(\d{3,5})\b")
    offenders = []
    # Scan the shipped package + docs/README — NOT the tests, which reference the
    # forbidden number deliberately to assert it never escapes into shipped text.
    sources = list((root / "scitt_cose").rglob("*.py"))
    sources += [p for p in root.glob("*.md")]
    sources += list((root / "docs").rglob("*.md")) if (root / "docs").exists() else []
    for src in sources:
        for i, line in enumerate(src.read_text(encoding="utf-8").splitlines(), 1):
            for num in rfc_ref.findall(line):
                if num in allowed:
                    continue
                # An explicit *denial* ("There is NO RFC 9942") is allowed.
                if "NO RFC" in line or "no RFC" in line:
                    continue
                offenders.append(f"{src.name}:{i}: RFC {num}: {line.strip()}")
    assert not offenders, f"non-allowlisted / unassigned RFC number claimed: {offenders}"


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_cli_statement_ok(tmp_path, eddsa_keys, capsys):
    priv, pub = eddsa_keys
    stmt = build_signed_statement(
        b"hi", alg="EdDSA", private_key_pem=priv,
        issuer="iss", subject="sub", content_type="text/plain",
    )
    s = _write(tmp_path, "stmt.cose", stmt)
    k = _write(tmp_path, "pub.pem", pub)
    rc = main(["--statement", s, "--statement-pubkey", k])
    out = capsys.readouterr().out
    assert rc == 0
    assert "iss" in out and "PASS" in out
    # banner states draft status positively, never naming unassigned numbers
    assert "NOT yet published as RFCs" in out
    assert "9942" not in out


def test_cli_statement_wrong_key_nonzero(tmp_path, eddsa_keys, other_eddsa_keys, capsys):
    priv, _pub = eddsa_keys
    _o, opub = other_eddsa_keys
    stmt = build_signed_statement(
        b"hi", alg="EdDSA", private_key_pem=priv,
        issuer="iss", subject="sub", content_type="text/plain",
    )
    s = _write(tmp_path, "stmt.cose", stmt)
    k = _write(tmp_path, "wrong.pem", opub)
    rc = main(["--statement", s, "--statement-pubkey", k])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_cli_receipt_ok(tmp_path, eddsa_keys, capsys):
    priv, pub = eddsa_keys
    es = [b"a".hex(), b"b".hex(), b"c".hex()]
    receipt = build_receipt(
        leaf_entry_hex=es[1], leaf_index=1, tree_entries_hex=es,
        alg="EdDSA", log_private_key_pem=priv,
    )
    r = _write(tmp_path, "r.cose", receipt)
    k = _write(tmp_path, "log.pem", pub)
    rc = main(["--receipt", r, "--receipt-log-pubkey", k, "--leaf-entry-hex", es[1], "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"ok": true' in out


def test_cli_requires_input():
    with pytest.raises(SystemExit):
        main([])
