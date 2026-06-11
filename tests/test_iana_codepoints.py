# SPDX-License-Identifier: Apache-2.0
"""Pin every wire value to its IANA-registry / RFC number — NOT a library enum.

The original sin this whole project guards against: ``python-cwt`` ships
``COSEHeaders.CWT_CLAIMS = 13``, but the IANA-registered "CWT Claims" header
parameter is **15** (RFC 9597 §2; 13 is ``kcwt`` from RFC 9528). A verifier that
trusts a library's enum can be confidently, consistently wrong on the wire.

So this test asserts each code point against a **literal** drawn from the
authoritative source (the IANA registry / the RFC text), spelled out here with
its citation — never against another library's constant. If an upstream value
ever drifts, this test breaks loudly. These literals ARE the conformance claim.
"""
from __future__ import annotations

from scitt_cose.cose_sign1 import (
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    COSE_SIGN1_TAG,
    HDR_ALG,
    HDR_CRIT,
)
from scitt_cose.receipt import (
    HDR_VDP,
    HDR_VDS,
    VDP_INCLUSION_PROOFS,
    VDS_RFC9162_SHA256,
)
from scitt_cose.statement import (
    CWT_ISS,
    CWT_SUB,
    HDR_CONTENT_TYPE,
    HDR_CWT_CLAIMS,
    HDR_KID,
    HDR_RECEIPTS,
)


def test_cbor_tags():
    # CBOR tag for COSE_Sign1 (RFC 9052 §2 / IANA CBOR Tags registry).
    assert COSE_SIGN1_TAG == 18


def test_cose_header_parameter_labels():
    # IANA "COSE Header Parameters" registry.
    assert HDR_ALG == 1            # alg               (RFC 9052 §3.1)
    assert HDR_CRIT == 2           # crit              (RFC 9052 §3.1)
    assert HDR_CONTENT_TYPE == 3   # content type      (RFC 9052 §3.1)
    assert HDR_KID == 4            # kid               (RFC 9052 §3.1)
    # The headline one: CWT Claims is 15 (RFC 9597 §2), NOT 13 (kcwt, RFC 9528).
    assert HDR_CWT_CLAIMS == 15
    assert HDR_CWT_CLAIMS != 13


def test_cose_algorithm_code_points():
    # IANA "COSE Algorithms" registry (RFC 9053).
    assert COSE_ALG_EDDSA == -8
    assert COSE_ALG_ES256 == -7


def test_cwt_claim_labels():
    # IANA "CWT Claims" registry (RFC 8392 §3.1.1 / §3.1.2).
    assert CWT_ISS == 1   # iss
    assert CWT_SUB == 2   # sub


def test_receipt_and_merkle_code_points():
    # COSE Receipts (draft-ietf-cose-merkle-tree-proofs) header parameters.
    assert HDR_VDS == 395               # verifiable-data-structure (protected)
    assert HDR_VDP == 396               # verifiable-data-proofs (unprotected)
    assert VDS_RFC9162_SHA256 == 1      # RFC9162_SHA256 verifiable data structure
    assert VDP_INCLUSION_PROOFS == -1   # inclusion-proofs key in the vdp map
    # SCITT Receipts attached in the statement unprotected header.
    assert HDR_RECEIPTS == 394


def test_we_do_not_depend_on_python_cwt_enum():
    """Independence guard: the package must not import python-cwt for wire values."""
    import pathlib

    pkg = pathlib.Path(__file__).resolve().parents[1] / "scitt_cose"
    offenders = []
    for src in pkg.rglob("*.py"):
        text = src.read_text(encoding="utf-8")
        for needle in ("import cwt", "from cwt", "import pycose", "from pycose"):
            if needle in text:
                offenders.append(f"{src.name}: {needle!r}")
    assert not offenders, f"runtime package must not import a COSE library: {offenders}"


def test_no_reserved_or_downstream_code_in_package():
    """Neutrality gate: nothing from any consuming product leaks into this package.

    The shipped package must never import (or even mention) the downstream
    host/profile packages that consume it. This is the file-level half of the
    "no reserved code" launch gate; the history-level half is a fresh git
    history at repo extraction (see docs/launch-checklist.md).
    """
    import pathlib

    # Needles assembled at runtime so this test file itself stays clean under
    # the tree-wide CI grep for the same strings.
    needles = ("gopher" + "_ai", "gopher" + "-ai")
    pkg = pathlib.Path(__file__).resolve().parents[1] / "scitt_cose"
    offenders = []
    for src in pkg.rglob("*.py"):
        text = src.read_text(encoding="utf-8")
        if any(n in text for n in needles):
            offenders.append(src.name)
    assert not offenders, f"downstream package referenced in neutral substrate: {offenders}"
