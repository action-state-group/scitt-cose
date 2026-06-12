# SPDX-License-Identifier: Apache-2.0
"""Generic SCITT Signed / Transparent Statement build + parse.

A *Signed Statement* (per draft-ietf-scitt-architecture) is a COSE_Sign1 whose
protected header carries a CWT Claims map (issuer / subject and friends) and a
content type, signed over an opaque payload. A *Transparent Statement* is that
same Signed Statement with one or more Receipts attached in the unprotected
header.

This module is **profile-agnostic**: the caller supplies ``issuer``, ``subject``,
``content_type`` and any ``extra_cwt_claims``. There is no baked-in media type,
no required subject prefix, no domain-separator claim — bring your own semantics.

CWT Claims live at COSE header **label 15** (RFC 9597 §2, "CWT Claims"). This is
deliberately *not* label 13: label 13 is ``kcwt`` (RFC 9528) and is sometimes
mis-used by libraries for the claims map. We always read and write at 15.
"""
from __future__ import annotations

from typing import Union

import cbor2

from .cose_sign1 import (
    ALG_CODE_TO_NAME,
    COSE_SIGN1_TAG,
    HDR_ALG,
    HDR_CRIT,
    CoseError,
    _plain,
    sign_sign1,
    strict_decode,
    verify_sign1,
)

#: COSE header parameter labels used by statements.
HDR_CONTENT_TYPE = 3  # RFC 9052 §3.1
HDR_KID = 4  # RFC 9052 §3.1
HDR_CWT_CLAIMS = 15  # RFC 9597 §2 ("CWT Claims") — NOT label 13 (kcwt, RFC 9528)

#: Unprotected header parameter for attached Receipts
#: (draft-ietf-cose-merkle-tree-proofs / draft-ietf-scitt-architecture).
HDR_RECEIPTS = 394

#: CWT claim labels (RFC 8392 / IANA CWT Claims registry).
CWT_ISS = 1
CWT_SUB = 2

PemLike = Union[bytes, str]


def _merge_extra_claims(claims: dict, extra: dict | None) -> None:
    """Merge ``extra`` into ``claims`` in place.

    Keys may be ``int`` (a registered CWT claim label) or ``str`` (a private /
    profile claim name). Both are passed through to CBOR unchanged.
    """
    if not extra:
        return
    for key, value in extra.items():
        if not isinstance(key, (int, str)):
            raise CoseError(f"extra_cwt_claims key must be int or str, got {type(key).__name__}")
        claims[key] = value


def build_signed_statement(
    payload: bytes,
    *,
    alg: str,
    private_key_pem: PemLike,
    issuer: str,
    subject: str,
    content_type: str,
    extra_cwt_claims: dict | None = None,
    kid: bytes | None = None,
) -> bytes:
    """Build a generic SCITT Signed Statement (COSE_Sign1) over ``payload``.

    The protected header carries: alg (label 1, set by the signer), content_type
    (label 3), optional kid (label 4), and a CWT Claims map (label 15) containing
    issuer (claim 1), subject (claim 2), and any ``extra_cwt_claims`` merged in.
    The unprotected header is left empty (the registration form). Returns CBOR
    tag-18 bytes.
    """
    claims: dict = {CWT_ISS: issuer, CWT_SUB: subject}
    _merge_extra_claims(claims, extra_cwt_claims)

    protected: dict = {
        HDR_CONTENT_TYPE: content_type,
        HDR_CWT_CLAIMS: claims,
    }
    if kid is not None:
        protected[HDR_KID] = kid

    return sign_sign1(
        payload,
        alg=alg,
        private_key_pem=private_key_pem,
        protected=protected,
        unprotected={},
    )


def _decode_text(value) -> str | None:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(value, str):
        return value
    return None


# Labels the statement layer actively processes — so a header legitimately
# marked critical among these is accepted, while anything else critical is
# rejected by the RFC 9052 §3.1 check inside verify_sign1.
_STMT_UNDERSTOOD = frozenset(
    {HDR_ALG, HDR_CRIT, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS}
)


def _extract_fields(protected: dict, payload: bytes | None) -> dict:
    """Pull the generic statement fields out of a (decoded) protected header."""
    claims = protected.get(HDR_CWT_CLAIMS)
    if not isinstance(claims, dict):
        claims = {}
    alg_code = protected.get(HDR_ALG)
    alg = ALG_CODE_TO_NAME.get(alg_code, alg_code) if isinstance(alg_code, int) else alg_code
    return {
        "issuer": _decode_text(claims.get(CWT_ISS)),
        "subject": _decode_text(claims.get(CWT_SUB)),
        "content_type": _decode_text(protected.get(HDR_CONTENT_TYPE)),
        "alg": alg,
        "claims": claims,
        "payload": payload,
    }


def parse_signed_statement(
    msg: bytes,
    *,
    public_key_pem: PemLike | None = None,
) -> dict:
    """Parse a generic Signed Statement, optionally verifying its signature.

    **Failure contract (see the README "Failure contract" section):** this is a
    public verifier entry point — it **never raises** on malformed or
    unverifiable input. Every outcome is reported in the returned dict.

    Keys:

    * ``signature_verified`` — ``True`` (key supplied and signature checked out),
      ``False`` (key supplied and it did not verify, *or* the input was
      malformed), or ``None`` (no key supplied, so nothing was checked).
    * ``issuer`` / ``subject`` / ``content_type`` / ``alg`` / ``claims`` /
      ``payload`` — the **authenticated** values. They are populated **only when
      ``signature_verified is True``**; otherwise they are ``None`` / ``{}``. An
      integrator can therefore trust a non-``None`` ``issuer`` to be signed.
    * ``unverified`` — when the structure parsed but was *not* authenticated
      (no key, wrong key, or bad signature over a well-formed envelope), the
      structurally-decoded fields are surfaced here, explicitly fenced off so
      they cannot be mistaken for authenticated values. ``None`` when the input
      did not parse at all.

    This closes the soft-fail identity-surfacing hazard: ``parsed["issuer"]`` is
    never an attacker-chosen value, because it is set only after a good signature.
    """
    authed = {
        "issuer": None, "subject": None, "content_type": None,
        "alg": None, "claims": {}, "payload": None,
    }

    if public_key_pem is not None:
        try:
            sign1 = verify_sign1(
                msg, public_key_pem=public_key_pem, understood_labels=_STMT_UNDERSTOOD,
            )
        except CoseError:
            # Well-formed-but-unverified, OR malformed: try a structural parse so
            # the caller can see (fenced) what was claimed, but authenticated
            # fields stay empty. A structural failure is itself a soft failure.
            unverified = _safe_structural_fields(msg)
            return {"signature_verified": False, **authed, "unverified": unverified}
        # Verified: the decoded fields are authenticated.
        return {
            "signature_verified": True,
            **_extract_fields(sign1.protected, sign1.payload),
            "unverified": None,
        }

    # No key: nothing is checked. Surface fields only under `unverified`.
    unverified = _safe_structural_fields(msg)
    return {"signature_verified": None, **authed, "unverified": unverified}


def _safe_structural_fields(msg: bytes) -> dict | None:
    """Structurally parse ``msg`` into the generic fields, or ``None`` if it does
    not parse. Never raises — the no-authentication paths use this."""
    try:
        protected, payload = _structural_parse(msg)
    except CoseError:
        return None
    fields = _extract_fields(protected, None)
    # Don't hand back attacker payload bytes as if meaningful; report length only.
    fields["payload_len"] = len(payload) if payload is not None else None
    return fields


def _structural_parse(msg: bytes):
    """Decode protected header + payload without verifying the signature.

    Uses the strict decoder so that even the no-key / verification-failed path
    rejects malleable encodings (trailing bytes, indefinite-length, duplicate
    protected keys) the same way the verifying path does — there is no lenient
    back door into the parser.
    """
    outer = strict_decode(msg)
    if outer.tag != COSE_SIGN1_TAG or not isinstance(outer.value, (list, tuple)) or len(outer.value) != 4:
        raise CoseError("not a COSE_Sign1 message")
    protected_bstr, _unprotected, payload_slot, _signature = outer.value
    if protected_bstr:
        try:
            protected = _plain(cbor2.loads(protected_bstr))
        except Exception as exc:  # noqa: BLE001
            raise CoseError(f"protected header is not valid CBOR: {exc}") from exc
    else:
        protected = {}
    if not isinstance(protected, dict):
        protected = {}
    payload = bytes(payload_slot) if isinstance(payload_slot, (bytes, bytearray)) else None
    return protected, payload


# ---------------------------------------------------------------------------
# Transparent Statement: attach / extract Receipts (unprotected label 394)
# ---------------------------------------------------------------------------


def attach_receipts(statement: bytes, receipts: list[bytes]) -> bytes:
    """Return a Transparent Statement: ``statement`` with ``receipts`` added.

    The receipts are placed in the unprotected header at label 394 as a CBOR
    array of bstrs. If receipts are already present they are extended. The
    protected header (and thus the signature) is untouched.
    """
    outer = strict_decode(statement)
    if outer.tag != COSE_SIGN1_TAG or not isinstance(outer.value, (list, tuple)) or len(outer.value) != 4:
        raise CoseError("not a COSE_Sign1 message")
    protected_bstr, unprotected, payload_slot, signature = outer.value
    unprotected = _plain(unprotected)
    if not isinstance(unprotected, dict):
        unprotected = {}
    existing = unprotected.get(HDR_RECEIPTS)
    if not isinstance(existing, (list, tuple)):
        existing = []
    unprotected = dict(unprotected)
    unprotected[HDR_RECEIPTS] = list(existing) + [bytes(r) for r in receipts]
    return cbor2.dumps(
        cbor2.CBORTag(outer.tag, [protected_bstr, unprotected, payload_slot, signature])
    )


def extract_receipts(transparent: bytes) -> list[bytes]:
    """Return the list of Receipt bytes attached to a Transparent Statement.

    An empty list is returned when no receipts are present.
    """
    outer = strict_decode(transparent)
    if outer.tag != COSE_SIGN1_TAG or not isinstance(outer.value, (list, tuple)) or len(outer.value) != 4:
        raise CoseError("not a COSE_Sign1 message")
    _protected_bstr, unprotected, _payload, _signature = outer.value
    unprotected = _plain(unprotected)
    if not isinstance(unprotected, dict):
        return []
    receipts = unprotected.get(HDR_RECEIPTS)
    if not isinstance(receipts, (list, tuple)):
        return []
    # Receipt elements must be byte strings; reject anything else (an int here
    # would coerce to a giant zero buffer — see the receipt allocation guard).
    out = []
    for r in receipts:
        if not isinstance(r, (bytes, bytearray)):
            raise CoseError("attached receipt element is not a byte string")
        out.append(bytes(r))
    return out


__all__ = [
    "build_signed_statement",
    "parse_signed_statement",
    "attach_receipts",
    "extract_receipts",
    "HDR_CONTENT_TYPE",
    "HDR_KID",
    "HDR_CWT_CLAIMS",
    "HDR_RECEIPTS",
    "CWT_ISS",
    "CWT_SUB",
]
