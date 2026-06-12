# SPDX-License-Identifier: Apache-2.0
"""Clean-room COSE_Sign1 sign + verify (RFC 9052 §4.4).

This module builds the COSE ``Sig_structure`` and signs / verifies it directly
with :mod:`cryptography`. It does **not** depend on any COSE library: the only
imports are :mod:`cbor2`, :mod:`cryptography`, and the standard library. The
point is to be a second, independent implementation — the kind that catches the
bug class where an emitter and its own round-trip reader are self-consistently
wrong.

Supported algorithms (RFC 9053):

* ``EdDSA`` — code point ``-8``; signature is the raw Ed25519 signature.
* ``ES256`` — code point ``-7``; COSE carries the signature as raw ``r || s``
  (64 bytes), *not* DER. We convert to/from DER on the :mod:`cryptography`
  boundary via :func:`encode_dss_signature` / :func:`decode_dss_signature`.

``external_aad`` is always ``b""`` here (the common SCITT case).
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Union

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

#: COSE_Sign1 CBOR tag (RFC 9052 §2).
COSE_SIGN1_TAG = 18

#: COSE header parameter label for the algorithm (RFC 9052 §3.1).
HDR_ALG = 1

#: COSE "critical headers" parameter (RFC 9052 §3.1, label 2). Lists header
#: labels a recipient MUST understand or else reject the whole message.
HDR_CRIT = 2

#: Largest COSE message this library will decode. Generous for real statements
#: and receipts, but stops a tiny message from steering an unbounded decode. The
#: deeper allocation/recursion bounds live in the Merkle/receipt layer; this is
#: the message-level guard at the trust boundary.
MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MiB

#: COSE algorithm code points (RFC 9053).
COSE_ALG_EDDSA = -8
COSE_ALG_ES256 = -7

#: Map of the algorithm names this module can sign/verify to code points.
ALG_NAME_TO_CODE = {
    "EdDSA": COSE_ALG_EDDSA,
    "ES256": COSE_ALG_ES256,
}
ALG_CODE_TO_NAME = {v: k for k, v in ALG_NAME_TO_CODE.items()}

PemLike = Union[bytes, str]


class CoseError(Exception):
    """Raised on a malformed COSE_Sign1 structure or a bad signature."""


@dataclass
class Sign1:
    """A decoded COSE_Sign1 message.

    ``protected`` is the decoded protected-header map; ``unprotected`` the
    unprotected-header map; ``payload`` the (possibly externally supplied)
    detached payload bytes.
    """

    protected: dict
    unprotected: dict
    payload: bytes


def _as_bytes(pem: PemLike) -> bytes:
    return pem.encode("utf-8") if isinstance(pem, str) else bytes(pem)


def _sig_structure(protected_bstr: bytes, payload: bytes) -> bytes:
    """RFC 9052 §4.4 Sig_structure for COSE_Sign1.

    ``["Signature1", body_protected, external_aad, payload]`` with
    ``external_aad == b""``.
    """
    return cbor2.dumps(["Signature1", protected_bstr, b"", payload])


def sign_sign1(
    payload: bytes,
    *,
    alg: str,
    private_key_pem: PemLike,
    protected: dict | None = None,
    unprotected: dict | None = None,
    detached: bool = False,
) -> bytes:
    """Produce a COSE_Sign1 message (CBOR tag-18) over ``payload``.

    ``alg`` is ``"EdDSA"`` or ``"ES256"``; its code point is forced into
    ``protected[1]`` regardless of any caller-supplied value, so the signed
    protected header always declares the algorithm actually used. Any other
    entries in ``protected`` / ``unprotected`` are passed through verbatim.

    When ``detached`` is true the payload slot in the emitted structure is CBOR
    ``nil`` (the bytes still being what was signed); the verifier must supply the
    payload out of band.
    """
    if alg not in ALG_NAME_TO_CODE:
        raise CoseError(f"unsupported alg {alg!r}; expected one of {sorted(ALG_NAME_TO_CODE)}")

    protected = dict(protected or {})
    unprotected = dict(unprotected or {})
    protected[HDR_ALG] = ALG_NAME_TO_CODE[alg]

    protected_bstr = cbor2.dumps(protected) if protected else b""
    tbs = _sig_structure(protected_bstr, payload)

    key = serialization.load_pem_private_key(_as_bytes(private_key_pem), password=None)

    if alg == "EdDSA":
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise CoseError("alg EdDSA requires an Ed25519 private key")
        signature = key.sign(tbs)
    else:  # ES256
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CoseError("alg ES256 requires an EC (P-256) private key")
        der = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    payload_slot = None if detached else payload
    return cbor2.dumps(
        cbor2.CBORTag(
            COSE_SIGN1_TAG, [protected_bstr, unprotected, payload_slot, signature]
        )
    )


def _plain(v):
    """Normalize cbor2 output across versions: cbor2>=6 returns CBOR maps as
    ``frozendict`` (not a ``dict`` subclass) and arrays as ``tuple``. Convert to
    plain ``dict``/``list`` so structural checks are cbor2-version-independent."""
    if isinstance(v, (bytes, bytearray, str)):
        return v
    if hasattr(v, "items"):  # dict or cbor2>=6 frozendict
        return {k: _plain(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v


def _read_definite_map_count(raw: bytes) -> int | None:
    """If ``raw`` begins a *definite-length* CBOR map, return its declared pair
    count; if it begins an *indefinite-length* map, return ``-1``; otherwise
    ``None``. Reads only the map's header byte(s) — this is not a value parser.
    """
    if not raw:
        return None
    ib = raw[0]
    if ib >> 5 != 5:  # major type 5 == map
        return None
    ai = ib & 0x1F
    if ai < 24:
        return ai
    if ai == 24:
        return raw[1] if len(raw) > 1 else 0
    if ai == 25:
        return int.from_bytes(raw[1:3], "big")
    if ai == 26:
        return int.from_bytes(raw[1:5], "big")
    if ai == 27:
        return int.from_bytes(raw[1:9], "big")
    if ai == 31:
        return -1  # indefinite-length map
    return None


def strict_decode(data: bytes) -> cbor2.CBORTag:
    """Decode attacker-controlled COSE bytes under strict, malleability-resistant
    rules, returning the decoded :class:`cbor2.CBORTag`.

    Plain ``cbor2.loads`` is too lenient for a verifier trust boundary: it
    silently ignores trailing bytes and accepts indefinite-length / non-minimal
    encodings, so two distinct byte strings can decode to "the same" message and
    one signature can be presented in many encodings. This rejects, with a typed
    :class:`CoseError`:

    * **trailing bytes** after the top-level item (explicit consumed-all check);
    * **non-deterministic encoding** of the COSE_Sign1 *structure* — indefinite
      length (e.g. an indefinite payload bstr), non-minimal integers, or a
      non-canonical unprotected map — caught by requiring the outer structure to
      equal its own canonical re-encoding;
    * **duplicate keys in the protected header** (ambiguous algorithm/claims;
      last-wins is a cross-implementation split).

    The protected header is preserved as opaque bytes by the outer check, so its
    inner key *ordering* is deliberately **not** constrained — a validly-signed
    third-party statement whose protected map is not canonically ordered is still
    accepted (verified against the RFC 9052 reference vector). Only duplicate
    keys and indefinite encoding inside it are rejected.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise CoseError("COSE message must be bytes")
    data = bytes(data)
    if len(data) > MAX_MESSAGE_BYTES:
        raise CoseError(f"COSE message too large ({len(data)} > {MAX_MESSAGE_BYTES} bytes)")

    stream = io.BytesIO(data)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception as exc:  # noqa: BLE001
        raise CoseError(f"not valid CBOR: {exc}") from exc
    extra = len(data) - stream.tell()
    if extra:
        raise CoseError(f"trailing bytes after the COSE_Sign1 item ({extra} extra) — rejected as malleable")

    # Deterministic-encoding check on the OUTER structure. The protected header
    # rides along as an opaque bstr here, so this does NOT constrain its inner
    # key ordering; it rejects indefinite-length, non-minimal ints, and a
    # non-canonical unprotected map — the malleability surface.
    try:
        recanonical = cbor2.dumps(value, canonical=True)
    except Exception as exc:  # noqa: BLE001
        raise CoseError(f"COSE message could not be re-encoded: {exc}") from exc
    if recanonical != data:
        raise CoseError(
            "non-deterministic COSE encoding (indefinite-length, non-minimal, "
            "or non-canonical) — rejected as malleable"
        )

    if not isinstance(value, cbor2.CBORTag):
        raise CoseError("top-level value is not a CBOR tag; expected COSE_Sign1 (tag 18)")

    # Duplicate-key / indefinite check on the protected header, which the outer
    # canonical check cannot see inside (it is an opaque bstr there).
    if isinstance(value.value, (list, tuple)) and len(value.value) == 4:
        prot = value.value[0]
        if isinstance(prot, (bytes, bytearray)) and prot:
            count = _read_definite_map_count(bytes(prot))
            if count == -1:
                raise CoseError("protected header uses indefinite-length encoding — rejected")
            if count is not None:
                try:
                    decoded = cbor2.loads(bytes(prot))
                except Exception as exc:  # noqa: BLE001
                    raise CoseError(f"protected header is not valid CBOR: {exc}") from exc
                if isinstance(decoded, dict) and len(decoded) != count:
                    raise CoseError(
                        "duplicate keys in the protected header — rejected "
                        "(ambiguous algorithm/claims; last-wins is a cross-impl split)"
                    )
    return value


def _decode_envelope(msg: bytes):
    """Decode the COSE_Sign1 outer structure strictly; return its four elements."""
    outer = strict_decode(msg)
    if outer.tag != COSE_SIGN1_TAG:
        raise CoseError(f"wrong CBOR tag {outer.tag}; expected COSE_Sign1 (tag 18)")
    value = _plain(outer.value)
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise CoseError(
            "COSE_Sign1 value must be a 4-element array "
            "[protected, unprotected, payload, signature]"
        )
    return value


def _check_critical_headers(protected: dict, understood_labels) -> None:
    """Enforce RFC 9052 §3.1 critical-header processing.

    If the protected header carries ``crit`` (label 2), it MUST be a non-empty
    array; every listed label MUST also be present in the protected header; and
    every listed label MUST be one this verifier understands — otherwise the
    whole message is rejected. This is the conservative, spec-faithful behaviour:
    a verifier that silently ignores a header someone marked *critical* is the
    kind of subtle non-conformance that costs a community verifier its trust.
    """
    if HDR_CRIT not in protected:
        return
    crit = protected[HDR_CRIT]
    if not isinstance(crit, (list, tuple)) or len(crit) == 0:
        raise CoseError("crit (label 2) must be a non-empty array (RFC 9052 §3.1)")
    for label in crit:
        if label not in protected:
            raise CoseError(
                f"crit lists header {label!r} which is absent from the protected header"
            )
        if label not in understood_labels:
            raise CoseError(
                f"crit marks header {label!r} as critical, but this verifier does "
                f"not understand it; rejecting (RFC 9052 §3.1)"
            )


def verify_sign1(
    msg: bytes,
    *,
    public_key_pem: PemLike,
    detached_payload: bytes | None = None,
    understood_labels=frozenset({HDR_ALG, HDR_CRIT}),
) -> Sign1:
    """Verify a COSE_Sign1 message and return its decoded :class:`Sign1`.

    Raises :class:`CoseError` on a structural problem or a bad signature. When
    the message carries a detached (``nil``) payload, ``detached_payload`` must
    be supplied — that is the payload whose signature is checked.

    ``understood_labels`` is the set of protected-header labels this caller can
    process; it governs RFC 9052 §3.1 ``crit`` enforcement. The generic default
    covers only alg (1) and crit (2) itself — a higher layer that processes more
    headers (e.g. the statement parser, which reads content-type / kid / CWT
    claims) passes a wider set so legitimately-critical headers are accepted.
    """
    protected_bstr, unprotected, payload_slot, signature = _decode_envelope(msg)

    if not isinstance(protected_bstr, (bytes, bytearray)):
        raise CoseError("protected header must be a bstr-wrapped map")
    protected_bstr = bytes(protected_bstr)
    if protected_bstr:
        protected = _plain(cbor2.loads(protected_bstr))
        if not isinstance(protected, dict):
            raise CoseError("decoded protected header is not a map")
    else:
        protected = {}

    if not isinstance(unprotected, dict):
        unprotected = {} if unprotected is None else unprotected
        if not isinstance(unprotected, dict):
            raise CoseError("unprotected header is not a map")

    if payload_slot is None:
        if detached_payload is None:
            raise CoseError(
                "payload is detached (nil); supply detached_payload to verify"
            )
        payload = bytes(detached_payload)
    else:
        if not isinstance(payload_slot, (bytes, bytearray)):
            raise CoseError("attached payload must be a byte string")
        payload = bytes(payload_slot)

    if not isinstance(signature, (bytes, bytearray)):
        raise CoseError("signature element is not a byte string")
    signature = bytes(signature)

    alg = protected.get(HDR_ALG)
    if not isinstance(alg, int):
        raise CoseError("protected header has no integer alg (label 1)")

    # RFC 9052 §3.1: reject any header marked critical that we do not understand.
    _check_critical_headers(protected, understood_labels)

    tbs = _sig_structure(protected_bstr, payload)
    try:
        pubkey = serialization.load_pem_public_key(_as_bytes(public_key_pem))
    except Exception as exc:  # noqa: BLE001
        raise CoseError(f"could not load public key: {exc}") from exc

    try:
        if alg == COSE_ALG_EDDSA:
            if not isinstance(pubkey, ed25519.Ed25519PublicKey):
                raise CoseError("alg is EdDSA (-8) but the public key is not Ed25519")
            pubkey.verify(signature, tbs)
        elif alg == COSE_ALG_ES256:
            if not isinstance(pubkey, ec.EllipticCurvePublicKey):
                raise CoseError("alg is ES256 (-7) but the public key is not EC")
            if len(signature) != 64:
                raise CoseError(
                    f"ES256 COSE signature must be 64 raw bytes (r||s), got {len(signature)}"
                )
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der = encode_dss_signature(r, s)
            pubkey.verify(der, tbs, ec.ECDSA(hashes.SHA256()))
        else:
            raise CoseError(f"unsupported alg code point {alg} for verification")
    except InvalidSignature as exc:
        raise CoseError("signature verification FAILED (InvalidSignature)") from exc

    return Sign1(protected=protected, unprotected=unprotected, payload=payload)


__all__ = [
    "CoseError",
    "Sign1",
    "sign_sign1",
    "verify_sign1",
    "strict_decode",
    "MAX_MESSAGE_BYTES",
    "COSE_SIGN1_TAG",
    "HDR_ALG",
    "HDR_CRIT",
    "COSE_ALG_EDDSA",
    "COSE_ALG_ES256",
    "ALG_NAME_TO_CODE",
    "ALG_CODE_TO_NAME",
]
