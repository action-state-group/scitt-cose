# SPDX-License-Identifier: Apache-2.0
"""The receipt encoding rule, checked on raw octets.

agent-action-capsule's interop profile v1 §6.2.2 states one rule for the CBOR
of a COSE Receipt, so that every verifier decides the same octets the same
way: the COSE_Sign1, its protected header and each inclusion-proof blob are
each one CBOR item with no trailing octet, definite lengths, every argument in
its shortest form (RFC 8949 §4.2.1), no repeated map key, every integer from
-2^63 to 2^64 - 1, every map key an integer or a text string, every text
string valid UTF-8, no float, no simple value but ``false``, ``true`` and
``null``, no tag but the outer tag 18, and no item nested more than 16 levels
deep (an item inside an array, a map or a tag is one level deeper). Map order
is not checked.

This walks the octets itself rather than asking cbor2, whose reading of tags,
floats and simple values is what made verifiers disagree. The Rust crate
(``rust/scitt-cose/src/encoding.rs``) and the Go verifier
(``scitt-cose-go-verify/encoding.go``) carry the same walk.
"""
from __future__ import annotations

from .cose_sign1 import COSE_SIGN1_TAG, CoseError

#: The deepest level an item may sit at; the top item is level 0.
MAX_DEPTH = 16

#: The smallest value each additional-information width may carry, so a
#: longer form than the value needs is refused (RFC 8949 §4.2.1).
_WIDTH = {24: (1, 24), 25: (2, 1 << 8), 26: (4, 1 << 16), 27: (8, 1 << 32)}

#: Simple values 20, 21 and 22: false, true and null.
_ALLOWED_SIMPLE = (20, 21, 22)


def check(octets: bytes, what: str, *, outer_tag: bool = False) -> None:
    """Raise :class:`CoseError` unless ``octets`` is one CBOR item under the
    receipt encoding rule. ``outer_tag`` admits tag 18 on the top item only."""
    end = _item(octets, 0, 0, outer_tag, what)
    if end != len(octets):
        raise CoseError(f"{what}: trailing octets after the CBOR item")


def _head(octets: bytes, pos: int, what: str):
    """Read one head at ``pos``; return ``(major, argument, next_pos)``."""
    if pos >= len(octets):
        raise CoseError(f"{what}: truncated CBOR")
    initial = octets[pos]
    major, info = initial >> 5, initial & 0x1F
    pos += 1
    if info < 24:
        return major, info, pos
    if info == 31:
        raise CoseError(f"{what}: an indefinite length")
    if info not in _WIDTH:
        raise CoseError(f"{what}: a reserved additional-information value")
    width, smallest = _WIDTH[info]
    if pos + width > len(octets):
        raise CoseError(f"{what}: truncated CBOR")
    argument = int.from_bytes(octets[pos:pos + width], "big")
    # A float has no shortest-form rule of its own here: every float is refused.
    if major != 7 and argument < smallest:
        raise CoseError(f"{what}: an argument longer than its shortest form")
    return major, argument, pos + width


def _item(octets: bytes, pos: int, depth: int, outer_tag: bool, what: str) -> int:
    """Check the item at ``pos`` at nesting ``depth``; return the position after it."""
    if depth > MAX_DEPTH:
        raise CoseError(f"{what}: an item nested more than {MAX_DEPTH} levels deep")
    start = pos
    major, argument, pos = _head(octets, pos, what)
    if major == 0:
        return pos
    if major == 1:
        if argument >= 1 << 63:
            raise CoseError(f"{what}: an integer below -2^63")
        return pos
    if major in (2, 3):
        if argument > len(octets) - pos:
            raise CoseError(f"{what}: truncated CBOR")
        end = pos + argument
        if major == 3:
            try:
                octets[pos:end].decode("utf-8")
            except UnicodeDecodeError:
                raise CoseError(f"{what}: a text string that is not valid UTF-8") from None
        return end
    if major == 4:
        for _ in range(argument):
            pos = _item(octets, pos, depth + 1, False, what)
        return pos
    if major == 5:
        keys = set()
        for _ in range(argument):
            if pos >= len(octets):
                raise CoseError(f"{what}: truncated CBOR")
            if octets[pos] >> 5 not in (0, 1, 3):
                raise CoseError(f"{what}: a map key that is not an integer or a text string")
            key_start = pos
            pos = _item(octets, pos, depth + 1, False, what)
            # Every argument is shortest, so equal keys have equal octets.
            key = octets[key_start:pos]
            if key in keys:
                raise CoseError(f"{what}: a repeated map key")
            keys.add(key)
            pos = _item(octets, pos, depth + 1, False, what)
        return pos
    if major == 6:
        if not (outer_tag and depth == 0 and argument == COSE_SIGN1_TAG):
            raise CoseError(f"{what}: a CBOR tag other than the outer tag 18")
        return _item(octets, pos, depth + 1, False, what)
    # Major type 7: simple values and floats.
    if octets[start] & 0x1F in (25, 26, 27):
        raise CoseError(f"{what}: a float")
    if argument not in _ALLOWED_SIMPLE or octets[start] & 0x1F == 24:
        raise CoseError(f"{what}: a simple value other than false, true and null")
    return pos
