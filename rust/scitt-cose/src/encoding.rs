//! The receipt encoding rule, checked on raw octets.
//!
//! agent-action-capsule's interop profile v1 §6.2.2 states one rule for the
//! CBOR of a COSE Receipt, so that every verifier decides the same octets the
//! same way: the COSE_Sign1, its protected header and each inclusion-proof
//! blob are each one CBOR item with no trailing octet, definite lengths,
//! every argument in its shortest form, no repeated map key, every integer
//! from -2^63 to 2^64 - 1, every map key an integer or a text string, every
//! text string valid UTF-8, no float, no simple value but `false`, `true` and
//! `null`, no tag but the outer tag 18, and no item nested more than 16
//! levels deep (an item inside an array, a map or a tag is one level deeper).
//! Map order is not checked.
//!
//! This walks the octets itself rather than asking ciborium, so the decision
//! does not depend on how a CBOR library reads tags, floats or simple values.
//! The Python package (`scitt_cose/_encoding_rule.py`) and the Go verifier
//! (`scitt-cose-go-verify/encoding.go`) carry the same walk.

use std::collections::HashSet;

/// The deepest level an item may sit at; the top item is level 0.
pub const MAX_DEPTH: usize = 16;

const COSE_SIGN1_TAG: u64 = 18;

/// Check that `octets` is one CBOR item under the receipt encoding rule.
/// `outer_tag` admits tag 18 on the top item only. The error names the
/// clause that failed, prefixed with `what`.
pub fn check(octets: &[u8], what: &str, outer_tag: bool) -> Result<(), String> {
    let end = item(octets, 0, 0, outer_tag).map_err(|e| format!("{what}: {e}"))?;
    if end != octets.len() {
        return Err(format!("{what}: trailing octets after the CBOR item"));
    }
    Ok(())
}

/// Read one head at `pos`: (major type, additional information, argument,
/// next position).
fn head(octets: &[u8], pos: usize) -> Result<(u8, u8, u64, usize), &'static str> {
    let initial = *octets.get(pos).ok_or("truncated CBOR")?;
    let (major, info) = (initial >> 5, initial & 0x1f);
    let pos = pos + 1;
    let (width, smallest) = match info {
        0..=23 => return Ok((major, info, u64::from(info), pos)),
        24 => (1, 24),
        25 => (2, 1 << 8),
        26 => (4, 1 << 16),
        27 => (8, 1 << 32),
        31 => return Err("an indefinite length"),
        _ => return Err("a reserved additional-information value"),
    };
    let bytes = octets.get(pos..pos + width).ok_or("truncated CBOR")?;
    let argument = bytes.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    // A float has no shortest-form rule of its own here: every float is refused.
    if major != 7 && argument < smallest {
        return Err("an argument longer than its shortest form");
    }
    Ok((major, info, argument, pos + width))
}

/// Check the item at `pos` at nesting `depth`; return the position after it.
fn item(octets: &[u8], pos: usize, depth: usize, outer_tag: bool) -> Result<usize, &'static str> {
    if depth > MAX_DEPTH {
        return Err("an item nested more than 16 levels deep");
    }
    let (major, info, argument, pos) = head(octets, pos)?;
    match major {
        0 => Ok(pos),
        1 if argument >= 1 << 63 => Err("an integer below -2^63"),
        1 => Ok(pos),
        2 | 3 => {
            let len = usize::try_from(argument).map_err(|_| "truncated CBOR")?;
            if len > octets.len() - pos {
                return Err("truncated CBOR");
            }
            let end = pos + len;
            if major == 3 && std::str::from_utf8(&octets[pos..end]).is_err() {
                return Err("a text string that is not valid UTF-8");
            }
            Ok(end)
        }
        4 => {
            let mut pos = pos;
            for _ in 0..argument {
                pos = item(octets, pos, depth + 1, false)?;
            }
            Ok(pos)
        }
        5 => {
            let mut pos = pos;
            let mut keys = HashSet::new();
            for _ in 0..argument {
                let initial = *octets.get(pos).ok_or("truncated CBOR")?;
                if !matches!(initial >> 5, 0 | 1 | 3) {
                    return Err("a map key that is not an integer or a text string");
                }
                let key_start = pos;
                pos = item(octets, pos, depth + 1, false)?;
                // Every argument is shortest, so equal keys have equal octets.
                if !keys.insert(&octets[key_start..pos]) {
                    return Err("a repeated map key");
                }
                pos = item(octets, pos, depth + 1, false)?;
            }
            Ok(pos)
        }
        6 => {
            if !(outer_tag && depth == 0 && argument == COSE_SIGN1_TAG) {
                return Err("a CBOR tag other than the outer tag 18");
            }
            item(octets, pos, depth + 1, false)
        }
        _ => match info {
            25..=27 => Err("a float"),
            20..=22 => Ok(pos),
            _ => Err("a simple value other than false, true and null"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::check;

    fn nest(depth: usize) -> Vec<u8> {
        let mut v = vec![0x81; depth];
        v.push(0x00);
        v
    }

    #[test]
    fn accepts_what_the_rule_allows() {
        let mut max_u64 = vec![0x1b];
        max_u64.extend([0xff; 8]);
        let mut min_i64 = vec![0x3b, 0x7f];
        min_i64.extend([0xff; 7]);
        for octets in [
            max_u64,
            min_i64,
            vec![0x83, 0xf4, 0xf5, 0xf6],
            vec![0xa2, 0x61, b'a', 0x01, 0x01, 0x02],
            vec![0x62, 0xc3, 0xa9],
            nest(16),
            vec![0x82, 0x80, 0xa0],
        ] {
            assert_eq!(check(&octets, "item", false), Ok(()), "{octets:02x?}");
        }
    }

    #[test]
    fn refuses_each_clause() {
        let mut below_i64 = vec![0x3b, 0x80];
        below_i64.extend([0; 7]);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (vec![0x9f, 0x00, 0xff], "indefinite"),
            (vec![0x5f, 0x41, 0x00, 0xff], "indefinite"),
            (vec![0x18, 0x17], "shortest"),
            (vec![0x59, 0x00, 0x01, 0x00], "shortest"),
            (vec![0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], "shortest"),
            (below_i64, "below -2^63"),
            (vec![0xa2, 0x01, 0x00, 0x01, 0x00], "repeated"),
            (vec![0xa1, 0x41, 0x00, 0x00], "map key"),
            (vec![0xa1, 0x80, 0x00], "map key"),
            (vec![0xa1, 0xf9, 0x7e, 0x00, 0x00], "map key"),
            (vec![0x61, 0xff], "UTF-8"),
            (vec![0xf9, 0x3c, 0x00], "float"),
            (vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0], "float"),
            (vec![0xf7], "simple value"),
            (vec![0xe0], "simple value"),
            (vec![0xf8, 0x20], "simple value"),
            (vec![0xc1, 0x00], "tag"),
            (vec![0xc2, 0x41, 0x01], "tag"),
            (vec![0x1c], "reserved"),
            (nest(17), "16 levels"),
            (vec![0x00, 0x00], "trailing"),
            (vec![0x82, 0x00], "truncated"),
            (vec![0x5a, 0xff, 0xff, 0xff, 0xff], "truncated"),
            (vec![], "truncated"),
        ];
        for (octets, needle) in cases {
            let err = check(&octets, "item", false).expect_err(needle);
            assert!(err.contains(needle), "{octets:02x?}: {err}");
        }
    }

    #[test]
    fn tag_18_only_on_the_top_item() {
        let sign1 = [0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40];
        assert_eq!(check(&sign1, "item", true), Ok(()));
        assert!(check(&sign1, "item", false).is_err());
        let mut inner = vec![0x81];
        inner.extend(sign1);
        assert!(check(&inner, "item", true).is_err());
        assert!(check(&[0xd1, 0x84, 0x40, 0xa0, 0xf6, 0x40], "item", true).is_err());
    }
}
