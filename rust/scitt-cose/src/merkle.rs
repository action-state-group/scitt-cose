//! RFC 6962 / RFC 9162 SHA-256 Merkle-tree inclusion-proof reconstruction
//! (clean-room port of the Python reference's `scitt_cose.merkle`).
//!
//! Only the verifier side is ported here (`root_from_inclusion_proof`) -- this
//! crate never mints a tree or a proof, only checks one against a claimed
//! leaf entry.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Largest tree size a verifier will entertain from an attacker-supplied
/// proof. `2**62` is the largest power of two representable as a positive
/// `i64`, so this is the exact ceiling the Python and Go verifiers share --
/// there is no `tree_size` band one accepts and another cannot represent.
/// It also bounds the fold's recursion depth to at most 62.
pub const MAX_TREE_SIZE: u64 = 1 << 62;

fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(entry);
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// k = largest power of two strictly less than n (requires n > 1).
fn largest_pow2_below(n: u64) -> u64 {
    let mut k: u64 = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Exact number of audit-path siblings for `index` in an RFC 6962 tree of
/// `tree_size` entries -- the leaf's depth under the recursive split.
fn expected_inclusion_path_len(tree_size: u64, index: u64) -> u64 {
    let mut n = 0u64;
    let (mut size, mut m) = (tree_size, index);
    while size > 1 {
        let k = largest_pow2_below(size);
        if m < k {
            size = k;
        } else {
            size -= k;
            m -= k;
        }
        n += 1;
    }
    n
}

/// Fold `leaf_entry` up its RFC 6962 §2.1.1 audit path to the root, or
/// `None` if `index`/`tree_size`/the path length is inconsistent.
///
/// Resource safety: `tree_size` is rejected above [`MAX_TREE_SIZE`], and the
/// audit path must be exactly the expected length for `(tree_size, index)`
/// *before* any hashing -- so a hostile `tree_size` or over-long path can
/// neither forge an inclusion nor exhaust the stack.
pub fn root_from_inclusion_proof(
    leaf_entry: &[u8],
    index: u64,
    tree_size: u64,
    audit_path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if tree_size == 0 || index >= tree_size || tree_size > MAX_TREE_SIZE {
        return None;
    }
    if audit_path.len() as u64 != expected_inclusion_path_len(tree_size, index) {
        return None;
    }
    let target = leaf_hash(leaf_entry);
    // Consumed outermost-first, mirroring the Python reference's `siblings.pop()`.
    let mut siblings: Vec<[u8; 32]> = audit_path.to_vec();

    fn fold(
        size: u64,
        m: u64,
        target: &[u8; 32],
        siblings: &mut Vec<[u8; 32]>,
    ) -> Option<[u8; 32]> {
        if size == 1 {
            return Some(*target);
        }
        let sibling = siblings.pop()?;
        let k = largest_pow2_below(size);
        if m < k {
            let child = fold(k, m, target, siblings)?;
            Some(node_hash(&child, &sibling))
        } else {
            let child = fold(size - k, m - k, target, siblings)?;
            Some(node_hash(&sibling, &child))
        }
    }

    let computed = fold(tree_size, index, &target, &mut siblings)?;
    if !siblings.is_empty() {
        return None;
    }
    Some(computed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a full tree by hand (small n) and confirm inclusion-proof
    /// reconstruction agrees with a direct top-down Merkle Tree Hash (MTH),
    /// independent of `root_from_inclusion_proof`'s own recursion.
    fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        let n = leaves.len();
        if n == 1 {
            return leaves[0];
        }
        let k = largest_pow2_below(n as u64) as usize;
        node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
    }

    fn inclusion_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
        fn path(sub: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
            if sub.len() == 1 {
                return vec![];
            }
            let k = largest_pow2_below(sub.len() as u64) as usize;
            if m < k {
                let mut p = path(&sub[..k], m);
                p.push(mth(&sub[k..]));
                p
            } else {
                let mut p = path(&sub[k..], m - k);
                p.push(mth(&sub[..k]));
                p
            }
        }
        path(leaves, index)
    }

    #[test]
    fn reconstructs_root_for_every_leaf_of_an_8_entry_tree() {
        let entries: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 4]).collect();
        let leaves: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();
        let root = mth(&leaves);
        for (i, entry) in entries.iter().enumerate() {
            let path = inclusion_path(&leaves, i);
            let got = root_from_inclusion_proof(entry, i as u64, 8, &path).unwrap();
            assert_eq!(got, root, "leaf {i}");
        }
    }

    #[test]
    fn tampered_path_does_not_reconstruct() {
        let entries: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 4]).collect();
        let leaves: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();
        let root = mth(&leaves);
        let mut path = inclusion_path(&leaves, 2);
        path[0][0] ^= 0xff;
        let got = root_from_inclusion_proof(&entries[2], 2, 8, &path).unwrap();
        assert_ne!(got, root);
    }

    #[test]
    fn oversized_tree_size_is_rejected_before_hashing() {
        assert!(root_from_inclusion_proof(b"x", 0, MAX_TREE_SIZE + 1, &[]).is_none());
    }

    #[test]
    fn wrong_path_length_is_rejected() {
        let entries: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 4]).collect();
        let leaves: Vec<[u8; 32]> = entries.iter().map(|e| leaf_hash(e)).collect();
        let mut path = inclusion_path(&leaves, 2);
        path.push([0u8; 32]);
        assert!(root_from_inclusion_proof(&entries[2], 2, 8, &path).is_none());
    }

    #[test]
    fn index_out_of_range_is_rejected() {
        assert!(root_from_inclusion_proof(b"x", 8, 8, &[]).is_none());
    }
}
