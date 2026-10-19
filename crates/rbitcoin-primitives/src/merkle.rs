//! Bitcoin block merkle root from leaf txids (internal byte order).
//!
//! The mutation flag is Core's `ComputeMerkleRoot` check (CVE-2012-2459):
//! some level held two equal hashes in one pair before odd padding, so a
//! shorter tx list has the same root.

use bitcoin_hashes::{sha256, Hash, HashEngine};

/// Bitcoin block merkle root from leaf txids (internal byte order).
pub fn merkle_root_from_txids(leaves: &[[u8; 32]]) -> [u8; 32] {
    merkle_root_mutated(leaves).0
}

/// [`merkle_root_from_txids`] plus Core's `ComputeMerkleRoot` mutation flag
/// (CVE-2012-2459).
// btc-lean: BLK-007
pub fn merkle_root_mutated(leaves: &[[u8; 32]]) -> ([u8; 32], bool) {
    // btc-lean: BLK-013
    if leaves.is_empty() {
        return ([0u8; 32], false);
    }
    let mut mutated = false;
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        // btc-lean: BLK-011
        mutated |= level.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        level = merkle_parent_level(level);
    }
    (level[0], mutated)
}

/// Sibling hashes from `leaves[index]` up to the root, deepest first. Empty for
/// one leaf. Folding the leaf with them (left when the index bit is 0)
/// reproduces [`merkle_root_from_txids`]. The leaf's own value feeds no entry.
// btc-lean: BLK-129
pub fn merkle_branch(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let sibling = (index ^ 1).min(level.len() - 1);
        branch.push(level[sibling]);
        level = merkle_parent_level(level);
        index /= 2;
    }
    branch
}

/// Root reached by folding `leaf` at `index` with its [`merkle_branch`]. The
/// leaf is the left child when the index bit at that depth is 0.
pub fn merkle_root_from_branch(leaf: [u8; 32], branch: &[[u8; 32]], index: usize) -> [u8; 32] {
    branch
        .iter()
        .enumerate()
        .fold(leaf, |acc, (depth, sibling)| {
            if (index >> depth) & 1 == 0 {
                hash256_concat(&acc, sibling)
            } else {
                hash256_concat(sibling, &acc)
            }
        })
}

fn merkle_parent_level(mut level: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    if level.len() % 2 == 1 {
        // btc-lean: BLK-008
        level.push(level[level.len() - 1]);
    }
    level
        .chunks_exact(2)
        .map(|pair| hash256_concat(&pair[0], &pair[1]))
        .collect()
}

// btc-lean: BLK-009
fn hash256_concat(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut eng = sha256::HashEngine::default();
    eng.input(a);
    eng.input(b);
    let mid = sha256::Hash::from_engine(eng);
    let mut eng2 = sha256::HashEngine::default();
    eng2.input(mid.as_byte_array());
    sha256::Hash::from_engine(eng2).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_single_and_pair() {
        let a = [1u8; 32];
        assert_eq!(merkle_root_from_txids(&[a]), a);
        let b = [2u8; 32];
        let root = merkle_root_from_txids(&[a, b]);
        assert_eq!(root, hash256_concat(&a, &b));
    }

    /// CVE-2012-2459: a repeated tail at any level keeps the root and is
    /// flagged. The shorter list and an unpaired repeat are not.
    #[test]
    // btc-lean: BLK-007 BLK-008 BLK-009 BLK-011 BLK-013 BLK-014 BLK-129
    fn merkle_mutation_flags_a_repeated_tail_at_any_level() {
        let l: Vec<[u8; 32]> = (1..=6u8).map(|n| [n; 32]).collect();
        let (root3, mutated) = merkle_root_mutated(&l[..3]);
        assert!(!mutated);
        assert_eq!(
            merkle_root_mutated(&[l[0], l[1], l[2], l[2]]),
            (root3, true)
        );
        assert!(!merkle_root_mutated(&[l[0], l[1], l[1]]).1);

        let (root6, mutated) = merkle_root_mutated(&l);
        assert!(!mutated);
        let mut tail = l.clone();
        tail.extend_from_slice(&l[4..]);
        assert_eq!(merkle_root_mutated(&tail), (root6, true));
        assert_eq!(merkle_root_mutated(&[]), ([0u8; 32], false));
    }

    #[test]
    fn merkle_path_folds_to_root_at_every_index() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        assert!(merkle_branch(&[a], 0).is_empty());
        assert_eq!(merkle_branch(&[a, b], 0), vec![b]);
        assert_eq!(
            merkle_branch(&[a, b, c], 0),
            vec![b, hash256_concat(&c, &c)]
        );
        assert_eq!(
            merkle_branch(&[a, b, c], 2),
            vec![c, hash256_concat(&a, &b)]
        );
        for n in 1..=9u8 {
            let leaves: Vec<[u8; 32]> = (0..n).map(|i| [i + 10; 32]).collect();
            let root = merkle_root_from_txids(&leaves);
            for (index, leaf) in leaves.iter().enumerate() {
                let branch = merkle_branch(&leaves, index);
                assert_eq!(
                    merkle_root_from_branch(*leaf, &branch, index),
                    root,
                    "n={n} index={index}"
                );
            }
        }
    }
}
