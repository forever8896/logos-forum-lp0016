//! Domain-tagged SHA-256 helpers. Every protocol-level hash goes through one
//! of these wrappers so the domain separation is impossible to forget.

use crate::domain;
use forum_core::Hash32;
use sha2::{Digest, Sha256};

/// `H(domain(tag) || piece_1 || ... || piece_n)`.
pub fn h_tagged(tag_name: &str, pieces: &[&[u8]]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(domain::tag(tag_name));
    for p in pieces {
        h.update(p);
    }
    h.finalize().into()
}

/// `min(a,b) || max(a,b)` then hash with `merkle-node` tag — used for
/// sorted-pair internal Merkle nodes.
pub fn h_merkle_node(a: &Hash32, b: &Hash32) -> Hash32 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    h_tagged(domain::MERKLE_NODE, &[lo, hi])
}

/// Leaf hash for the membership tree.
pub fn h_merkle_leaf(commitment: &Hash32) -> Hash32 {
    h_tagged(domain::MERKLE_LEAF, &[commitment])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_node_is_commutative() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(h_merkle_node(&a, &b), h_merkle_node(&b, &a));
    }

    #[test]
    fn distinct_inputs_give_distinct_hashes() {
        assert_ne!(h_merkle_leaf(&[0u8; 32]), h_merkle_leaf(&[1u8; 32]));
        assert_ne!(
            h_merkle_leaf(&[0u8; 32]),
            h_merkle_node(&[0u8; 32], &[0u8; 32])
        );
    }
}
