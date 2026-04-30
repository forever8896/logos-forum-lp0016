//! Append-only sorted-pair binary Merkle tree over commitments.
//!
//! Sorted-pair hashing means an inclusion proof is just a list of D sibling
//! hashes — no left/right bits required. This trades one bit per level of
//! commitment-position information for proof simplicity, which is fine
//! because the tree is anonymous (commitments are random) and positions
//! are public anyway (registration order).
//!
//! Empty subtrees are filled with per-level zero hashes (`zero[d]`).

use crate::hash::{h_merkle_leaf, h_merkle_node};
use alloc::vec::Vec;
use forum_core::Hash32;

/// Append-only Merkle tree over commitments. Stores all leaves so any leaf can
/// later receive an inclusion proof. Tree depth `d` is fixed at construction.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: u8,
    /// Hashed leaves: `h_merkle_leaf(commitment_i)` in append order.
    leaves: Vec<Hash32>,
    /// Per-level zero hashes: `zero[0]` = `h_merkle_leaf(0³²)`, etc.
    zero: Vec<Hash32>,
}

/// Sibling path from leaf to root. `siblings[i]` is the sibling hash at level
/// `i` (level 0 = leaf level). Tree depth = `siblings.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub siblings: Vec<Hash32>,
    pub leaf_index: u32,
}

impl MerkleTree {
    /// Empty tree of depth `d`. Capacity = `2^d` leaves.
    pub fn new(depth: u8) -> Self {
        assert!(depth >= 1 && depth <= 32, "tree depth out of range");
        let mut zero = Vec::with_capacity(depth as usize);
        zero.push(h_merkle_leaf(&[0u8; 32]));
        for i in 1..(depth as usize) {
            let z = zero[i - 1];
            zero.push(h_merkle_node(&z, &z));
        }
        Self {
            depth,
            leaves: Vec::new(),
            zero,
        }
    }

    /// Append a single commitment. Returns the leaf index.
    pub fn append(&mut self, commitment: &Hash32) -> u32 {
        let idx = self.leaves.len() as u32;
        assert!((idx as u64) < (1u64 << self.depth), "tree full");
        self.leaves.push(h_merkle_leaf(commitment));
        idx
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Compute the current root by walking up the implicit complete tree,
    /// filling missing siblings with zero hashes.
    pub fn root(&self) -> Hash32 {
        let mut layer: Vec<Hash32> = self.leaves.clone();
        if layer.is_empty() {
            // All-zero tree: the root is the top zero hash.
            // For depth 1 the root is zero[0] (one level above leaf? no — for
            // depth 1 the root *is* the level-0 hash). Actually: by our
            // convention, depth = number of hashing levels between leaf and
            // root. So for an empty tree the root is `zero[depth-1]`.
            return self.zero[self.depth as usize - 1];
        }
        for level in 0..(self.depth as usize) {
            if layer.len() % 2 == 1 {
                layer.push(self.zero[level]);
            }
            let mut next = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                next.push(h_merkle_node(&chunk[0], &chunk[1]));
            }
            layer = next;
        }
        debug_assert_eq!(layer.len(), 1);
        layer[0]
    }

    /// Produce an inclusion proof for the leaf at the given index.
    pub fn proof(&self, leaf_index: u32) -> Option<MerkleProof> {
        if (leaf_index as usize) >= self.leaves.len() {
            return None;
        }
        let mut layer: Vec<Hash32> = self.leaves.clone();
        let mut idx = leaf_index as usize;
        let mut siblings: Vec<Hash32> = Vec::with_capacity(self.depth as usize);

        for level in 0..(self.depth as usize) {
            if layer.len() % 2 == 1 {
                layer.push(self.zero[level]);
            }
            let sibling_idx = idx ^ 1; // partner under sorted-pair hashing
            siblings.push(layer[sibling_idx]);
            // Compute next layer.
            let mut next = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                next.push(h_merkle_node(&chunk[0], &chunk[1]));
            }
            layer = next;
            idx /= 2;
        }
        Some(MerkleProof {
            siblings,
            leaf_index,
        })
    }
}

/// Verify a sorted-pair Merkle inclusion proof for `commitment`.
pub fn verify_inclusion(commitment: &Hash32, root: &Hash32, proof: &MerkleProof) -> bool {
    let mut node = h_merkle_leaf(commitment);
    for sib in &proof.siblings {
        node = h_merkle_node(&node, sib);
    }
    node == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_root_is_deterministic() {
        let t1 = MerkleTree::new(8);
        let t2 = MerkleTree::new(8);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn proof_round_trip_single_leaf() {
        let mut t = MerkleTree::new(4);
        let c = [42u8; 32];
        let idx = t.append(&c);
        let root = t.root();
        let proof = t.proof(idx).unwrap();
        assert!(verify_inclusion(&c, &root, &proof));
    }

    #[test]
    fn proof_round_trip_many_leaves() {
        let mut t = MerkleTree::new(6);
        let leaves: Vec<Hash32> = (0..23).map(|i| [i as u8; 32]).collect();
        let mut indices = Vec::new();
        for c in &leaves {
            indices.push(t.append(c));
        }
        let root = t.root();
        for (i, c) in leaves.iter().enumerate() {
            let proof = t.proof(indices[i]).unwrap();
            assert!(verify_inclusion(c, &root, &proof), "leaf {} failed", i);
        }
    }

    #[test]
    fn rejects_wrong_commitment() {
        let mut t = MerkleTree::new(4);
        let c = [1u8; 32];
        t.append(&c);
        let root = t.root();
        let proof = t.proof(0).unwrap();
        let bad = [2u8; 32];
        assert!(!verify_inclusion(&bad, &root, &proof));
    }

    #[test]
    fn rejects_wrong_root() {
        let mut t = MerkleTree::new(4);
        t.append(&[1u8; 32]);
        let proof = t.proof(0).unwrap();
        let fake_root = [0xFFu8; 32];
        assert!(!verify_inclusion(&[1u8; 32], &fake_root, &proof));
    }
}
