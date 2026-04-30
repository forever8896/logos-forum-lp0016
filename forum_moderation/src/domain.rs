//! Domain separation tags. Every SHA-256 input in the protocol gets prefixed
//! with one of these — it ensures hashes computed for different purposes
//! cannot be confused for one another even if their inputs collide.
//!
//! Protocol freezes these strings: changing one is a hard fork.

use forum_core::DOMAIN_PREFIX;

/// 32-byte SHA-256 of `DOMAIN_PREFIX || sub_tag`. Computed once per call site.
pub fn tag(sub: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(DOMAIN_PREFIX.as_bytes());
    h.update(sub.as_bytes());
    h.finalize().into()
}

pub const COMMITMENT: &str = "commitment";
pub const MERKLE_LEAF: &str = "merkle-leaf";
pub const MERKLE_NODE: &str = "merkle-node";
pub const NULLIFIER: &str = "nullifier";
pub const SHARE_KDF: &str = "share";
pub const CERT_HASH: &str = "cert";
pub const CERT_SIG: &str = "cert-sig";
pub const SLASH_BINDING: &str = "slash-binding";
pub const REVOCATION_HASH: &str = "revocation";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_distinct() {
        let all = [
            COMMITMENT,
            MERKLE_LEAF,
            MERKLE_NODE,
            NULLIFIER,
            SHARE_KDF,
            CERT_HASH,
            CERT_SIG,
            SLASH_BINDING,
            REVOCATION_HASH,
        ];
        let tags: alloc::vec::Vec<_> = all.iter().map(|s| tag(s)).collect();
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(tags[i], tags[j], "tags {} and {} collide", all[i], all[j]);
            }
        }
    }
}
