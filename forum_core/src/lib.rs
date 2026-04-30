//! Wire types shared between the SPEL guest, the moderation library, and the
//! UI plugin's FFI. Anything that crosses the host/guest boundary or shows up
//! in the on-chain account schema lives here.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Domain tag for SHA-256 inputs across the protocol. Each callsite extends it
/// with a sub-tag (e.g. `"commitment"`, `"merkle-leaf"`). Keep in sync with
/// `forum_moderation::domain`.
pub const DOMAIN_PREFIX: &str = "/logos-forum/v1/";

/// 32-byte SHA-256 digest used for commitments, Merkle nodes, and similar.
pub type Hash32 = [u8; 32];

/// 33-byte SEC1-compressed secp256k1 point. Used for the moderator threshold
/// public key, decryption shares, and ciphertext components.
pub type CompressedPoint = [u8; 33];

/// 32-byte big-endian secp256k1 scalar. Used for Shamir abscissas/ordinates,
/// secret keys, and individual mod key shares.
pub type Scalar32 = [u8; 32];

/// Forum-instance parameters. Fixed at instance creation; never mutated.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct InstanceParams {
    /// Strikes-to-revoke. Same K used for the Shamir polynomial degree (K-1)
    /// and for the slash-reconstruction threshold.
    pub k: u8,
    /// Mods-to-issue-strike (threshold for the ElGamal decryption).
    pub n: u8,
    /// Total moderators (M). The forum creator hands `m` shares to `m`
    /// moderators at instance creation.
    pub m: u8,
    /// Merkle tree depth. Membership capacity is `2^d`.
    pub d: u8,
    /// Stake (LEZ native token) locked at registration, forfeited on slash.
    pub stake_amount: u128,
    /// Threshold ElGamal public key Q = [d]G as 33-byte compressed point.
    #[serde(with = "BigArray")]
    pub mod_pubkey: CompressedPoint,
    /// SHA-256 hash of the canonical-encoded list of moderator long-lived
    /// signing pubkeys (see `ModeratorRoster`). Mods are pinned at instance
    /// creation; rotation requires a new instance.
    pub moderator_roster_hash: Hash32,
    /// Human-readable instance name; UI hint only, not security-sensitive.
    pub label: String,
}

/// The list of moderator signing pubkeys. Hashed into `InstanceParams.moderator_roster_hash`.
///
/// Wire form uses `Vec<u8>` (concatenated 33-byte points) to side-step
/// serde's lack of >32-byte fixed-array support without dragging in
/// `serde-big-array` everywhere. Use [`ModeratorRoster::points`] to access
/// individual entries.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ModeratorRoster {
    /// Concatenated 33-byte SEC1-compressed points. `entries.len() % 33 == 0`.
    pub entries: Vec<u8>,
}

impl ModeratorRoster {
    pub fn from_points(points: &[CompressedPoint]) -> Self {
        let mut entries = Vec::with_capacity(points.len() * 33);
        for p in points {
            entries.extend_from_slice(p);
        }
        Self { entries }
    }

    pub fn count(&self) -> usize {
        self.entries.len() / 33
    }

    pub fn point(&self, index: usize) -> Option<CompressedPoint> {
        let start = index * 33;
        let end = start + 33;
        if end > self.entries.len() {
            return None;
        }
        let mut out = [0u8; 33];
        out.copy_from_slice(&self.entries[start..end]);
        Some(out)
    }
}

/// On-chain registry state PDA contents. One per forum instance. Field names
/// must match `methods/guest/src/bin/forum_registry.rs` exactly because the
/// guest borsh-decodes into this same struct.
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ForumInstanceState {
    /// Bytes of `InstanceParams` borsh-encoded; decoded by clients via the
    /// SPEL IDL. Stored opaquely here to keep the guest small.
    pub params_blob: Vec<u8>,
    /// Bytes of `ModeratorRoster` borsh-encoded.
    pub roster_blob: Vec<u8>,
    /// Current Merkle root of the membership tree (32 bytes).
    pub member_root: Hash32,
    /// Number of registered (non-revoked) members. Bounded by `2^d`.
    pub member_count: u64,
    /// Pooled stake currently locked in the registry account.
    pub pooled_stake: u128,
    /// Length of `revocation_list`. Capped at the moment by data-size budget.
    pub revocation_count: u32,
    /// Flat list of slashed commitments. v0.1: linear scan. v0.2: SMT.
    pub revocation_list: Vec<Hash32>,
}

/// One off-chain post broadcast over Logos Delivery on `/logos-forum/1/<instance>/posts/v1`.
/// Opaque to the moderation library — the application defines the meaning of
/// `payload`. The library only computes hashes over `(msg_id, payload, enc_share)`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct PostEnvelope {
    pub msg_id: Hash32,
    pub payload: Vec<u8>,
    /// Member-tree root the author saw at post time. Receivers verify the
    /// proof against THIS root, not necessarily the most recent on-chain one
    /// (the proof may have been generated against an older root).
    pub root_seen: Hash32,
    /// Threshold-ElGamal ciphertext over the Shamir share `(x_i, y_i)`.
    pub enc_share: EncryptedShare,
    /// RISC0 receipt — bytes deserialized as `risc0_zkvm::Receipt`.
    pub proof_bytes: Vec<u8>,
}

/// Ciphertext over a Shamir share: ElGamal `(c1, c2)` where `c1` is a
/// secp256k1 point and `c2` is a 64-byte XOR-pad output (Scalar32 || Scalar32).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EncryptedShare {
    #[serde(with = "BigArray")]
    pub c1: CompressedPoint,
    #[serde(with = "BigArray")]
    pub c2: [u8; 64],
}

/// One moderator's contribution to deciphering a post's encrypted share.
/// Broadcast over `/logos-forum/1/<instance>/certs/v1` after the moderator
/// votes for moderation.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct CertificateShare {
    pub instance_id: Hash32,
    /// `H(domain("cert") || msg_id || payload || enc_share)`.
    pub post_hash: Hash32,
    /// `D_j = [d_j] c1` as a compressed point.
    #[serde(with = "BigArray")]
    pub decryption_share: CompressedPoint,
    /// 1-indexed moderator index `α_j ∈ {1..m}`.
    pub moderator_index: u8,
    /// Ed25519/Schnorr signature over `(post_hash || α_j || D_j)`.
    pub signature: Vec<u8>,
}

/// Aggregated certificate: result of combining ≥ N `CertificateShare`s.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct Certificate {
    pub instance_id: Hash32,
    pub post_hash: Hash32,
    pub enc_share: EncryptedShare,
    /// Recovered Shamir point.
    pub x_i: Scalar32,
    pub y_i: Scalar32,
    /// Underlying shares in case anyone wants to re-verify the aggregation.
    pub shares: Vec<CertificateShare>,
}
