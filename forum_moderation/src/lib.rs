//! `forum_moderation` — a forum-agnostic library for anonymous moderated
//! posting with K-strike cryptographic revocation.
//!
//! See `docs/protocol.md` (top-level repo doc) for the full specification.
//! This crate exposes eight modules; only `pub` items are part of the API.
//!
//! Module map:
//! - [`domain`] — domain-separation tags used everywhere SHA-256 is invoked.
//! - [`hash`] — wrappers over `sha2::Sha256` that take domain-tagged inputs.
//! - [`scalar`] — secp256k1 scalar conversion helpers (32-byte BE ↔ k256).
//! - [`commitment`] — derive a member commitment `C` from `(sk, a₁..a_{K-1})`.
//! - [`merkle`] — append-only sorted-pair binary Merkle tree.
//! - [`shamir`] — degree-(K-1) polynomial eval and Lagrange interpolation.
//! - [`threshold_elgamal`] — IND-CPA threshold ElGamal over secp256k1.
//! - [`certificate`] — aggregating N share decryptions into one cert.
//! - [`slash`] — searching K-subsets and reconstructing a candidate commitment.
//! - [`identity`] — a member's keypair + polynomial bundle.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod certificate;
pub mod commitment;
pub mod domain;
pub mod hash;
pub mod identity;
pub mod merkle;
pub mod scalar;
pub mod shamir;
pub mod slash;
pub mod threshold_elgamal;

pub use certificate::{aggregate_certificate, build_share, verify_share, AggregateError};
pub use commitment::{commitment_from_secret, MemberCommitment};
pub use forum_core::{
    Certificate, CertificateShare, CompressedPoint, EncryptedShare, ForumInstanceState, Hash32,
    InstanceParams, ModeratorRoster, PostEnvelope, Scalar32,
};
pub use identity::{MemberIdentity, RegistrationPacket};
pub use merkle::{MerkleProof, MerkleTree};
pub use shamir::Polynomial;
pub use slash::{find_slash_candidates, SlashCandidate};
pub use threshold_elgamal::{
    decrypt_with_shares, encrypt_share, generate_threshold_key, DecryptionShareSet,
    ThresholdKeySet,
};

/// Library-level error type. Each submodule wraps its specific failure into
/// this enum so callers don't need to import every internal error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Bytes didn't decode as a secp256k1 scalar (out of range or zero).
    InvalidScalar,
    /// Bytes didn't decode as a secp256k1 point (bad encoding or off-curve).
    InvalidPoint,
    /// A Merkle proof failed to reproduce the expected root.
    BadMerkleProof,
    /// Polynomial degree mismatch during interpolation.
    DegreeMismatch,
    /// `K` certificates were not provided to `find_slash_candidates`.
    InsufficientShares,
    /// Threshold cryptography parameter out of range (e.g. N>M).
    InvalidThreshold,
    /// Decryption share didn't aggregate to a valid plaintext.
    DecryptionFailed,
    /// Aggregating fewer than N shares.
    NotEnoughShares { have: usize, need: usize },
    /// A signature failed to verify on a CertificateShare.
    BadSignature,
    /// Commitment recovered from K shares didn't appear in the membership tree.
    CommitmentNotInTree,
    /// Internal serialization failure (borsh).
    Serialization,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
