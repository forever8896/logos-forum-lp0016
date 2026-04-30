//! Threshold ElGamal over secp256k1.
//!
//! Setup (run once at forum-instance creation):
//! - Sample master scalar `d`. Compute `Q = [d]G`.
//! - Use Shamir to split `d` into `M` shares `(α_j, d_j)`. Hand `(α_j, d_j)`
//!   privately to moderator `j`.
//!
//! Encryption (anyone with `Q`, message `m ∈ {0,1}^64`):
//! - Sample `r ∈ 𝔽`. Compute `c1 = [r]G`, `c2 = m ⊕ KDF([r]Q)`.
//!
//! Decryption (any `t ≥ N` moderators):
//! - Each emits `D_j = [d_j] c1`.
//! - Combine: `[d] c1 = Σ λ_j(0) · D_j` over `j ∈ T`.
//! - Recover `m = c2 ⊕ KDF([d]c1)`.
//!
//! KDF is `H(domain("share") || x_coord)` expanded to 64 bytes via two SHA-256s.

use crate::{domain, hash::h_tagged, scalar, shamir, Error};
use alloc::vec::Vec;
use forum_core::{CompressedPoint, EncryptedShare, Hash32, Scalar32};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Field;
use k256::{ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};

/// The full set of moderator key shares + the public key. Returned by
/// `generate_threshold_key` to the forum creator.
pub struct ThresholdKeySet {
    /// Threshold ElGamal public key Q = [d]G (compressed).
    pub public_key: CompressedPoint,
    /// `[(α_j, d_j); j=1..M]`. Index 0 = moderator with α=1.
    pub shares: Vec<(u8, Scalar32)>,
    /// The master `d`, returned for testability and (rare) backup. **Should
    /// be discarded by the forum creator immediately after distribution** —
    /// its presence breaks the threshold property.
    pub master_secret: Scalar32,
}

/// A set of moderator-emitted decryption shares for one ciphertext.
pub struct DecryptionShareSet {
    pub shares: Vec<(u8, CompressedPoint)>,
}

/// Generate a threshold ElGamal key with N-of-M moderators.
pub fn generate_threshold_key<R: RngCore + CryptoRng>(
    n: u8,
    m: u8,
    rng: &mut R,
) -> Result<ThresholdKeySet, Error> {
    if n == 0 || n > m || m > 64 {
        return Err(Error::InvalidThreshold);
    }
    // Master secret + N-1 random coefficients = polynomial of degree N-1.
    let d = Scalar::random(&mut *rng);
    let poly = shamir::Polynomial::random_with_secret(d, (n as usize) - 1, rng);

    let mut shares = Vec::with_capacity(m as usize);
    for j in 1..=m {
        let alpha = Scalar::from(j as u64);
        let d_j = poly.eval(&alpha);
        shares.push((j, scalar::scalar_to_bytes(&d_j)));
    }

    let q = ProjectivePoint::GENERATOR * d;
    let q_bytes = scalar::point_to_bytes(&q);

    Ok(ThresholdKeySet {
        public_key: q_bytes,
        shares,
        master_secret: scalar::scalar_to_bytes(&d),
    })
}

/// Encrypt a 64-byte message under the threshold public key.
pub fn encrypt_share<R: RngCore + CryptoRng>(
    public_key: &CompressedPoint,
    message: &[u8; 64],
    rng: &mut R,
) -> Result<EncryptedShare, Error> {
    let q = scalar::projective_from_bytes(public_key)?;
    let r = Scalar::random(&mut *rng);
    let c1 = ProjectivePoint::GENERATOR * r;
    let shared = q * r;
    let pad = kdf64(&shared);
    let mut c2 = [0u8; 64];
    for i in 0..64 {
        c2[i] = message[i] ^ pad[i];
    }
    Ok(EncryptedShare {
        c1: scalar::point_to_bytes(&c1),
        c2,
    })
}

/// Compute one moderator's decryption share `D_j = [d_j] c1`.
pub fn decryption_share(
    moderator_index: u8,
    share_secret: &Scalar32,
    c1: &CompressedPoint,
) -> Result<(u8, CompressedPoint), Error> {
    let d_j = scalar::scalar_from_bytes_allow_zero(share_secret)?;
    let c1p = scalar::projective_from_bytes(c1)?;
    let dj_c1 = c1p * d_j;
    Ok((moderator_index, scalar::point_to_bytes(&dj_c1)))
}

/// Combine ≥ N decryption shares into the plaintext.
pub fn decrypt_with_shares(
    n: u8,
    ct: &EncryptedShare,
    shares: &DecryptionShareSet,
) -> Result<[u8; 64], Error> {
    if shares.shares.len() < n as usize {
        return Err(Error::NotEnoughShares {
            have: shares.shares.len(),
            need: n as usize,
        });
    }
    // Use the first N shares; if more are provided we silently ignore the
    // surplus (any N reconstruct the same secret).
    let chosen = &shares.shares[..n as usize];
    let xs: Vec<Scalar> = chosen
        .iter()
        .map(|(j, _)| Scalar::from(*j as u64))
        .collect();
    let lambdas = shamir::lagrange_coeffs_at_zero(&xs)?;

    // Σ λ_j · D_j as a projective point.
    let mut acc = ProjectivePoint::IDENTITY;
    for ((_, dj_bytes), lambda) in chosen.iter().zip(lambdas.iter()) {
        let dj = scalar::projective_from_bytes(dj_bytes)?;
        acc += dj * *lambda;
    }
    let pad = kdf64(&acc);
    let mut m = [0u8; 64];
    for i in 0..64 {
        m[i] = ct.c2[i] ^ pad[i];
    }
    Ok(m)
}

/// 64-byte KDF over a secp256k1 point's x-coordinate.
fn kdf64(p: &ProjectivePoint) -> [u8; 64] {
    let aff = p.to_affine();
    let ep = aff.to_encoded_point(false); // uncompressed: 0x04 || X || Y
    let bytes = ep.as_bytes();
    // Skip the leading tag byte; take X (32 bytes).
    debug_assert!(bytes.len() == 65 || bytes.len() == 1);
    let x: &[u8] = if bytes.len() == 65 {
        &bytes[1..33]
    } else {
        &[]
    };
    let h0 = h_tagged(domain::SHARE_KDF, &[x, &[0u8]]);
    let h1 = h_tagged(domain::SHARE_KDF, &[x, &[1u8]]);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h0);
    out[32..].copy_from_slice(&h1);
    out
}

/// Hash-binding helper used elsewhere: `H(domain("cert") || msg_id || payload || enc_share)`.
pub fn cert_hash(msg_id: &Hash32, payload: &[u8], enc: &EncryptedShare) -> Hash32 {
    h_tagged(
        domain::CERT_HASH,
        &[msg_id, payload, &enc.c1, &enc.c2],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn round_trip_threshold_decrypt() {
        let n = 3u8;
        let m = 5u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();

        let mut msg = [0u8; 64];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();

        // Pick any 3 moderators.
        let chosen = [0usize, 2, 4];
        let mut share_set = DecryptionShareSet { shares: Vec::new() };
        for &i in &chosen {
            let (alpha, d_j) = key.shares[i];
            share_set.shares.push(decryption_share(alpha, &d_j, &ct.c1).unwrap());
        }
        let recovered = decrypt_with_shares(n, &ct, &share_set).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn fewer_than_n_shares_rejected() {
        let n = 3u8;
        let m = 5u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();
        let msg = [0xAAu8; 64];
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();
        let mut share_set = DecryptionShareSet { shares: Vec::new() };
        let (alpha, d_j) = key.shares[0];
        share_set.shares.push(decryption_share(alpha, &d_j, &ct.c1).unwrap());
        assert!(matches!(
            decrypt_with_shares(n, &ct, &share_set),
            Err(Error::NotEnoughShares { have: 1, need: 3 })
        ));
    }

    #[test]
    fn any_n_subset_works() {
        let n = 2u8;
        let m = 4u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();
        let msg = [0x55u8; 64];
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();

        for (i, j) in [(0usize, 1), (0, 2), (1, 3), (2, 3)] {
            let mut share_set = DecryptionShareSet { shares: Vec::new() };
            for &k in &[i, j] {
                let (alpha, d_j) = key.shares[k];
                share_set
                    .shares
                    .push(decryption_share(alpha, &d_j, &ct.c1).unwrap());
            }
            let recovered = decrypt_with_shares(n, &ct, &share_set).unwrap();
            assert_eq!(recovered, msg, "subset ({},{}) failed", i, j);
        }
    }
}
