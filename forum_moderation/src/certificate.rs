//! N-of-M moderation certificate construction.
//!
//! Each moderator builds a `CertificateShare` and broadcasts it. An aggregator
//! (any party — typically another moderator or an external watcher) collects
//! ≥ N shares for the same `post_hash`, decrypts the encrypted share, and
//! emits a complete `Certificate`.

use crate::{
    domain,
    hash::h_tagged,
    scalar, shamir,
    threshold_elgamal::{decryption_share, DecryptionShareSet},
    Error,
};
use alloc::vec::Vec;
use forum_core::{
    Certificate, CertificateShare, CompressedPoint, EncryptedShare, Hash32, Scalar32,
};
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature as EcdsaSig, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregateError {
    /// Less than N shares supplied.
    NotEnoughShares { have: usize, need: usize },
    /// Two shares carry the same moderator_index.
    DuplicateShare(u8),
    /// A share's signature didn't verify (or its decryption share didn't
    /// combine into a parseable scalar pair).
    InvalidShare(u8),
    /// The recovered (x_i, y_i) didn't decode as scalars.
    BadPlaintext,
    /// All shares must reference the same post_hash; one of them didn't.
    MismatchedPost,
}

/// Build a single moderator's certificate share for a post.
///
/// `moderator_index` is the 1-indexed position in the forum's moderator
/// roster (= the Shamir abscissa α_j for that moderator's key share).
///
/// `share_secret` is `d_j`, the moderator's private threshold-ElGamal share.
///
/// `signing_key` is the moderator's long-lived ECDSA-secp256k1 key. We sign
/// `H(domain("cert-sig") || instance_id || post_hash || α_j || decryption_share)`
/// so the on-chain slash verifier can confirm exactly N of M moderators
/// agreed to issue the strike. Without this binding, a colluding ≥ N
/// moderator quorum could secretly decrypt + slash, leaving no audit trail.
pub fn build_share(
    instance_id: Hash32,
    msg_id: Hash32,
    payload: &[u8],
    enc_share: &EncryptedShare,
    moderator_index: u8,
    share_secret: &Scalar32,
    signing_key: &SigningKey,
) -> Result<CertificateShare, Error> {
    let post_hash = crate::threshold_elgamal::cert_hash(&msg_id, payload, enc_share);
    let (alpha, dj) = decryption_share(moderator_index, share_secret, &enc_share.c1)?;
    debug_assert_eq!(alpha, moderator_index);

    let to_sign = sig_message(&instance_id, &post_hash, alpha, &dj);
    let sig: EcdsaSig = signing_key.sign(&to_sign);
    let signature = sig.to_der().as_bytes().to_vec();

    Ok(CertificateShare {
        instance_id,
        post_hash,
        decryption_share: dj,
        moderator_index: alpha,
        signature,
    })
}

/// Verify a single share's signature against the moderator's pubkey. Returns
/// `Ok(true)` only on a fully valid DER ECDSA-secp256k1 signature over the
/// canonical `sig_message` bytes.
pub fn verify_share(share: &CertificateShare, moderator_pubkey: &CompressedPoint) -> bool {
    let Ok(vk) = VerifyingKey::from_sec1_bytes(moderator_pubkey) else {
        return false;
    };
    let Ok(sig) = EcdsaSig::from_der(&share.signature) else {
        return false;
    };
    let msg = sig_message(
        &share.instance_id,
        &share.post_hash,
        share.moderator_index,
        &share.decryption_share,
    );
    vk.verify(&msg, &sig).is_ok()
}

/// Canonical bytes that the moderator signs and the slash verifier checks.
/// Domain-tagged so signatures over different protocol surfaces can never
/// collide.
fn sig_message(
    instance_id: &Hash32,
    post_hash: &Hash32,
    alpha: u8,
    decryption_share: &CompressedPoint,
) -> Hash32 {
    h_tagged(
        "cert-sig",
        &[instance_id, post_hash, &[alpha], decryption_share],
    )
}

/// Aggregate ≥ N certificate shares into a complete `Certificate`. Combines
/// the decryption shares via Lagrange interpolation at zero (see
/// `threshold_elgamal::decrypt_with_shares`) and parses the recovered
/// 64 bytes as `(x_i || y_i)`.
///
/// Does NOT verify share signatures — the caller should pre-filter shares to
/// those whose signature has already verified against the moderator roster.
pub fn aggregate_certificate(
    instance_id: Hash32,
    n: u8,
    enc_share: &EncryptedShare,
    shares: Vec<CertificateShare>,
) -> Result<Certificate, AggregateError> {
    if shares.len() < n as usize {
        return Err(AggregateError::NotEnoughShares {
            have: shares.len(),
            need: n as usize,
        });
    }

    // Detect duplicate moderator indices.
    let mut seen = [false; 256];
    let post_hash = shares[0].post_hash;
    for s in &shares {
        if s.post_hash != post_hash {
            return Err(AggregateError::MismatchedPost);
        }
        let i = s.moderator_index as usize;
        if seen[i] {
            return Err(AggregateError::DuplicateShare(s.moderator_index));
        }
        seen[i] = true;
    }

    // Decrypt: take the first N shares deterministically (sorted by index).
    let mut sorted = shares.clone();
    sorted.sort_by_key(|s| s.moderator_index);
    let chosen: Vec<&CertificateShare> = sorted.iter().take(n as usize).collect();

    let xs: Vec<Scalar> = chosen
        .iter()
        .map(|s| Scalar::from(s.moderator_index as u64))
        .collect();
    let lambdas = shamir::lagrange_coeffs_at_zero(&xs)
        .map_err(|_| AggregateError::InvalidShare(0))?;

    let mut acc = ProjectivePoint::IDENTITY;
    for (s, lambda) in chosen.iter().zip(lambdas.iter()) {
        let dj = scalar::projective_from_bytes(&s.decryption_share)
            .map_err(|_| AggregateError::InvalidShare(s.moderator_index))?;
        acc += dj * *lambda;
    }
    let pad = kdf64_for_acc(&acc);
    let mut m = [0u8; 64];
    for i in 0..64 {
        m[i] = enc_share.c2[i] ^ pad[i];
    }
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&m[..32]);
    y_bytes.copy_from_slice(&m[32..]);

    // Sanity-check the bytes parse as scalars.
    if scalar::scalar_from_bytes_allow_zero(&x_bytes).is_err()
        || scalar::scalar_from_bytes_allow_zero(&y_bytes).is_err()
    {
        return Err(AggregateError::BadPlaintext);
    }

    Ok(Certificate {
        instance_id,
        post_hash,
        enc_share: enc_share.clone(),
        x_i: x_bytes,
        y_i: y_bytes,
        shares,
    })
}

/// Reconstruct the share set for `decrypt_with_shares` from `CertificateShare`s.
pub fn shares_to_decryption_set(shares: &[CertificateShare]) -> DecryptionShareSet {
    DecryptionShareSet {
        shares: shares
            .iter()
            .map(|s| (s.moderator_index, s.decryption_share))
            .collect(),
    }
}

fn kdf64_for_acc(p: &ProjectivePoint) -> [u8; 64] {
    let aff = p.to_affine();
    let ep = aff.to_encoded_point(false);
    let bytes = ep.as_bytes();
    let x: &[u8] = if bytes.len() == 65 { &bytes[1..33] } else { &[] };
    let h0 = h_tagged(domain::SHARE_KDF, &[x, &[0u8]]);
    let h1 = h_tagged(domain::SHARE_KDF, &[x, &[1u8]]);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h0);
    out[32..].copy_from_slice(&h1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold_elgamal::{encrypt_share, generate_threshold_key};
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;
    use rand_core::OsRng;

    fn fresh_signing_key() -> (SigningKey, CompressedPoint) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let pk_bytes: [u8; 33] = vk.to_encoded_point(true).as_bytes().try_into().unwrap();
        (sk, pk_bytes)
    }

    #[test]
    fn end_to_end_aggregate() {
        let n = 3u8;
        let m = 5u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();
        let (sk0, _) = fresh_signing_key();
        let (sk1, _) = fresh_signing_key();
        let (sk2, _) = fresh_signing_key();
        let signers = [&sk0, &sk1, &sk2];

        let mut msg = [0u8; 64];
        for i in 0..32 {
            msg[i] = i as u8;
            msg[32 + i] = 0xFF - i as u8;
        }
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();

        let instance_id = [0xAAu8; 32];
        let msg_id = [0xBBu8; 32];
        let payload = b"hello";

        let mut shares = Vec::new();
        for i in 0..(n as usize) {
            let (alpha, d_j) = key.shares[i];
            shares.push(build_share(instance_id, msg_id, payload, &ct, alpha, &d_j, signers[i]).unwrap());
        }
        let cert = aggregate_certificate(instance_id, n, &ct, shares).expect("aggregation works");

        assert_eq!(&cert.x_i[..], &msg[..32]);
        assert_eq!(&cert.y_i[..], &msg[32..]);
    }

    #[test]
    fn rejects_duplicate_moderator() {
        let n = 2u8;
        let m = 3u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();
        let (sk, _) = fresh_signing_key();
        let msg = [0u8; 64];
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();
        let (alpha, d_j) = key.shares[0];
        let s1 = build_share([0u8; 32], [0u8; 32], &[], &ct, alpha, &d_j, &sk).unwrap();
        let s2 = s1.clone();
        let result = aggregate_certificate([0u8; 32], n, &ct, vec![s1, s2]);
        assert!(matches!(result, Err(AggregateError::DuplicateShare(_))));
    }

    #[test]
    fn rejects_too_few_shares() {
        let n = 3u8;
        let m = 5u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();
        let (sk, _) = fresh_signing_key();
        let msg = [0u8; 64];
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();
        let (alpha, d_j) = key.shares[0];
        let s = build_share([0u8; 32], [0u8; 32], &[], &ct, alpha, &d_j, &sk).unwrap();
        let result = aggregate_certificate([0u8; 32], n, &ct, vec![s]);
        assert!(matches!(result, Err(AggregateError::NotEnoughShares { have: 1, need: 3 })));
    }

    #[test]
    fn signature_verification_round_trip() {
        // Real moderator signs; verify_share returns true. Tampered fields
        // must cause verify_share to return false.
        let n = 2u8;
        let m = 3u8;
        let key = generate_threshold_key(n, m, &mut OsRng).unwrap();
        let (sk, pk) = fresh_signing_key();
        let msg = [0xCCu8; 64];
        let ct = encrypt_share(&key.public_key, &msg, &mut OsRng).unwrap();
        let (alpha, dj) = key.shares[0];
        let share = build_share([0xAA; 32], [0xBB; 32], b"body", &ct, alpha, &dj, &sk).unwrap();

        assert!(verify_share(&share, &pk));

        // Wrong pubkey → reject.
        let (_, other_pk) = fresh_signing_key();
        assert!(!verify_share(&share, &other_pk));

        // Tampered post_hash → reject.
        let mut tampered = share.clone();
        tampered.post_hash[0] ^= 0xFF;
        assert!(!verify_share(&tampered, &pk));

        // Tampered moderator_index → reject.
        let mut tampered2 = share.clone();
        tampered2.moderator_index = tampered2.moderator_index.wrapping_add(1);
        assert!(!verify_share(&tampered2, &pk));
    }
}
