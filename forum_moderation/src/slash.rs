//! Slash candidate search. Given `t` certificates and threshold `K`, try every
//! K-subset, Lagrange-interpolate the polynomial, derive the candidate
//! commitment, and check it against the on-chain membership tree.
//!
//! Only K-subsets that reconstruct a real (registered, non-revoked) member
//! produce a valid `SlashCandidate`. False positives require a SHA-256
//! collision and are therefore cryptographically negligible.

use crate::{commitment, scalar, shamir, Error};
use alloc::vec::Vec;
use forum_core::{Certificate, Hash32};
use k256::Scalar;

#[derive(Debug, Clone)]
pub struct SlashCandidate {
    /// The recovered member commitment.
    pub commitment: Hash32,
    /// Indices into the input certificate list that combined to produce this
    /// candidate. Length = K.
    pub cert_indices: Vec<usize>,
    /// The interpolated polynomial. Caller may need this to derive other
    /// derived values during slash submission.
    pub polynomial: shamir::Polynomial,
}

/// Search every K-subset of `certs` and return all that reconstruct a
/// commitment present in `tree_membership` (a closure: candidate → in tree?).
///
/// `revoked` returns true if a commitment is already on the revocation list;
/// such commitments are skipped.
///
/// For a typical forum (`K ∈ {3, 5, 7}`, `t ≤ 200`), this exhaustive search
/// is fast (millions of interpolations per second on a modern CPU). For
/// larger `t`, callers should keep `t` bounded by periodically draining
/// already-slashed certificates from the pool.
pub fn find_slash_candidates<F, G>(
    k: u8,
    certs: &[Certificate],
    mut in_tree: F,
    mut revoked: G,
) -> Result<Vec<SlashCandidate>, Error>
where
    F: FnMut(&Hash32) -> bool,
    G: FnMut(&Hash32) -> bool,
{
    let k = k as usize;
    if certs.len() < k {
        return Err(Error::InsufficientShares);
    }

    let mut candidates = Vec::new();
    let mut subset = (0..k).collect::<Vec<usize>>();
    let n = certs.len();

    loop {
        // Try the current subset.
        if let Some(cand) = try_subset(&subset, certs, &mut in_tree, &mut revoked)? {
            candidates.push(cand);
        }

        // Advance to next combination (lexicographic).
        if !next_combination(&mut subset, n) {
            break;
        }
    }
    Ok(candidates)
}

/// Try one specific K-subset of `certs`.
fn try_subset<F, G>(
    subset: &[usize],
    certs: &[Certificate],
    in_tree: &mut F,
    revoked: &mut G,
) -> Result<Option<SlashCandidate>, Error>
where
    F: FnMut(&Hash32) -> bool,
    G: FnMut(&Hash32) -> bool,
{
    let mut points: Vec<(Scalar, Scalar)> = Vec::with_capacity(subset.len());
    let mut x_seen = Vec::new();
    for &i in subset {
        let cert = &certs[i];
        let x = scalar::scalar_from_bytes_allow_zero(&cert.x_i)?;
        let y = scalar::scalar_from_bytes_allow_zero(&cert.y_i)?;
        if x_seen.iter().any(|x_old: &Scalar| *x_old == x) {
            // Duplicate abscissa among the chosen subset — interpolation
            // would be singular; skip.
            return Ok(None);
        }
        x_seen.push(x);
        points.push((x, y));
    }
    let poly = match shamir::lagrange_interpolate(&points) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let candidate_commitment = commitment::commitment_from_secret(&poly.coeffs)?;
    if revoked(&candidate_commitment) {
        return Ok(None);
    }
    if !in_tree(&candidate_commitment) {
        return Ok(None);
    }
    Ok(Some(SlashCandidate {
        commitment: candidate_commitment,
        cert_indices: subset.to_vec(),
        polynomial: poly,
    }))
}

/// In-place lexicographic next-combination over indices in `[0, n)`.
/// Returns false when there is no next combination.
fn next_combination(subset: &mut [usize], n: usize) -> bool {
    let k = subset.len();
    if k == 0 {
        return false;
    }
    let mut i = k - 1;
    loop {
        if subset[i] < n - k + i {
            subset[i] += 1;
            for j in (i + 1)..k {
                subset[j] = subset[j - 1] + 1;
            }
            return true;
        }
        if i == 0 {
            return false;
        }
        i -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::MemberIdentity,
        threshold_elgamal::{encrypt_share, generate_threshold_key},
    };
    use alloc::collections::BTreeSet;
    use forum_core::EncryptedShare;
    use rand_core::OsRng;

    fn make_cert_for(
        identity: &MemberIdentity,
        x: &Scalar,
        ct: &EncryptedShare,
    ) -> Certificate {
        let y = identity.polynomial.eval(x);
        Certificate {
            instance_id: [0u8; 32],
            post_hash: [0u8; 32],
            enc_share: ct.clone(),
            x_i: scalar::scalar_to_bytes(x),
            y_i: scalar::scalar_to_bytes(&y),
            shares: Vec::new(),
        }
    }

    #[test]
    fn finds_slash_when_k_certs_belong_to_one_author() {
        let k = 3u8;
        let id = MemberIdentity::generate(k as usize, &mut OsRng).unwrap();
        let real_commit = id.commitment;

        // Build 5 certs total: 3 from real author, 2 from a different author.
        let other = MemberIdentity::generate(k as usize, &mut OsRng).unwrap();

        let key = generate_threshold_key(2, 3, &mut OsRng).unwrap();
        let dummy_msg = [0u8; 64];
        let ct = encrypt_share(&key.public_key, &dummy_msg, &mut OsRng).unwrap();

        let mut certs = Vec::new();
        for i in 1..=3 {
            let x = Scalar::from(i as u64);
            certs.push(make_cert_for(&id, &x, &ct));
        }
        for i in 100..=101 {
            let x = Scalar::from(i as u64);
            certs.push(make_cert_for(&other, &x, &ct));
        }

        let tree: BTreeSet<Hash32> =
            [real_commit, other.commitment].into_iter().collect();
        let revoked: BTreeSet<Hash32> = BTreeSet::new();

        let cands = find_slash_candidates(
            k,
            &certs,
            |c| tree.contains(c),
            |c| revoked.contains(c),
        )
        .unwrap();

        // Should find at least one candidate (the real author's K-subset).
        assert!(cands.iter().any(|c| c.commitment == real_commit));
        // None of them should be the OTHER author (only 2 of their certs are
        // in the pool — fewer than K).
        assert!(!cands.iter().any(|c| c.commitment == other.commitment));
    }

    #[test]
    fn revoked_member_is_skipped() {
        let k = 3u8;
        let id = MemberIdentity::generate(k as usize, &mut OsRng).unwrap();
        let key = generate_threshold_key(2, 3, &mut OsRng).unwrap();
        let dummy_msg = [0u8; 64];
        let ct = encrypt_share(&key.public_key, &dummy_msg, &mut OsRng).unwrap();
        let mut certs = Vec::new();
        for i in 1..=3 {
            let x = Scalar::from(i as u64);
            certs.push(make_cert_for(&id, &x, &ct));
        }
        let tree: BTreeSet<Hash32> = [id.commitment].into_iter().collect();
        let revoked: BTreeSet<Hash32> = [id.commitment].into_iter().collect();

        let cands = find_slash_candidates(
            k,
            &certs,
            |c| tree.contains(c),
            |c| revoked.contains(c),
        )
        .unwrap();
        assert!(cands.is_empty());
    }

    #[test]
    fn random_certs_do_not_collide_with_real_member() {
        let k = 3u8;
        let id = MemberIdentity::generate(k as usize, &mut OsRng).unwrap();
        let key = generate_threshold_key(2, 3, &mut OsRng).unwrap();
        let dummy_msg = [0u8; 64];
        let ct = encrypt_share(&key.public_key, &dummy_msg, &mut OsRng).unwrap();

        // 4 random certs from 4 different unrelated members.
        let mut certs = Vec::new();
        for _ in 0..4 {
            let other = MemberIdentity::generate(k as usize, &mut OsRng).unwrap();
            let x = Scalar::from(42u64);
            certs.push(make_cert_for(&other, &x, &ct));
        }

        let tree: BTreeSet<Hash32> = [id.commitment].into_iter().collect();
        let revoked: BTreeSet<Hash32> = BTreeSet::new();
        let cands = find_slash_candidates(
            k,
            &certs,
            |c| tree.contains(c),
            |c| revoked.contains(c),
        )
        .unwrap();
        // Should find no candidate matching the real (uncertified) member.
        assert!(cands.is_empty());
    }

    #[test]
    fn next_combination_ranges() {
        // Check we enumerate C(5,3) = 10 subsets.
        let mut s = vec![0, 1, 2];
        let mut count = 1;
        while next_combination(&mut s, 5) {
            count += 1;
        }
        assert_eq!(count, 10);
    }
}
