//! Member commitment derivation. The commitment is a 32-byte SHA-256 over
//! the entire Shamir polynomial (`sk` followed by `K-1` random coefficients).
//! See protocol §2 — note we follow Option A (no separate salt; the secret
//! itself provides the hiding).

use crate::{domain, hash::h_tagged, scalar, Error};
use alloc::vec::Vec;
use forum_core::{Hash32, Scalar32};
use k256::Scalar;

/// A member's commitment plus the underlying polynomial coefficients used to
/// derive it. Holding this struct = holding the member's full identity.
#[derive(Debug, Clone)]
pub struct MemberCommitment {
    /// The published commitment `C` (`Hash32`).
    pub commitment: Hash32,
    /// Polynomial coefficients `[sk, a_1, ..., a_{K-1}]`. Length = K.
    pub coeffs: Vec<Scalar>,
}

/// Derive `C = SHA256(domain("commitment") || sk || a_1 || ... || a_{K-1})`.
///
/// `coeffs[0]` is `sk`. `coeffs.len()` must equal `K` (forum parameter).
pub fn commitment_from_secret(coeffs: &[Scalar]) -> Result<Hash32, Error> {
    if coeffs.is_empty() {
        return Err(Error::DegreeMismatch);
    }
    let mut pieces: Vec<Scalar32> = Vec::with_capacity(coeffs.len());
    for c in coeffs {
        pieces.push(scalar::scalar_to_bytes(c));
    }
    // Pass references for h_tagged.
    let refs: Vec<&[u8]> = pieces.iter().map(|p| p.as_slice()).collect();
    Ok(h_tagged(domain::COMMITMENT, &refs))
}

/// Convenience: derive commitment + bundle coeffs together.
pub fn member_commitment(coeffs: Vec<Scalar>) -> Result<MemberCommitment, Error> {
    let commitment = commitment_from_secret(&coeffs)?;
    Ok(MemberCommitment { commitment, coeffs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;
    use rand_core::OsRng;

    #[test]
    fn deterministic_for_same_inputs() {
        let coeffs = (0..5).map(|_| Scalar::random(&mut OsRng)).collect::<Vec<_>>();
        let c1 = commitment_from_secret(&coeffs).unwrap();
        let c2 = commitment_from_secret(&coeffs).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn changes_when_any_coeff_changes() {
        let mut coeffs = (0..3).map(|_| Scalar::random(&mut OsRng)).collect::<Vec<_>>();
        let c1 = commitment_from_secret(&coeffs).unwrap();
        coeffs[1] = Scalar::random(&mut OsRng);
        let c2 = commitment_from_secret(&coeffs).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn empty_coeffs_rejected() {
        assert!(matches!(
            commitment_from_secret(&[]),
            Err(Error::DegreeMismatch)
        ));
    }
}
