//! Member identity: a Shamir polynomial of degree `K-1` whose constant term
//! is the member's `sk`. Holding a `MemberIdentity` is equivalent to being
//! able to post in the forum.

use crate::{commitment, scalar, shamir, Error};
use alloc::vec::Vec;
use forum_core::{Hash32, Scalar32};
use k256::elliptic_curve::Field;
use k256::Scalar;
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, Clone)]
pub struct MemberIdentity {
    /// Polynomial f with f(0) = sk; degree K-1.
    pub polynomial: shamir::Polynomial,
    /// Cached commitment for the polynomial.
    pub commitment: Hash32,
}

/// A bundle suitable for handing to the on-chain registry: the public
/// commitment (so it can be appended to the membership tree) plus the stake
/// amount the member is locking.
#[derive(Debug, Clone)]
pub struct RegistrationPacket {
    pub commitment: Hash32,
    pub stake_amount: u128,
}

impl MemberIdentity {
    /// Generate a fresh identity for a forum with parameter `K`.
    pub fn generate<R: RngCore + CryptoRng>(k: usize, rng: &mut R) -> Result<Self, Error> {
        if k < 2 {
            return Err(Error::InvalidThreshold);
        }
        let sk = Scalar::random(&mut *rng);
        let polynomial = shamir::Polynomial::random_with_secret(sk, k - 1, rng);
        let commitment = commitment::commitment_from_secret(&polynomial.coeffs)?;
        Ok(Self {
            polynomial,
            commitment,
        })
    }

    /// Reconstruct an identity from its full coefficient vector. Used for
    /// import / persistence.
    pub fn from_coeffs(coeffs: Vec<Scalar32>) -> Result<Self, Error> {
        let parsed: Result<Vec<Scalar>, Error> = coeffs
            .iter()
            .map(scalar::scalar_from_bytes_allow_zero)
            .collect();
        let parsed = parsed?;
        let polynomial = shamir::Polynomial::from_coeffs(parsed)?;
        let commitment = commitment::commitment_from_secret(&polynomial.coeffs)?;
        Ok(Self {
            polynomial,
            commitment,
        })
    }

    pub fn to_coeffs(&self) -> Vec<Scalar32> {
        self.polynomial
            .coeffs
            .iter()
            .map(|s| scalar::scalar_to_bytes(s))
            .collect()
    }

    pub fn registration_packet(&self, stake_amount: u128) -> RegistrationPacket {
        RegistrationPacket {
            commitment: self.commitment,
            stake_amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn generate_then_export_round_trip() {
        for k in [2, 3, 5, 7] {
            let id = MemberIdentity::generate(k, &mut OsRng).unwrap();
            let coeffs = id.to_coeffs();
            let id2 = MemberIdentity::from_coeffs(coeffs).unwrap();
            assert_eq!(id.commitment, id2.commitment);
            for (a, b) in id
                .polynomial
                .coeffs
                .iter()
                .zip(id2.polynomial.coeffs.iter())
            {
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn k_less_than_2_rejected() {
        assert!(matches!(
            MemberIdentity::generate(1, &mut OsRng),
            Err(Error::InvalidThreshold)
        ));
    }
}
