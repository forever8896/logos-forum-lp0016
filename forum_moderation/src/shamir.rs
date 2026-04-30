//! Shamir secret sharing over the secp256k1 scalar field.
//!
//! A `Polynomial` of degree `K-1` is represented by its `K` coefficients
//! `[c_0, c_1, ..., c_{K-1}]` so that `f(x) = c_0 + c_1·x + ... + c_{K-1}·x^{K-1}`.
//! `c_0` is the secret (the member's `sk`).
//!
//! `K` distinct evaluations `(x_i, f(x_i))` Lagrange-interpolate back to the
//! full coefficient vector.

use crate::Error;
use alloc::vec::Vec;
use k256::elliptic_curve::Field;
use k256::Scalar;

#[derive(Debug, Clone)]
pub struct Polynomial {
    pub coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Build from the secret + (K-1) random coefficients. Caller chooses RNG.
    pub fn random_with_secret<R: rand_core::RngCore + rand_core::CryptoRng>(
        secret: Scalar,
        degree_minus_one: usize,
        rng: &mut R,
    ) -> Self {
        let mut coeffs = Vec::with_capacity(degree_minus_one + 1);
        coeffs.push(secret);
        for _ in 0..degree_minus_one {
            coeffs.push(Scalar::random(&mut *rng));
        }
        Self { coeffs }
    }

    pub fn from_coeffs(coeffs: Vec<Scalar>) -> Result<Self, Error> {
        if coeffs.is_empty() {
            return Err(Error::DegreeMismatch);
        }
        Ok(Self { coeffs })
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    pub fn k(&self) -> usize {
        self.coeffs.len()
    }

    pub fn secret(&self) -> &Scalar {
        &self.coeffs[0]
    }

    /// Horner evaluation `f(x)`.
    pub fn eval(&self, x: &Scalar) -> Scalar {
        let mut acc = Scalar::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }
}

/// Lagrange-interpolate the unique polynomial of degree at most `points.len()-1`
/// passing through `points = [(x_i, y_i)]`. Returns the full coefficient vector
/// `[c_0, c_1, ..., c_{n-1}]`.
///
/// Errors:
/// - `DegreeMismatch` if `points.is_empty()`.
/// - `InvalidScalar` if two abscissas are equal (singular system).
pub fn lagrange_interpolate(points: &[(Scalar, Scalar)]) -> Result<Polynomial, Error> {
    if points.is_empty() {
        return Err(Error::DegreeMismatch);
    }
    let n = points.len();

    // Build the polynomial in the standard monomial basis by summing each
    // Lagrange basis polynomial L_j(x) scaled by y_j.
    //
    // L_j(x) = ∏_{m≠j} (x - x_m) / (x_j - x_m)
    //
    // For small K (typically ≤ 8) this O(K²) algorithm is fine.
    let mut result: Vec<Scalar> = vec![Scalar::ZERO; n];

    for j in 0..n {
        // Compute the numerator polynomial: ∏_{m≠j}(x - x_m). Start with [1].
        let mut basis: Vec<Scalar> = vec![Scalar::ONE];
        let mut denom = Scalar::ONE;
        for m in 0..n {
            if m == j {
                continue;
            }
            // Multiply basis by (x - x_m).
            let mut new_basis: Vec<Scalar> = vec![Scalar::ZERO; basis.len() + 1];
            for (i, &b) in basis.iter().enumerate() {
                // x · b lives at degree i+1.
                new_basis[i + 1] += b;
                // (-x_m) · b lives at degree i.
                new_basis[i] -= b * points[m].0;
            }
            basis = new_basis;

            let diff = points[j].0 - points[m].0;
            if bool::from(diff.is_zero()) {
                return Err(Error::InvalidScalar);
            }
            denom *= diff;
        }
        let inv = Option::<Scalar>::from(denom.invert()).ok_or(Error::InvalidScalar)?;
        let scale = points[j].1 * inv;
        for (i, b) in basis.iter().enumerate() {
            result[i] += *b * scale;
        }
    }

    Ok(Polynomial { coeffs: result })
}

/// Lagrange coefficients evaluated at zero. Used for ElGamal threshold
/// decryption: Σ λ_j(0) · D_j reconstructs `[d] c1`.
///
/// Returns `λ_j(0)` for each `j` in `xs`.
pub fn lagrange_coeffs_at_zero(xs: &[Scalar]) -> Result<Vec<Scalar>, Error> {
    let n = xs.len();
    if n == 0 {
        return Err(Error::DegreeMismatch);
    }
    let mut out = Vec::with_capacity(n);
    for j in 0..n {
        let mut num = Scalar::ONE; // ∏_{m≠j}(-x_m)
        let mut den = Scalar::ONE; // ∏_{m≠j}(x_j - x_m)
        for m in 0..n {
            if m == j {
                continue;
            }
            num *= -xs[m];
            let diff = xs[j] - xs[m];
            if bool::from(diff.is_zero()) {
                return Err(Error::InvalidScalar);
            }
            den *= diff;
        }
        let inv = Option::<Scalar>::from(den.invert()).ok_or(Error::InvalidScalar)?;
        out.push(num * inv);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn eval_then_interpolate_round_trip() {
        for k in [2usize, 3, 5, 7] {
            let secret = Scalar::random(&mut OsRng);
            let poly = Polynomial::random_with_secret(secret, k - 1, &mut OsRng);

            // Sample K distinct nonzero abscissas.
            let mut points = Vec::with_capacity(k);
            for i in 1..=k {
                let x = Scalar::from(i as u64);
                let y = poly.eval(&x);
                points.push((x, y));
            }

            let recovered = lagrange_interpolate(&points).unwrap();
            assert_eq!(recovered.coeffs.len(), k);
            for (a, b) in poly.coeffs.iter().zip(recovered.coeffs.iter()) {
                assert_eq!(a, b);
            }
            assert_eq!(*recovered.secret(), secret);
        }
    }

    #[test]
    fn k_minus_one_points_do_not_determine_secret() {
        let k = 5;
        let secret = Scalar::random(&mut OsRng);
        let poly = Polynomial::random_with_secret(secret, k - 1, &mut OsRng);
        let points: Vec<_> = (1..=(k - 1))
            .map(|i| {
                let x = Scalar::from(i as u64);
                (x, poly.eval(&x))
            })
            .collect();
        // Interpolating K-1 points yields a polynomial of degree at most K-2.
        // Its f(0) is generally NOT the original secret.
        let recovered = lagrange_interpolate(&points).unwrap();
        assert_ne!(*recovered.secret(), secret);
    }

    #[test]
    fn duplicate_abscissa_rejected() {
        let pts = vec![
            (Scalar::from(1u64), Scalar::from(10u64)),
            (Scalar::from(1u64), Scalar::from(20u64)),
        ];
        assert!(matches!(lagrange_interpolate(&pts), Err(Error::InvalidScalar)));
    }

    #[test]
    fn lagrange_at_zero_matches_full_interpolation() {
        let xs: Vec<Scalar> = (1..=4).map(|i| Scalar::from(i as u64)).collect();
        let ys: Vec<Scalar> = (1..=4).map(|i| Scalar::from((i * i + 7) as u64)).collect();
        let pts: Vec<_> = xs.iter().zip(ys.iter()).map(|(x, y)| (*x, *y)).collect();
        let poly = lagrange_interpolate(&pts).unwrap();
        let f0 = *poly.secret();

        let lambdas = lagrange_coeffs_at_zero(&xs).unwrap();
        let f0_via_lambda = lambdas
            .iter()
            .zip(ys.iter())
            .fold(Scalar::ZERO, |acc, (l, y)| acc + *l * *y);
        assert_eq!(f0, f0_via_lambda);
    }
}
