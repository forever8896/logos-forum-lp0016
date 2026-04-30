//! secp256k1 scalar wrapping. Conversions between our 32-byte big-endian wire
//! format (`Scalar32`) and `k256::Scalar`. We never let an out-of-range or
//! zero scalar through silently.

use crate::Error;
use forum_core::{CompressedPoint, Scalar32};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::{
    sec1::{ToEncodedPoint},
    PrimeField,
};
use k256::{ProjectivePoint, PublicKey, Scalar};

/// Decode a 32-byte big-endian into a non-zero secp256k1 scalar. Rejects:
/// - bytes ≥ secp256k1 group order
/// - the zero scalar
pub fn scalar_from_bytes(bytes: &Scalar32) -> Result<Scalar, Error> {
    let opt = Scalar::from_repr((*bytes).into());
    let s: Scalar = Option::from(opt).ok_or(Error::InvalidScalar)?;
    if bool::from(s.is_zero()) {
        return Err(Error::InvalidScalar);
    }
    Ok(s)
}

/// Decode a 32-byte big-endian, allowing zero. Used in places where zero is a
/// valid value (e.g. raw secret material before normalisation).
pub fn scalar_from_bytes_allow_zero(bytes: &Scalar32) -> Result<Scalar, Error> {
    let opt = Scalar::from_repr((*bytes).into());
    Option::from(opt).ok_or(Error::InvalidScalar)
}

pub fn scalar_to_bytes(s: &Scalar) -> Scalar32 {
    s.to_bytes().into()
}

/// Decode a 33-byte SEC1-compressed point into a `PublicKey` (rejects
/// identity).
pub fn point_from_bytes(bytes: &CompressedPoint) -> Result<PublicKey, Error> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPoint)
}

/// Same but returns a `ProjectivePoint` (no rejection of identity); use when
/// you intend to do projective arithmetic.
pub fn projective_from_bytes(bytes: &CompressedPoint) -> Result<ProjectivePoint, Error> {
    let ep = k256::EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidPoint)?;
    let opt = k256::AffinePoint::from_encoded_point(&ep);
    let aff: k256::AffinePoint = Option::from(opt).ok_or(Error::InvalidPoint)?;
    Ok(aff.into())
}

/// Encode a projective point as 33-byte SEC1 compressed.
pub fn point_to_bytes(p: &ProjectivePoint) -> CompressedPoint {
    let aff = p.to_affine();
    let ep = aff.to_encoded_point(true);
    let bytes = ep.as_bytes();
    debug_assert_eq!(bytes.len(), 33);
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;
    use rand_core::OsRng;

    #[test]
    fn round_trip_scalar() {
        let s = Scalar::random(&mut OsRng);
        let bytes = scalar_to_bytes(&s);
        let s2 = scalar_from_bytes_allow_zero(&bytes).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn rejects_zero_scalar() {
        let bytes = [0u8; 32];
        assert!(matches!(scalar_from_bytes(&bytes), Err(Error::InvalidScalar)));
    }

    #[test]
    fn round_trip_point() {
        use k256::ProjectivePoint;
        let s = Scalar::random(&mut OsRng);
        let p = ProjectivePoint::GENERATOR * s;
        let bytes = point_to_bytes(&p);
        let p2 = projective_from_bytes(&bytes).unwrap();
        assert_eq!(p, p2);
    }
}
