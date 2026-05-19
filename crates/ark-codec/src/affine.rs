//! Affine-point serialisation to/from coordinate strings.
//!
//! Exports: [`affine_to_hex_str`], [`affine_to_decimal_str`],
//! [`coords_to_affine`], [`FromCoords`], [`FieldParseError`].  Supports
//! short-Weierstrass (`G1Affine`, `G2Affine`) and twisted-Edwards curves.
//! Requires the `field-serde` feature.

use std::fmt::UpperHex;

use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_ff::PrimeField;

/// Failure modes for affine-point and field-coordinate parsing.
///
/// Returned by [`coords_to_affine`] and the underlying field-string conversions
/// in [`crate::codec::string`]. The `NotOnCurve` / `NotInCorrectSubgroup`
/// variants are produced by [`FromCoords::validate`] after a candidate point is
/// constructed; `InvalidDecimal` / `InvalidHex` / `InvalidLength` come from the
/// string-to-field decoder before construction.
#[derive(Debug, thiserror::Error)]
pub enum FieldParseError {
    /// Decimal string did not parse as a base-field element.
    #[error("Invalid decimal string for field element")]
    InvalidDecimal,
    /// Hex string did not parse as a base-field element.
    #[error("Invalid hex string for field element")]
    InvalidHex,
    /// ASCII byte count is not a multiple of the field's expected chunk size
    /// (first parameter is the required multiple, second is the actual length).
    #[error("Invalid length for ASCII to field conversion: expected multiple of {0}, got {1}")]
    InvalidLength(usize, usize),
    /// Coordinates parsed but the resulting point fails the curve equation.
    #[error("point is not on curve")]
    NotOnCurve,
    /// Point is on the curve but outside the correct prime-order subgroup —
    /// rejecting it is required for soundness in pairing-based protocols.
    #[error("point is not in correct subgroup")]
    NotInCorrectSubgroup,
}

/// Converts (x, y) coordinates of an Affine point to hex strings (["0x..", "0x.."]).
/// - Returns "0x0" for the point at infinity.
pub fn affine_to_hex_str<A: AffineRepr>(p: &A) -> Vec<String>
where
    A::BaseField: PrimeField,
    <A::BaseField as PrimeField>::BigInt: UpperHex,
{
    [p.x(), p.y()]
        .into_iter()
        .map(|coord_opt| match coord_opt {
            Some(field_elem) => format!("0x{:X}", field_elem.into_bigint()),
            None => "0x0".to_string(),
        })
        .collect()
}

/// Converts (x, y) coordinates of an Affine point to decimal strings (["..", ".."]).
/// - Returns "0" for the point at infinity.
pub fn affine_to_decimal_str<A: AffineRepr>(p: &A) -> Vec<String>
where
    A::BaseField: PrimeField,
{
    [p.x(), p.y()]
        .into_iter()
        .map(|coord_opt| {
            coord_opt
                .map(|field_elem| field_elem.to_string())
                .unwrap_or_else(|| "0".to_string())
        })
        .collect()
}

impl From<super::string::ConvertError> for FieldParseError {
    fn from(e: super::string::ConvertError) -> Self {
        match e {
            super::string::ConvertError::InvalidHex(_) => FieldParseError::InvalidHex,
            super::string::ConvertError::InvalidDecimal(_) => FieldParseError::InvalidDecimal,
            _ => FieldParseError::InvalidDecimal,
        }
    }
}

/// Converts (x, y) coordinate strings to an Affine point.
/// - Each coordinate follows the `hex_decimal_to_field` rule (hex if 0x prefix, otherwise decimal).
pub fn coords_to_affine<A>(x_str: &str, y_str: &str) -> Result<A, FieldParseError>
where
    A: FromCoords,
    A::BaseField: PrimeField,
{
    let x = super::string::hex_decimal_to_field::<A::BaseField>(x_str)?;
    let y = super::string::hex_decimal_to_field::<A::BaseField>(y_str)?;

    let p = A::from_coords(x, y);

    A::validate(&p)?;

    Ok(p)
}
/// Builder for [`AffineRepr`] points that takes raw `(x, y)` coordinates and
/// returns a validated point.
///
/// Split into `from_coords` (cheap construction without curve checks) and
/// `validate` (which enforces both the curve equation and prime-order
/// subgroup membership) so callers can amortise validation across batches —
/// [`coords_to_affine`] always validates per call.
pub trait FromCoords: AffineRepr {
    /// Construct an affine point from coordinates without validating that it
    /// lies on the curve or in the correct subgroup. Pair with [`Self::validate`]
    /// before use in any soundness-critical path.
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self;
    /// Returns `Ok(())` iff the point lies on the curve **and** in the
    /// prime-order subgroup. Both checks are required for pairing soundness;
    /// the curve check alone admits points of unwanted order.
    fn validate(p: &Self) -> Result<(), FieldParseError>;
}

// SW: G1Affine, G2Affine, etc.
impl<P> FromCoords for SWAffine<P>
where
    P: SWCurveConfig,
    P::BaseField: PrimeField,
{
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new_unchecked(x, y)
    }

    fn validate(p: &Self) -> Result<(), FieldParseError> {
        if !p.is_on_curve() {
            return Err(FieldParseError::NotOnCurve);
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(FieldParseError::NotInCorrectSubgroup);
        }
        Ok(())
    }
}

// Twisted Edwards: EdOnBN, etc.
impl<P> FromCoords for TEAffine<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new_unchecked(x, y)
    }

    fn validate(p: &Self) -> Result<(), FieldParseError> {
        if !p.is_on_curve() {
            return Err(FieldParseError::NotOnCurve);
        }
        if !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(FieldParseError::NotInCorrectSubgroup);
        }
        Ok(())
    }
}
