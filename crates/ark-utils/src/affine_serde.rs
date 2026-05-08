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

#[derive(Debug, thiserror::Error)]
pub enum FieldParseError {
    #[error("Invalid decimal string for field element")]
    InvalidDecimal,
    #[error("Invalid hex string for field element")]
    InvalidHex,
    #[error("Invalid length for ASCII to field conversion: expected multiple of {0}, got {1}")]
    InvalidLength(usize, usize),
    #[error("point is not on curve")]
    NotOnCurve,
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

impl From<crate::convert::ConvertError> for FieldParseError {
    fn from(e: crate::convert::ConvertError) -> Self {
        match e {
            crate::convert::ConvertError::InvalidHex(_) => FieldParseError::InvalidHex,
            crate::convert::ConvertError::InvalidDecimal(_) => FieldParseError::InvalidDecimal,
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
    let x = crate::convert::hex_decimal_to_field::<A::BaseField>(x_str)?;
    let y = crate::convert::hex_decimal_to_field::<A::BaseField>(y_str)?;

    let p = A::from_coords(x, y);

    A::validate(&p)?;

    Ok(p)
}
pub trait FromCoords: AffineRepr {
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self;
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
