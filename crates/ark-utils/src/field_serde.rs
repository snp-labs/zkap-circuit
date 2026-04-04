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

/// Decodes a hex string to bytes.
/// - Accepts "0x" prefix.
/// - If the hex length is odd, prepends '0' to make it even before decoding.
fn hex_to_bytes_even(s: &str) -> Result<Vec<u8>, FieldParseError> {
    let mut hex_body = s.strip_prefix("0x").unwrap_or(s).to_owned();
    if hex_body.len() % 2 == 1 {
        hex_body.insert(0, '0');
    }
    hex::decode(&hex_body).map_err(|_| FieldParseError::InvalidHex)
}

/// Parses an input string as a field element.
/// - If it starts with "0x..." or "0X...", treats it as hex and reduces `mod p`.
/// - Otherwise, parses it as a decimal.
pub fn hex_decimal_to_field<F: PrimeField>(s: &str) -> Result<F, FieldParseError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let bytes = hex_to_bytes_even(s)?;
        Ok(F::from_be_bytes_mod_order(&bytes))
    } else {
        Ok(F::from_str(s).map_err(|_| FieldParseError::InvalidDecimal)?)
    }
}

/// Splits ASCII bytes into big-endian limbs and interprets each limb as a field element.
/// - Limb width is computed as `((MODULUS_BIT_SIZE-1)/8)`.
/// - Returns an error if the input length is not a multiple of the limb width.
/// - (Useful for packing JWT claims into fixed-width limbs)
pub fn ascii_to_field_be<F: PrimeField>(s: &str) -> Result<Vec<F>, FieldParseError> {
    let bytes = s.as_bytes();
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if !bytes.len().is_multiple_of(limb_width) {
        return Err(FieldParseError::InvalidLength(limb_width, bytes.len()));
    }

    Ok(bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect())
}

/// Converts (x, y) coordinate strings to an Affine point.
/// - Each coordinate follows the `hex_decimal_to_field` rule (hex if 0x prefix, otherwise decimal).
pub fn coords_to_affine<A>(x_str: &str, y_str: &str) -> Result<A, FieldParseError>
where
    A: FromCoords,
    A::BaseField: PrimeField,
{
    let x = hex_decimal_to_field::<A::BaseField>(x_str)?;
    let y = hex_decimal_to_field::<A::BaseField>(y_str)?;

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
