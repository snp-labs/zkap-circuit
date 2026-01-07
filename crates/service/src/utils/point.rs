// point.rs

use std::fmt::UpperHex;
use std::str::FromStr;

use ark_ec::{
    AffineRepr, CurveGroup,
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_ff::PrimeField;

use crate::error::error::PointError;

// ---------------------------
// 좌표 → Affine
// ---------------------------

pub trait FromCoords: AffineRepr {
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self;
}

// SW: G1Affine, G2Affine 등
impl<P> FromCoords for SWAffine<P>
where
    P: SWCurveConfig,
    P::BaseField: PrimeField,
{
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new(x, y)
    }
}

// Twisted Edwards: EdOnBN 등
impl<P> FromCoords for TEAffine<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    fn from_coords(x: Self::BaseField, y: Self::BaseField) -> Self {
        Self::new(x, y)
    }
}

// ---------------------------
// Affine → String 좌표
// ---------------------------

pub trait ToHexStr: AffineRepr
where
    Self::BaseField: PrimeField,
    <Self::BaseField as PrimeField>::BigInt: UpperHex,
{
    fn to_hex_str(&self) -> Vec<String> {
        [self.x(), self.y()]
            .into_iter()
            .map(|coord_opt| match coord_opt {
                Some(field_elem) => format!("0x{:X}", field_elem.into_bigint()),
                None => "0x0".to_string(),
            })
            .collect()
    }
}

// 모든 적절한 AffineRepr에 대해 한 번에 구현
impl<T> ToHexStr for T
where
    T: AffineRepr,
    T::BaseField: PrimeField,
    <T::BaseField as PrimeField>::BigInt: UpperHex,
{
}

pub trait ToDecimalStr: AffineRepr
where
    Self::BaseField: PrimeField,
{
    fn to_decimal_str(&self) -> Vec<String> {
        [self.x(), self.y()]
            .into_iter()
            .map(|coord_opt| {
                coord_opt
                    .map(|field_elem| field_elem.to_string())
                    .unwrap_or_else(|| "0".to_string())
            })
            .collect()
    }
}

impl<T> ToDecimalStr for T
where
    T: AffineRepr,
    T::BaseField: PrimeField,
{
}

// ---------------------------
// String 좌표 → Affine
// ---------------------------

pub trait FromDecimalCoords {
    fn from_decimal_coords(x_str: &str, y_str: &str) -> Result<Self, PointError>
    where
        Self: Sized;
}

// SW 커브
impl<P> FromDecimalCoords for SWAffine<P>
where
    P: SWCurveConfig,
    P::BaseField: PrimeField,
{
    fn from_decimal_coords(x_str: &str, y_str: &str) -> Result<Self, PointError> {
        let x = P::BaseField::from_str(x_str).map_err(|_| PointError::InvalidDecimal)?;
        let y = P::BaseField::from_str(y_str).map_err(|_| PointError::InvalidDecimal)?;
        Ok(Self::new(x, y))
    }
}

// TE 커브
impl<P> FromDecimalCoords for TEAffine<P>
where
    P: TECurveConfig,
    P::BaseField: PrimeField,
{
    fn from_decimal_coords(x_str: &str, y_str: &str) -> Result<Self, PointError> {
        let x = P::BaseField::from_str(x_str).map_err(|_| PointError::InvalidDecimal)?;
        let y = P::BaseField::from_str(y_str).map_err(|_| PointError::InvalidDecimal)?;
        Ok(Self::new(x, y))
    }
}

// ---------------------------
// Field helpers
// ---------------------------

fn hex_to_bytes_even(s: &str) -> Result<Vec<u8>, PointError> {
    let mut hex_body = s.strip_prefix("0x").unwrap_or(s).to_owned();
    if hex_body.len() % 2 == 1 {
        hex_body.insert(0, '0');
    }
    Ok(hex::decode(&hex_body)?)
}

/// "0x..."면 hex, 아니면 10진수로 간주
pub fn hex_decimal_to_field<F: PrimeField>(s: &str) -> Result<F, PointError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let bytes = hex_to_bytes_even(s)?;
        Ok(F::from_be_bytes_mod_order(&bytes))
    } else {
        Ok(F::from_str(s).map_err(|_| PointError::InvalidDecimal)?)
    }
}

pub fn decimal_str_to_field<F>(s: &str) -> Result<F, PointError>
where
    F: PrimeField,
{
    F::from_str(s).map_err(|_| PointError::InvalidDecimal)
}

/// ASCII를 big-endian limb로 잘라서 각 limb를 field로 해석
pub fn ascii_to_field_be<F: PrimeField>(s: &str) -> Result<Vec<F>, PointError> {
    let bytes = s.as_bytes();
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if bytes.len() % limb_width != 0 {
        return Err(PointError::InvalidAsciiLength {
            expected: limb_width,
            actual: bytes.len(),
        });
    }

    Ok(bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect())
}

/// hex 좌표 두 개를 Affine 포인트로 변환 (Result 버전)
pub fn hex_point_to_affine<A>(x_str: &str, y_str: &str) -> Result<A, PointError>
where
    A: FromCoords,
    A::BaseField: PrimeField,
{
    let x = hex_decimal_to_field::<A::BaseField>(x_str)?;
    let y = hex_decimal_to_field::<A::BaseField>(y_str)?;
    Ok(A::from_coords(x, y))
}

pub trait FromStrings: Sized {
    type Err;
    fn from_strings(strings: &[String]) -> Result<Self, Self::Err>;
}

// ---------------------------
// 고수준: &[String] → Vec<Affine>
// ---------------------------

pub fn parse_coords_to_affine<C>(coords: &[String]) -> Result<Vec<C::Affine>, PointError>
where
    C: CurveGroup,
    C::Affine: FromDecimalCoords,
{
    coords
        .chunks(2)
        .map(|pair| {
            if pair.len() != 2 {
                return Err(PointError::InvalidCoordPair(pair.len()));
            }

            C::Affine::from_decimal_coords(&pair[0], &pair[1])
        })
        .collect()
}
