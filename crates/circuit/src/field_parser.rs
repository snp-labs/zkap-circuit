use std::fmt::UpperHex;

use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine as SWAffine, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
};
use ark_ff::PrimeField;

use crate::error::FieldParseError;

/// Affine 점의 (x, y) 좌표를 16진수 문자열(["0x..", "0x.."])로 변환합니다.
/// - 무한점(infinity)인 경우 "0x0"을 반환합니다.
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

/// Affine 점의 (x, y) 좌표를 10진수 문자열(["..", ".."])로 변환합니다.
/// - 무한점(infinity)인 경우 "0"을 반환합니다.
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

/// hex 문자열을 바이트로 디코딩합니다.
/// - "0x" prefix를 허용하고,
/// - hex 길이가 홀수면 앞에 '0'을 붙여 짝수 길이로 만든 뒤 디코딩합니다.
fn hex_to_bytes_even(s: &str) -> Result<Vec<u8>, FieldParseError> {
    let mut hex_body = s.strip_prefix("0x").unwrap_or(s).to_owned();
    if hex_body.len() % 2 == 1 {
        hex_body.insert(0, '0');
    }
    hex::decode(&hex_body).map_err(|_| FieldParseError::InvalidHex)
}

/// 입력 문자열을 field 원소로 파싱합니다.
/// - "0x..." 또는 "0X..." 로 시작하면 hex로 처리하여 `mod p`로 축약합니다.
/// - 그 외에는 10진수로 간주하여 파싱합니다.
pub fn hex_decimal_to_field<F: PrimeField>(s: &str) -> Result<F, FieldParseError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let bytes = hex_to_bytes_even(s)?;
        Ok(F::from_be_bytes_mod_order(&bytes))
    } else {
        Ok(F::from_str(s).map_err(|_| FieldParseError::InvalidDecimal)?)
    }
}

/// ASCII 바이트열을 big-endian limb 단위로 잘라 각 limb를 field 원소로 해석합니다.
/// - limb 폭은 `((MODULUS_BIT_SIZE-1)/8)`로 계산합니다.
/// - 입력 길이가 limb 폭의 배수가 아니면 에러를 반환합니다.
/// - (JWT claim 등을 “고정 폭 limb”로 패킹할 때 유용)
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

/// (x, y) 좌표 문자열을 Affine 포인트로 변환합니다.
/// - 각 좌표는 `hex_decimal_to_field` 규칙(0x면 hex, 아니면 decimal)을 따릅니다.
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

// SW: G1Affine, G2Affine 등
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

// Twisted Edwards: EdOnBN 등
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
