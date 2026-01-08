use ark_crypto_primitives::{crh::CRHScheme, sponge::Absorb};
use ark_ff::PrimeField;
use common::{
    constants::AnchorConfig,
    field_parser::{ascii_to_field_be, hex_decimal_to_field},
};
use gadget::anchor::poseidon::PoseidonAnchor;

use crate::{error::ApplicationError, types::Secret};

pub(crate) fn derive_x_from_secret<F, CRH>(
    secret: &Secret,
    hash_params: &CRH::Parameters,
    ctx: &AnchorConfig,
) -> Result<F, ApplicationError>
where
    F: PrimeField + Absorb,
    CRH: CRHScheme<Input = [F], Output = F>,
{
    let input = secret_to_padded_string(
        secret,
        ctx.max_aud_len,
        ctx.max_iss_len,
        ctx.max_sub_len,
        ctx.pad_char,
    )?;

    let limbs =
        ascii_to_field_be(&input).map_err(|e| ApplicationError::InvalidFormat(e.to_string()))?;

    let hashed =
        CRH::evaluate(hash_params, limbs).map_err(|_| ApplicationError::PoseidonHashError)?;

    Ok(hashed)
}

/// 개별 SecretDto를 패딩 및 연결하여 문자열로 반환합니다.
pub(crate) fn secret_to_padded_string(
    secret: &Secret,
    max_aud_len: usize,
    max_iss_len: usize,
    max_sub_len: usize,
    pad_char: char,
) -> Result<String, ApplicationError> {
    let aud_processed = pad(&secret.aud, max_aud_len, pad_char)?;
    let iss_processed = pad(&secret.iss, max_iss_len, pad_char)?;
    let sub_processed = pad(&secret.sub, max_sub_len, pad_char)?;

    Ok([aud_processed, iss_processed, sub_processed].concat())
}

/// 문자열 패딩 로직
fn pad(s: &str, target_len: usize, pad_char: char) -> Result<String, ApplicationError> {
    if s.len() > target_len {
        return Err(ApplicationError::InvalidFormat(format!(
            "String length exceeds target length: {} > {}",
            s.len(),
            target_len
        )));
    }

    let mut result = String::with_capacity(target_len);
    result.push_str(s);
    let pad_needed = target_len - s.len();
    result.extend(std::iter::repeat(pad_char).take(pad_needed));

    Ok(result)
}

/// Anchor를 문자열 배열로부터 파싱하여 PoseidonAnchor와 hanchor로 변환합니다.
///
/// # Arguments
/// * `raw_anchor` - Anchor 값들과 hanchor를 포함하는 문자열 배열
///                  마지막 요소가 hanchor, 나머지가 anchor 값들
///
/// # Returns
/// (PoseidonAnchor, hanchor) 튜플
pub fn convert_raw_anchor<F: PrimeField>(
    raw_anchor: &[String],
) -> Result<(PoseidonAnchor<F>, F), ApplicationError> {
    if raw_anchor.is_empty() {
        return Err(ApplicationError::InvalidFormat(
            "Anchor parts cannot be empty".to_string(),
        ));
    }

    // 마지막 요소를 hanchor로 분리
    let (raw_hanchor, raw_anchor) = raw_anchor.split_last().ok_or_else(|| {
        ApplicationError::InvalidFormat("Failed to split anchor parts".to_string())
    })?;

    // hanchor 파싱
    let hanchor = hex_decimal_to_field::<F>(raw_hanchor).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse hanchor '{}': {}", raw_hanchor, e))
    })?;

    // anchor 값들 파싱
    let fields: Vec<F> = raw_anchor
        .iter()
        .map(|f| {
            hex_decimal_to_field::<F>(f)
                .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))
        })
        .collect::<Result<Vec<F>, ApplicationError>>()?;

    let anchor = PoseidonAnchor::new(fields);

    Ok((anchor, hanchor))
}
