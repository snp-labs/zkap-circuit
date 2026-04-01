use ark_ff::PrimeField;

pub fn str_to_fields<F: PrimeField>(s: &str) -> Vec<F> {
    let bytes = s.as_bytes();

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = (bytes.len() + (limb_width - 1)) / limb_width;
    let expected_length = n_limbs * limb_width;

    assert_eq!(bytes.len(), expected_length);

    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}

/// 문자열을 패딩 후 필드 원소 벡터로 변환합니다.
///
/// 문자열을 `target_len` 길이까지 `pad` 문자로 패딩한 후,
/// limb 단위로 분할하여 필드 원소 벡터로 변환합니다.
pub fn str_to_limbs<F: PrimeField>(s: &str, target_len: usize, pad: u8) -> Vec<F> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.resize(target_len, pad);

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = (bytes.len() + (limb_width - 1)) / limb_width;
    let expected_length = n_limbs * limb_width;

    assert_eq!(bytes.len(), expected_length);

    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}
