use ark_ff::PrimeField;

pub fn fit_len_to_field<F: PrimeField>(len: &usize) -> usize {
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = (len + (limb_width - 1)) / limb_width;
    let max_claim_len = n_limbs * limb_width;
    max_claim_len
}

// TODO: 더 나은 형태 고려
pub fn calculate_fitted_lengths<F: PrimeField>(
    max_aud_len: Option<usize>,
    max_iss_len: Option<usize>,
    max_sub_len: usize,
) -> (usize, usize, usize) {
    // None이면 max_sub_len을 사용합니다.
    let aud_len_to_fit = max_aud_len.unwrap_or(max_sub_len);
    let fitted_aud_len = fit_len_to_field::<F>(&aud_len_to_fit);

    // None이면 max_sub_len을 사용합니다.
    let iss_len_to_fit = max_iss_len.unwrap_or(max_sub_len);
    let fitted_iss_len = fit_len_to_field::<F>(&iss_len_to_fit);

    let fitted_sub_len = fit_len_to_field::<F>(&max_sub_len);

    (fitted_aud_len, fitted_iss_len, fitted_sub_len)
}

pub fn pad_str<S: Into<String>>(s: S, target_len: usize, pad_char: u8) -> String {
    let s = s.into();
    let len = s.len();
    if len < target_len {
        let mut padded = s;
        padded.push_str(
            &std::iter::repeat(pad_char as char)
                .take(target_len - len)
                .collect::<String>(),
        );
        padded
    } else {
        s
    }
}
