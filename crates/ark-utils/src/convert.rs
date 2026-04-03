use ark_ff::PrimeField;

pub fn str_to_fields<F: PrimeField>(s: &str) -> Vec<F> {
    let bytes = s.as_bytes();

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = bytes.len().div_ceil(limb_width);
    let expected_length = n_limbs * limb_width;

    assert_eq!(bytes.len(), expected_length);

    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}

/// Converts a string to field elements after padding.
///
/// Pads the string to `target_len` with `pad` byte, then splits into
/// limb-sized chunks and converts each to a field element.
pub fn str_to_limbs<F: PrimeField>(s: &str, target_len: usize, pad: u8) -> Vec<F> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.resize(target_len, pad);

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    let n_limbs = bytes.len().div_ceil(limb_width);
    let expected_length = n_limbs * limb_width;

    assert_eq!(bytes.len(), expected_length);

    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}
