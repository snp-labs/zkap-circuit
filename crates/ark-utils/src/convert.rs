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

#[cfg(test)]
mod tests {
    use super::*;

    type F = ark_bn254::Fr;

    #[test]
    fn test_str_to_fields_exact_limb_width() {
        let s = "A".repeat(31); // bn254: limb_width = (254-1)/8 = 31
        let result = str_to_fields::<F>(&s);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_str_to_fields_two_limbs() {
        let s = "B".repeat(62);
        let result = str_to_fields::<F>(&s);
        assert_eq!(result.len(), 2);
    }

    #[test]
    #[should_panic]
    fn test_str_to_fields_non_multiple_panics() {
        let s = "hello"; // 5 bytes, not a multiple of 31
        let _ = str_to_fields::<F>(s);
    }

    #[test]
    fn test_str_to_limbs_padding_basic() {
        let result = str_to_limbs::<F>("hi", 31, 0);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_str_to_limbs_padding_value() {
        let result = str_to_limbs::<F>("AB", 31, 0x20);
        assert_eq!(result.len(), 1);
        let all_space = str_to_limbs::<F>("", 31, 0x20);
        assert_ne!(result[0], all_space[0]);
    }

    #[test]
    fn test_str_to_limbs_big_endian_consistency() {
        let s = "A".repeat(31);
        let from_fields = str_to_fields::<F>(&s);
        let from_limbs = str_to_limbs::<F>(&s, 31, 0);
        assert_eq!(from_fields, from_limbs);
    }
}
