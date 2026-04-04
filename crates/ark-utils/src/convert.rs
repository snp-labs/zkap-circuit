use ark_ff::PrimeField;

#[deprecated(note = "use try_str_to_fields (Result-returning) or field_serde::ascii_to_field_be instead")]
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

/// Converts a string to field elements, returning an error if the length
/// is not a multiple of the limb width.
///
/// This is the fallible replacement for [`str_to_fields`].
pub fn try_str_to_fields<F: PrimeField>(s: &str) -> Result<Vec<F>, ConvertError> {
    let bytes = s.as_bytes();
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if !bytes.len().is_multiple_of(limb_width) {
        return Err(ConvertError::InvalidLength {
            expected_multiple: limb_width,
            actual: bytes.len(),
        });
    }

    Ok(bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect())
}

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("Invalid length: expected multiple of {expected_multiple}, got {actual}")]
    InvalidLength {
        expected_multiple: usize,
        actual: usize,
    },
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
    #[allow(deprecated)]
    use super::*;

    type F = ark_bn254::Fr;

    #[test]
    #[allow(deprecated)]
    fn test_str_to_fields_exact_limb_width() {
        let s = "A".repeat(31); // bn254: limb_width = (254-1)/8 = 31
        let result = str_to_fields::<F>(&s);
        assert_eq!(result.len(), 1);
    }

    #[test]
    #[allow(deprecated)]
    fn test_str_to_fields_two_limbs() {
        let s = "B".repeat(62);
        let result = str_to_fields::<F>(&s);
        assert_eq!(result.len(), 2);
    }

    #[test]
    #[should_panic]
    #[allow(deprecated)]
    fn test_str_to_fields_non_multiple_panics() {
        let s = "hello"; // 5 bytes, not a multiple of 31
        let _ = str_to_fields::<F>(s);
    }

    #[test]
    fn test_try_str_to_fields_exact_limb_width() {
        let s = "A".repeat(31);
        let result = try_str_to_fields::<F>(&s).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_try_str_to_fields_non_multiple_returns_error() {
        let s = "hello"; // 5 bytes, not a multiple of 31
        assert!(try_str_to_fields::<F>(s).is_err());
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
    #[allow(deprecated)]
    fn test_str_to_limbs_big_endian_consistency() {
        let s = "A".repeat(31);
        let from_fields = str_to_fields::<F>(&s);
        let from_limbs = str_to_limbs::<F>(&s, 31, 0);
        assert_eq!(from_fields, from_limbs);
    }
}
