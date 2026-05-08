use ark_ff::PrimeField;

/// Converts a string to field elements, returning an error if the length
/// is not a multiple of the limb width.
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
pub enum TextError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    #[error("Invalid length: expected multiple of {expected_multiple}, got {actual}")]
    InvalidLength {
        expected_multiple: usize,
        actual: usize,
    },
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[cfg(feature = "field-serde")]
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),
    #[cfg(feature = "field-serde")]
    #[error("Invalid decimal string: {0}")]
    InvalidDecimal(String),
}

/// Pads a string to the target length using the given pad character.
///
/// Returns an error if the string is already longer than the target length.
pub fn pad(s: &str, target_len: usize, pad_char: char) -> Result<String, TextError> {
    if s.len() > target_len {
        return Err(TextError::InvalidFormat(format!(
            "String length {} exceeds target length {}",
            s.len(),
            target_len
        )));
    }
    let mut result = String::with_capacity(target_len);
    result.push_str(s);
    let pad_needed = target_len - s.len();
    result.extend(std::iter::repeat_n(pad_char, pad_needed));
    Ok(result)
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

/// Parses an input string as a field element.
/// - If it starts with "0x..." or "0X...", treats it as hex and reduces `mod p`.
/// - Otherwise, parses it as a decimal.
#[cfg(feature = "field-serde")]
pub fn hex_decimal_to_field<F: PrimeField>(s: &str) -> Result<F, ConvertError> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let mut hex_body = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s)
            .to_owned();
        if hex_body.len() % 2 == 1 {
            hex_body.insert(0, '0');
        }
        let bytes = hex::decode(&hex_body).map_err(|e| ConvertError::InvalidHex(e.to_string()))?;
        Ok(F::from_be_bytes_mod_order(&bytes))
    } else {
        Ok(F::from_str(s).map_err(|_| ConvertError::InvalidDecimal(s.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type F = ark_bn254::Fr;

    #[test]
    fn test_try_str_to_fields_exact_limb_width() {
        let s = "A".repeat(31); // bn254: limb_width = (254-1)/8 = 31
        let result = try_str_to_fields::<F>(&s).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_try_str_to_fields_two_limbs() {
        let s = "B".repeat(62);
        let result = try_str_to_fields::<F>(&s).unwrap();
        assert_eq!(result.len(), 2);
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
    fn test_str_to_limbs_big_endian_consistency() {
        let s = "A".repeat(31);
        let from_fields = try_str_to_fields::<F>(&s).unwrap();
        let from_limbs = str_to_limbs::<F>(&s, 31, 0);
        assert_eq!(from_fields, from_limbs);
    }
}
