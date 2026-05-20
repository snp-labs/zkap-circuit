//! String-to-field and padding conversion helpers.
//!
//! Exports: [`try_str_to_fields`], [`pad`], [`str_to_limbs`], [`ConvertError`],
//! [`TextError`], and (with `field-serde` feature) `hex_decimal_to_field`.
//! All but the last are always available regardless of feature flags.

use ark_ff::PrimeField;

/// Pack ASCII bytes into base-field elements, one limb per
/// `(MODULUS_BIT_SIZE - 1) / 8` byte chunk.
///
/// The chunk width is one byte short of the modulus byte size so each chunk
/// is always less than the field modulus — i.e. `from_be_bytes_mod_order`
/// is a no-op reduction and the encoding is injective on the input bytes.
/// This is what the circuit relies on when comparing a Poseidon-hashed JWT
/// claim against its in-circuit field representation; a multiple-of-limb
/// input length is therefore a correctness invariant, not just a
/// convenience, and `Err(InvalidLength)` here means the caller failed to
/// pad upstream (use [`pad`] when the source is variable-width).
pub fn try_str_to_fields<F: PrimeField>(s: &str) -> Result<Vec<F>, ConvertError> {
    let bytes = s.as_bytes();
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if bytes.len() % limb_width != 0 {
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

/// Errors returned by [`pad`] when padding-related invariants are violated.
#[derive(Debug, thiserror::Error)]
pub enum TextError {
    /// The input string did not satisfy the expected text format
    /// (e.g. exceeded the requested padding length).
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

/// Errors returned by string-to-field conversion helpers in this module.
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    /// The input byte length is not a multiple of the field's limb width.
    #[error("Invalid length: expected multiple of {expected_multiple}, got {actual}")]
    InvalidLength {
        /// The required multiple (limb width in bytes).
        expected_multiple: usize,
        /// The observed input length in bytes.
        actual: usize,
    },
    /// Generic format violation message for callers that cannot describe the
    /// failure in a more specific variant.
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    /// Returned by [`hex_decimal_to_field`] when a `0x`-prefixed input is not
    /// a valid hex string.
    #[cfg(feature = "field-serde")]
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),
    /// Returned by [`hex_decimal_to_field`] when a non-`0x` input fails
    /// decimal parsing.
    #[cfg(feature = "field-serde")]
    #[error("Invalid decimal string: {0}")]
    InvalidDecimal(String),
}

/// Pack raw bytes into base-field elements, one limb per
/// `(MODULUS_BIT_SIZE - 1) / 8` byte chunk.
///
/// Identical algorithm to [`try_str_to_fields`] but operates on an
/// arbitrary byte slice rather than a UTF-8 string. Use this when the
/// source data is already binary (e.g. SHA-padded JWT buffers, RSA
/// modulus/signature blocks) rather than an ASCII/UTF-8 string.
///
/// The same length-multiple invariant applies: `bytes.len()` must be an
/// exact multiple of the limb width, otherwise `Err(InvalidLength)` is
/// returned so callers catch alignment bugs at the boundary rather than
/// silently dropping trailing bytes.
pub fn try_bytes_to_fields<F: PrimeField>(bytes: &[u8]) -> Result<Vec<F>, ConvertError> {
    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;

    if bytes.len() % limb_width != 0 {
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
/// limb-sized chunks and converts each to a field element. Returns
/// `Err(TextError::InvalidFormat)` if `s` is longer than `target_len`:
/// the JWT-claim length invariant the circuit relies on must not be
/// silently truncated.
pub fn str_to_limbs<F: PrimeField>(
    s: &str,
    target_len: usize,
    pad: u8,
) -> Result<Vec<F>, TextError> {
    if s.len() > target_len {
        return Err(TextError::InvalidFormat(format!(
            "String length {} exceeds target length {}",
            s.len(),
            target_len
        )));
    }

    let mut bytes = s.as_bytes().to_vec();
    bytes.resize(target_len, pad);

    let limb_width = (F::MODULUS_BIT_SIZE - 1) as usize / 8;
    Ok(bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect())
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
        let result = str_to_limbs::<F>("hi", 31, 0).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_str_to_limbs_padding_value() {
        let result = str_to_limbs::<F>("AB", 31, 0x20).unwrap();
        assert_eq!(result.len(), 1);
        let all_space = str_to_limbs::<F>("", 31, 0x20).unwrap();
        assert_ne!(result[0], all_space[0]);
    }

    #[test]
    fn test_str_to_limbs_big_endian_consistency() {
        let s = "A".repeat(31);
        let from_fields = try_str_to_fields::<F>(&s).unwrap();
        let from_limbs = str_to_limbs::<F>(&s, 31, 0).unwrap();
        assert_eq!(from_fields, from_limbs);
    }

    #[test]
    fn test_try_bytes_to_fields_exact_limb_width() {
        let bytes = vec![0x41u8; 31]; // 31 bytes = one BN254 limb
        let result = try_bytes_to_fields::<F>(&bytes).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_try_bytes_to_fields_two_limbs() {
        let bytes = vec![0x42u8; 62]; // 62 bytes = two BN254 limbs
        let result = try_bytes_to_fields::<F>(&bytes).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_try_bytes_to_fields_non_multiple_returns_error() {
        let bytes = vec![0x01u8; 5]; // 5 bytes, not a multiple of 31
        let result = try_bytes_to_fields::<F>(&bytes);
        assert!(
            matches!(result, Err(ConvertError::InvalidLength { .. })),
            "non-multiple-of-limb input must surface as Err(InvalidLength)"
        );
    }

    #[test]
    fn test_try_bytes_to_fields_parity_with_try_str_to_fields_ascii() {
        // For ASCII input, try_bytes_to_fields and try_str_to_fields must agree.
        let s = "A".repeat(31);
        let from_str = try_str_to_fields::<F>(&s).unwrap();
        let from_bytes = try_bytes_to_fields::<F>(s.as_bytes()).unwrap();
        assert_eq!(from_str, from_bytes);
    }

    #[test]
    fn test_try_bytes_to_fields_parity_two_limbs() {
        let s = "B".repeat(62);
        let from_str = try_str_to_fields::<F>(&s).unwrap();
        let from_bytes = try_bytes_to_fields::<F>(s.as_bytes()).unwrap();
        assert_eq!(from_str, from_bytes);
    }

    #[test]
    fn test_try_bytes_to_fields_zero_length() {
        let result = try_bytes_to_fields::<F>(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_try_str_to_fields_rejects_over_length() {
        let result = str_to_limbs::<F>("ABCDE", 3, 0x20);
        assert!(
            matches!(result, Err(TextError::InvalidFormat(_))),
            "over-length input must surface as Err, not silent truncation"
        );
    }
}
