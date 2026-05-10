//! Native Base64 URL-safe decoding helpers.
//!
//! [`decode_any_base64`] and [`decode_any_base64_to_string`] wrap the `base64` crate for
//! URL-safe (no-pad) decoding used by the service layer. [`Base64CharBits`] and
//! [`IndexBits::from_base64_url`] decompose a single character into bits for witness
//! generation. NULL-padding convention: when `idx == 0` (the `'A'` character acts as
//! padding), it is normalised to `'A'` (65) rather than rejected.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::Engine as _;
use base64::engine::general_purpose::{self};

use super::error::Base64Error;

/// 6 bits (Big-Endian) representing a single Base64 character
#[derive(Debug, Clone, Copy, Default, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Base64CharBits {
    /// Order: [MSB, ..., LSB]
    pub bits: [bool; 6],
}

impl Base64CharBits {
    /// Creates an instance from an index value (0~63) converted to a Big-Endian bit array
    pub fn from_index(val: u8) -> Self {
        let mut bits = [false; 6];
        for (i, bit) in bits.iter_mut().enumerate() {
            let shift = 5 - i;
            *bit = (val >> shift) & 1 == 1;
        }
        Self { bits }
    }
}

/// Per-character 6-bit decompositions for a padded Base64 URL-safe input.
///
/// Each entry in `inner` corresponds to one Base64 character position (including
/// NULL-pad positions). Used as witness input when allocating
/// [`IndexBitsVar`](crate::base64::constraints::IndexBitsVar) in-circuit.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IndexBits {
    /// One [`Base64CharBits`] per input character in MSB-first order.
    pub inner: Vec<Base64CharBits>,
}

impl IndexBits {
    /// Create an empty IndexBits with the given length
    pub fn empty(len: usize) -> Self {
        Self {
            inner: vec![Base64CharBits::default(); len],
        }
    }

    /// Convert a Base64URL string into a vector of circuit input structs (with padding)
    pub fn from_base64_url(input: &str, padded_len: usize) -> Result<Self, Base64Error> {
        if input.len() > padded_len {
            return Err(Base64Error::InputTooLong(input.len(), padded_len));
        }

        let input_bytes = input.as_bytes();
        let mut inner = Vec::with_capacity(padded_len);

        for i in 0..padded_len {
            // 1. Get the byte (positions out of range are padding)
            let idx = if i < input_bytes.len() {
                // Decode and validate the input character
                Self::decode_char(input_bytes[i], i)?
            } else {
                // Padding is 0
                0
            };

            // 3. Create struct (Index -> Base64CharBits)
            // Bit decomposition logic is encapsulated in Base64CharBits::from_index
            inner.push(Base64CharBits::from_index(idx));
        }

        Ok(Self { inner })
    }

    /// Internal helper: character -> index (0~63)
    fn decode_char(byte: u8, index: usize) -> Result<u8, Base64Error> {
        match byte {
            b'A'..=b'Z' => Ok(byte - b'A'),
            b'a'..=b'z' => Ok(byte - b'a' + 26),
            b'0'..=b'9' => Ok(byte - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(Base64Error::InvalidBase64Character(index, byte as char)),
        }
    }
}

/// Decodes a Base64 string by sequentially trying multiple standards
/// (URL-safe, Standard, with and without padding).
pub fn decode_any_base64(input: &str) -> Result<Vec<u8>, Base64Error> {
    // Use or_else instead of nested match for readability.
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(input))
        .or_else(|_| general_purpose::URL_SAFE.decode(input))
        .or_else(|_| general_purpose::STANDARD.decode(input))
        .map_err(Base64Error::from)
}

/// Decodes a Base64 string (any variant) and interprets the result as UTF-8.
///
/// Wraps [`decode_any_base64`] and converts the raw bytes to a `String`.
/// Returns [`Base64Error::InvalidUtf8`] if the payload is valid Base64 but
/// not valid UTF-8.
pub fn decode_any_base64_to_string(input: &str) -> Result<String, Base64Error> {
    let decoded_bytes = decode_any_base64(input)?;
    String::from_utf8(decoded_bytes).map_err(Base64Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 1. Base64CharBits unit tests ---

    #[test]
    fn test_char_bits_conversion() {
        // Case A: Index 0 ('A') -> 000000
        let zero = Base64CharBits::from_index(0);
        assert_eq!(zero.bits, [false, false, false, false, false, false]);

        // Case B: Index 1 ('B') -> 000001 (MSB First check)
        let one = Base64CharBits::from_index(1);
        assert_eq!(one.bits, [false, false, false, false, false, true]);

        // Case C: Index 32 -> 100000 (MSB First check)
        let thirty_two = Base64CharBits::from_index(32);
        assert_eq!(thirty_two.bits, [true, false, false, false, false, false]);

        // Case D: Index 63 ('_') -> 111111
        let max = Base64CharBits::from_index(63);
        assert_eq!(max.bits, [true, true, true, true, true, true]);
    }

    // --- 2. IndexBits success cases (Success Scenarios) ---

    #[test]
    fn test_index_bits_standard_decoding() {
        // Input: "Hm" (Target Len: 2)
        // 'H': Index 7  -> 000111
        // 'm': Index 38 -> 100110
        let witness = IndexBits::from_base64_url("Hm", 2).unwrap();

        assert_eq!(witness.inner.len(), 2);

        // 'H' Check
        assert_eq!(
            witness.inner[0].bits,
            [false, false, false, true, true, true]
        );
        // 'm' Check
        assert_eq!(
            witness.inner[1].bits,
            [true, false, false, true, true, false]
        );
    }

    #[test]
    fn test_index_bits_url_safe_chars() {
        // Input: "-_" (Target Len: 2)
        // '-': Index 62 -> 111110
        // '_': Index 63 -> 111111
        let witness = IndexBits::from_base64_url("-_", 2).unwrap();

        // '-' Check
        assert_eq!(witness.inner[0].bits, [true, true, true, true, true, false]);
        // '_' Check
        assert_eq!(witness.inner[1].bits, [true, true, true, true, true, true]);
    }

    #[test]
    fn test_index_bits_padding_logic() {
        // Input: "A" (Target Len: 3)
        // 'A': Index 0 -> 000000
        // Padding 1: -> 000000
        // Padding 2: -> 000000
        let witness = IndexBits::from_base64_url("A", 3).unwrap();

        assert_eq!(witness.inner.len(), 3);

        // Actual data 'A'
        assert_eq!(witness.inner[0].bits, [false; 6]);

        // Auto-generated padding
        assert_eq!(witness.inner[1].bits, [false; 6]); // All Zero
        assert_eq!(witness.inner[2].bits, [false; 6]); // All Zero
    }

    // --- 3. IndexBits edge/failure cases (Edge/Failure Scenarios) ---

    #[test]
    fn test_invalid_characters_handling() {
        // Input: "@!" (Target Len: 2)
        // '@': Invalid -> error expected
        // '!': Invalid -> error expected
        let result = IndexBits::from_base64_url("@!", 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_input() {
        // Input: "" (Target Len: 2)
        // All positions should be filled with padding (0)
        let witness = IndexBits::from_base64_url("", 2).unwrap();

        assert_eq!(witness.inner.len(), 2);
        assert_eq!(witness.inner[0].bits, [false; 6]);
        assert_eq!(witness.inner[1].bits, [false; 6]);
    }

    #[test]
    fn test_truncation() {
        // Input: "ABC" (Target Len: 2)
        // If input is longer than target length, an error should occur
        let result = IndexBits::from_base64_url("ABC", 2);
        assert!(result.is_err());
    }
}
