use base64::Engine as _;
use base64::engine::general_purpose::{self};

use super::error::Base64Error;

/// [단위 구조체] Base64 문자 하나에 해당하는 6비트 (Big-Endian)
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Base64CharBits {
    /// 순서: [MSB, ..., LSB]
    pub bits: [bool; 6],
}

impl Base64CharBits {
    /// 인덱스 값(0~63)을 받아 Big-Endian 비트 배열로 변환하여 생성
    pub fn from_index(val: u8) -> Self {
        let mut bits = [false; 6];
        for i in 0..6 {
            let shift = 5 - i;
            bits[i] = (val >> shift) & 1 == 1;
        }
        Self { bits }
    }
}

#[derive(Debug, Clone)]
pub struct IndexBits {
    pub inner: Vec<Base64CharBits>,
}

impl IndexBits {
    /// 빈 IndexBits 생성 (길이만 지정)
    pub fn empty(len: usize) -> Self {
        Self {
            inner: vec![Base64CharBits::default(); len],
        }
    }

    /// Base64URL 문자열을 회로 입력용 구조체 벡터로 변환 (패딩 포함)
    pub fn from_base64_url(input: &str, padded_len: usize) -> Result<Self, Base64Error> {
        if input.len() > padded_len {
            return Err(Base64Error::InputTooLong(input.len(), padded_len));
        }

        let input_bytes = input.as_bytes();
        let mut inner = Vec::with_capacity(padded_len);

        for i in 0..padded_len {
            // 1. 바이트 가져오기 (범위 밖은 패딩)
            let idx = if i < input_bytes.len() {
                // 입력된 문자는 디코딩 및 검증
                Self::decode_char(input_bytes[i], i)?
            } else {
                // 패딩은 0
                0
            };

            // 3. 구조체 생성 (Index -> Base64CharBits)
            // 비트 분해 로직은 Base64CharBits::from_index 안에 숨겨짐
            inner.push(Base64CharBits::from_index(idx));
        }

        Ok(Self { inner })
    }

    /// 내부 헬퍼: 문자 -> 인덱스(0~63)
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

/// 여러 표준(URL-safe, Standard, padding 유무)을 순차적으로 시도하여
/// Base64 문자열을 디코딩합니다.
pub fn decode_any_base64(input: &str) -> Result<Vec<u8>, Base64Error> {
    // 2. 중첩된 match 대신 or_else를 사용하여 가독성을 높입니다.
    general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(input))
        .or_else(|_| general_purpose::URL_SAFE.decode(input))
        .or_else(|_| general_purpose::STANDARD.decode(input))
        .map_err(Base64Error::from)
}

pub fn decode_any_base64_to_string(input: &str) -> Result<String, Base64Error> {
    let decoded_bytes = decode_any_base64(input)?;
    String::from_utf8(decoded_bytes).map_err(Base64Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 1. Base64CharBits 단위 테스트 ---

    #[test]
    fn test_char_bits_conversion() {
        // Case A: Index 0 ('A') -> 000000
        let zero = Base64CharBits::from_index(0);
        assert_eq!(zero.bits, [false, false, false, false, false, false]);

        // Case B: Index 1 ('B') -> 000001 (MSB First 확인)
        let one = Base64CharBits::from_index(1);
        assert_eq!(one.bits, [false, false, false, false, false, true]);

        // Case C: Index 32 -> 100000 (MSB First 확인)
        let thirty_two = Base64CharBits::from_index(32);
        assert_eq!(thirty_two.bits, [true, false, false, false, false, false]);

        // Case D: Index 63 ('_') -> 111111
        let max = Base64CharBits::from_index(63);
        assert_eq!(max.bits, [true, true, true, true, true, true]);
    }

    // --- 2. IndexBits 성공 케이스 (Success Scenarios) ---

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

        // 실제 데이터 'A'
        assert_eq!(witness.inner[0].bits, [false; 6]);

        // 자동 생성된 패딩
        assert_eq!(witness.inner[1].bits, [false; 6]); // All Zero
        assert_eq!(witness.inner[2].bits, [false; 6]); // All Zero
    }

    // --- 3. IndexBits 실패/경계 케이스 (Edge/Failure Scenarios) ---

    #[test]
    fn test_invalid_characters_handling() {
        // Input: "@!" (Target Len: 2)
        // '@': Invalid -> 오류 발생
        // '!': Invalid -> 오류 발생
        let result = IndexBits::from_base64_url("@!", 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_input() {
        // Input: "" (Target Len: 2)
        // 모두 패딩(0)으로 채워져야 함
        let witness = IndexBits::from_base64_url("", 2).unwrap();

        assert_eq!(witness.inner.len(), 2);
        assert_eq!(witness.inner[0].bits, [false; 6]);
        assert_eq!(witness.inner[1].bits, [false; 6]);
    }

    #[test]
    fn test_truncation() {
        // Input: "ABC" (Target Len: 2)
        // 입력이 목표 길이보다 길 경우, 오류 발생
        let result = IndexBits::from_base64_url("ABC", 2);
        assert!(result.is_err());
    }
}
