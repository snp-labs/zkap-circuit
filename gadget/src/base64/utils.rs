use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::{self};

use super::error::Base64Error;

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

fn get_urlsafe_base64_value_map() -> HashMap<u8, u8> {
    let mut map = HashMap::with_capacity(64);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (i, &byte) in alphabet.iter().enumerate() {
        map.insert(byte, i as u8);
    }
    map
}

fn value_to_6bits_lsb(value: u8) -> [bool; 6] {
    let mut bits = [false; 6];
    for i in 0..6 {
        if (value >> i) & 1 == 1 {
            bits[i] = true;
        }
    }
    bits
}

pub fn base64_to_6bit_bools(encoded_str: &[u8]) -> Result<Vec<bool>, Base64Error> {
    assert!(
        encoded_str.len() % 4 == 0,
        "Base64 string length must be a multiple of 4"
    );
    let value_map = get_urlsafe_base64_value_map();
    let mut result_vec = Vec::with_capacity(encoded_str.len());

    for (char_index, c) in encoded_str.iter().enumerate() {
        // 1. Base64 문자 테이블에서 값(0-63) 조회
        let value = match value_map.get(&c) {
            Some(val) => *val,
            None => {
                return Err(Base64Error::WrongCharacter(char_index, *c as char));
            }
        };

        // 2. 값을 6비트 bool 배열 (LSB first)로 변환
        let bits = value_to_6bits_lsb(value); // 에러는 여기서 발생 안 함

        // 3. 결과 벡터에 추가
        result_vec.extend_from_slice(&bits);
    }

    Ok(result_vec)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose;
    use base64::{DecodeError, Engine as _};

    use crate::base64::decode_any_base64;
    use crate::base64::error::Base64Error;

    enum EncodeType {
        StandardNoPad,
        StandardWithPad,
        UrlSafeNoPad,
        UrlSafeWithPad,
    }

    fn test_base64_decode_trivial(input: &str, mode: EncodeType) {
        let encode = generate_base64(input, mode);
        let decode = decode_any_base64(&encode).unwrap();
        assert_eq!(decode, input.as_bytes());
    }

    #[test]
    fn test_base64_decode_trivial1() {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";
        test_base64_decode_trivial(input, EncodeType::StandardNoPad);
    }

    #[test]
    fn test_base64_decode_trivial2() {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        test_base64_decode_trivial(input, EncodeType::UrlSafeNoPad);
    }

    #[test]
    fn test_base64_decode_trivial3() {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";
        test_base64_decode_trivial(input, EncodeType::StandardWithPad);
    }

    #[test]
    fn test_base64_decode_trivial4() {
        let input = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        test_base64_decode_trivial(input, EncodeType::UrlSafeWithPad);
    }

    fn test_base64_decode_error(input: &str, expected_error_type: Base64Error) {
        match decode_any_base64(input) {
            Ok(_) => panic!("Expected error, but got Ok"),
            Err(e) => assert_eq!(e, expected_error_type),
        }
    }

    #[test]
    fn test_base64_decode_error_trivial1() {
        let err_input = "SGVsbG9Ad29ybGQ%";
        test_base64_decode_error(err_input, DecodeError::InvalidByte(15, b'%').into());
    }

    #[test]
    fn test_base64_decode_error_trivial2() {
        let err_input = "SGVsbG8=V29ybGQh";
        test_base64_decode_error(err_input, DecodeError::InvalidByte(7, b'=').into());
    }

    #[test]
    fn test_base64_decode_error_trivial3() {
        let err_input = "SGVsbG8h==ABC";
        test_base64_decode_error(err_input, DecodeError::InvalidByte(8, b'=').into());
    }

    #[test]
    fn test_base64_decode_error_trivial4() {
        let err_input = "Y";
        test_base64_decode_error(err_input, DecodeError::InvalidLength(1).into());
    }

    #[test]
    fn test_base64_decode_error_trivial5() {
        let err_input = "TQ=";
        test_base64_decode_error(err_input, DecodeError::InvalidPadding.into());
    }

    fn generate_base64(input: &str, mode: EncodeType) -> String {
        match mode {
            EncodeType::StandardNoPad => general_purpose::STANDARD_NO_PAD.encode(input),
            EncodeType::StandardWithPad => general_purpose::STANDARD.encode(input),
            EncodeType::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.encode(input),
            EncodeType::UrlSafeWithPad => general_purpose::URL_SAFE.encode(input),
        }
    }
}
