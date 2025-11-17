use regex::Regex;

use crate::{
    base64::base64_to_6bit_bools,
    jwt::{
        error::TokenError,
        types::{Claim, ClaimIndices},
    },
};

/// Parses a JSON claim from a string and extracts its metadata.
/// Returns claim with key, value, and position indices for circuit use.
pub fn parse_claim_from_str(s: &str, key: &str) -> Result<Claim, TokenError> {
    let pattern = format!(r#"\s*("{}")\s*:\s*("?[^",]*"?)\s*([,\}}])"#, key);
    let re = Regex::new(&pattern).unwrap();

    let (offset, len, colon_idx, value_idx, value_len, value_str) =
        if let Some(caps) = re.captures(s) {
            // 전체 매치된 claim
            let full_match = caps.get(0).unwrap();
            let full_match_str = full_match.as_str();
            let offset = full_match.start();
            let len = full_match_str.len();

            // 그룹 2: 값 (따옴표 포함 가능)
            let captured_value = caps.get(2).unwrap().as_str();

            // ':' 위치
            let colon_idx = full_match_str.find(':').unwrap();

            // 따옴표까지 포함한 값 저장
            let value_str = captured_value.to_string();

            // full_match 내에서 값 시작 위치 계산
            let rel_search_start = colon_idx + 1; // ':' 이후
            let found_at = full_match_str[rel_search_start..]
                .find(captured_value)
                .map(|i| i + rel_search_start)
                .unwrap();

            let value_idx = found_at;
            // 길이: 따옴표 포함
            let value_len = captured_value.len();

            (offset, len, colon_idx, value_idx, value_len, value_str)
        } else {
            return Err(TokenError::NotFoundKeyError(key.to_string()));
        };

    let indices = ClaimIndices {
        offset,
        len,
        colon_idx,
        value_idx,
        value_len,
    };

    Ok(Claim {
        key: key.to_string(),
        value: value_str,
        indices,
    })
}

/// Finds the offset of the first claim in the payload.
/// Used to determine optimal partition point for SHA-256 pre-computation.
pub fn find_first_claim_offset(claims: &[Claim]) -> Result<usize, TokenError> {
    claims
        .iter()
        .map(|c| c.indices.offset)
        .min()
        .ok_or_else(|| TokenError::NotFoundKeyError("any key".to_string()))
}

/// Finds the first occurring claim key in the payload string.
/// Returns (key, offset) tuple for the earliest match.
pub fn first_claim(payload: &str, keys: &[&str]) -> Result<(String, usize), TokenError> {
    keys.iter()
        .filter_map(|key| payload.find(key).map(|offset| (key.to_string(), offset)))
        .min_by_key(|(_, offset)| *offset)
        .ok_or_else(|| TokenError::NotFoundKeyError("any key".to_string()))
}

/// Resizes a string to exact length, padding with specified character.
/// Ensures fixed-size strings for circuit compatibility.
pub fn resize(s: &str, max_len: usize, pad_char: u8) -> String {
    let mut resized = s.to_string();

    if resized.len() < max_len {
        let padding_len = max_len - resized.len();
        resized.reserve(padding_len); // Pre-allocate to avoid reallocations
        resized.extend(std::iter::repeat(pad_char as char).take(padding_len));
    }

    resized
}

/// Converts base64-encoded payload to 6-bit boolean witness for circuit decoding.
/// Pads to max_payload_len_b64 to ensure fixed circuit size.
pub fn pay_b64_bits(
    payload_b64: &[u8],
    max_payload_len_b64: usize,
    pad_byte: u8,
) -> Result<Vec<bool>, TokenError> {
    if payload_b64.len() > max_payload_len_b64 {
        return Err(TokenError::InvalidFormat(format!(
            "Payload length {} exceeds maximum {}",
            payload_b64.len(),
            max_payload_len_b64
        )));
    }

    // Efficient padding: allocate once
    let mut padded = Vec::with_capacity(max_payload_len_b64);
    padded.extend_from_slice(payload_b64);
    padded.resize(max_payload_len_b64, pad_byte);

    base64_to_6bit_bools(&padded).map_err(TokenError::from)
}

/// Finds claim value by key in the claims list.
/// Returns reference to avoid unnecessary allocations.
pub fn find_claim_value<'a>(claims: &'a [Claim], key: &str) -> Result<&'a str, TokenError> {
    claims
        .iter()
        .find(|c| c.key == key)
        .map(|c| c.value.as_str())
        .ok_or_else(|| TokenError::NotFoundKeyError(key.to_string()))
}
