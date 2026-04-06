use circuit::token::{Claim, ClaimIndices};
use gadget::base64::Base64Error;
use regex::Regex;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    #[error("Base64 error")]
    Base64ErrorInToken(#[from] Base64Error),

    #[error("Key not found: {0}")]
    NotFoundKeyError(String),

    #[error("Invalid length: {0}")]
    #[allow(dead_code)]
    InvalidLengthError(String),
}

/// Parses a JSON claim from a string and extracts its metadata.
pub fn parse_claim_from_str(s: &str, key: &str) -> Result<Claim, TokenError> {
    let escaped_key = regex::escape(key);
    let pattern = format!(r#"\s*("{}")\s*:\s*("?[^",]*"?)\s*([,\}}])"#, escaped_key);
    let re = Regex::new(&pattern).map_err(|e| {
        TokenError::InvalidFormat(format!("Invalid regex for key '{}': {}", key, e))
    })?;

    let (offset, claim_len, colon_idx, value_idx, value_len, value_str) = if let Some(caps) =
        re.captures(s)
    {
        let full_match = caps.get(0).ok_or_else(|| {
            TokenError::InvalidFormat("Regex match missing full capture".to_string())
        })?;
        let full_match_str = full_match.as_str();
        let offset = full_match.start();
        let len = full_match_str.len();

        let captured_value = caps
            .get(2)
            .ok_or_else(|| {
                TokenError::InvalidFormat("Regex match missing value capture".to_string())
            })?
            .as_str();
        let colon_idx = full_match_str.find(':').ok_or_else(|| {
            TokenError::InvalidFormat("Colon not found in matched claim".to_string())
        })?;
        let value_str = captured_value.to_string();

        let rel_search_start = colon_idx + 1;
        let found_at = full_match_str[rel_search_start..]
            .find(captured_value)
            .map(|i| i + rel_search_start)
            .ok_or_else(|| {
                TokenError::InvalidFormat("Value position not found in matched claim".to_string())
            })?;

        let value_idx = found_at;
        let value_len = captured_value.len();

        (offset, len, colon_idx, value_idx, value_len, value_str)
    } else {
        return Err(TokenError::NotFoundKeyError(key.to_string()));
    };

    let indices = ClaimIndices {
        offset,
        claim_len,
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PAYLOAD: &str = r#"{"aud":"test-audience","exp":1700000000,"iss":"https://accounts.google.com","nonce":"abc123","sub":"user_0"}"#;

    #[test]
    fn test_parse_string_claim() {
        let claim = parse_claim_from_str(SAMPLE_PAYLOAD, "aud").unwrap();
        assert_eq!(claim.key, "aud");
        assert_eq!(claim.value, "\"test-audience\"");
    }

    #[test]
    fn test_parse_numeric_claim() {
        let claim = parse_claim_from_str(SAMPLE_PAYLOAD, "exp").unwrap();
        assert_eq!(claim.key, "exp");
        assert_eq!(claim.value, "1700000000");
    }

    #[test]
    fn test_parse_url_claim() {
        let claim = parse_claim_from_str(SAMPLE_PAYLOAD, "iss").unwrap();
        assert_eq!(claim.key, "iss");
        assert!(claim.value.contains("accounts.google.com"));
    }

    #[test]
    fn test_parse_last_claim() {
        let claim = parse_claim_from_str(SAMPLE_PAYLOAD, "sub").unwrap();
        assert_eq!(claim.key, "sub");
        assert_eq!(claim.value, "\"user_0\"");
    }

    #[test]
    fn test_parse_nonexistent_key() {
        let result = parse_claim_from_str(SAMPLE_PAYLOAD, "nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            TokenError::NotFoundKeyError(key) => assert_eq!(key, "nonexistent"),
            other => panic!("Expected NotFoundKeyError, got: {:?}", other),
        }
    }

    #[test]
    fn test_parse_claim_indices_valid() {
        let claim = parse_claim_from_str(SAMPLE_PAYLOAD, "aud").unwrap();
        assert!(claim.indices.claim_len > 0);
        assert!(claim.indices.value_len > 0);
        assert!(claim.indices.colon_idx > 0);
    }

    #[test]
    fn test_parse_empty_payload() {
        let result = parse_claim_from_str("{}", "aud");
        assert!(result.is_err());
    }
}
