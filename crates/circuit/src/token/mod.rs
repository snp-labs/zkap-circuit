use regex::Regex;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::token::error::TokenError;

pub mod claimverifier;
pub mod constraints;
pub mod error;

#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ClaimIndices {
    pub offset: usize,
    pub claim_len: usize,
    pub colon_idx: usize,
    pub value_idx: usize,
    pub value_len: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Claim {
    pub key: String,
    pub value: String,
    pub indices: ClaimIndices,
}

impl Claim {
    pub fn empty() -> Self {
        Claim {
            key: String::new(),
            value: String::new(),
            indices: ClaimIndices::default(),
        }
    }
}

/// Parses a JSON claim from a string and extracts its metadata.
/// Returns claim with key, value, and position indices for circuit use.
pub fn parse_claim_from_str(s: &str, key: &str) -> Result<Claim, TokenError> {
    let escaped_key = regex::escape(key);
    let pattern = format!(r#"\s*("{}")\s*:\s*("?[^",]*"?)\s*([,\}}])"#, escaped_key);
    let re = Regex::new(&pattern)
        .map_err(|e| TokenError::InvalidFormat(format!("Invalid regex for key '{}': {}", key, e)))?;

    let (offset, claim_len, colon_idx, value_idx, value_len, value_str) =
        if let Some(caps) = re.captures(s) {
            // Full matched claim
            let full_match = caps.get(0).ok_or_else(|| TokenError::InvalidFormat("Regex match missing full capture".to_string()))?;
            let full_match_str = full_match.as_str();
            let offset = full_match.start();
            let len = full_match_str.len();

            // Group 2: value (may include quotes)
            let captured_value = caps.get(2).ok_or_else(|| TokenError::InvalidFormat("Regex match missing value capture".to_string()))?.as_str();

            // ':' position
            let colon_idx = full_match_str.find(':').ok_or_else(|| TokenError::InvalidFormat("Colon not found in matched claim".to_string()))?;

            // Store value including quotes
            let value_str = captured_value.to_string();

            // Calculate value start position within full_match
            let rel_search_start = colon_idx + 1; // after ':'
            let found_at = full_match_str[rel_search_start..]
                .find(captured_value)
                .map(|i| i + rel_search_start)
                .ok_or_else(|| TokenError::InvalidFormat("Value position not found in matched claim".to_string()))?;

            let value_idx = found_at;
            // Length: including quotes
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

/// Finds claim value by key in the claims list.
/// Returns reference to avoid unnecessary allocations.
pub fn find_claim_value<'a>(claims: &'a [Claim], key: &str) -> Result<&'a str, TokenError> {
    claims
        .iter()
        .find(|c| c.key == key)
        .map(|c| c.value.as_str())
        .ok_or_else(|| TokenError::NotFoundKeyError(key.to_string()))
}
