//! JWT claim parser: extracts named fields from JSON payloads.
//!
//! [`parse_claim_from_str`] locates a key in a flat JSON object using pure-std
//! string operations (no JSON deserializer dependency). Returns [`TokenError`]
//! on malformed input or missing keys. [`TokenError`] converts automatically
//! into [`crate::error::ApplicationError`] via [`From`].

use circuit::token::{Claim, ClaimIndices};
use gadget::base64::{Base64Error, decode_any_base64};
use thiserror::Error;

use crate::dto::AnchorSecret;
use crate::error::ApplicationError;

/// Failure modes for JWT claim parsing.
///
/// Returned by [`parse_claim_from_str`]; converts into
/// [`crate::error::ApplicationError::ParseError`] via the `From` impl in
/// [`crate::error`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    /// JWT payload could not be parsed structurally — for example, the
    /// targeted key was not surrounded by the expected `"…"` quoting or its
    /// value was not closed with a balancing quote / `,` / `}`.
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    /// Base64 decoding of a JWT segment failed (auto-converted from
    /// [`Base64Error`] via `?`); the JWT is malformed at the segment
    /// boundary, before any claim extraction is attempted.
    #[error("Base64 error")]
    Base64ErrorInToken(#[from] Base64Error),

    /// The requested key was not present in the payload JSON. The string
    /// carries the requested key name so callers can surface it in audit
    /// logs without re-deriving it.
    #[error("Key not found: {0}")]
    NotFoundKeyError(String),
}

/// Parses a JSON claim from a string and extracts its metadata.
///
/// Locates `"key"` in the JWT payload JSON, then finds the `:` separator and
/// value boundaries. Returns `Claim` with byte-level indices compatible with
/// the circuit's `ClaimIndices`. Uses pure `std` string operations.
pub fn parse_claim_from_str(s: &str, key: &str) -> Result<Claim, TokenError> {
    let needle = format!("\"{}\"", key);

    let key_start = s
        .find(&needle)
        .ok_or_else(|| TokenError::NotFoundKeyError(key.to_string()))?;

    // Walk backwards to include leading whitespace
    let mut offset = key_start;
    while offset > 0 && s.as_bytes()[offset - 1].is_ascii_whitespace() {
        offset -= 1;
    }

    let after_key = key_start + needle.len();
    let colon_rel = s[after_key..]
        .find(':')
        .ok_or_else(|| TokenError::InvalidFormat("Colon not found after key".to_string()))?;
    let colon_idx = (after_key + colon_rel) - offset;

    let after_colon = after_key + colon_rel + 1;
    let mut value_start = after_colon;
    while value_start < s.len() && s.as_bytes()[value_start].is_ascii_whitespace() {
        value_start += 1;
    }

    if value_start >= s.len() {
        return Err(TokenError::InvalidFormat(
            "Value not found after colon".to_string(),
        ));
    }

    let value_end = if s.as_bytes()[value_start] == b'"' {
        // Quoted string: find closing quote
        let closing = s[value_start + 1..]
            .find('"')
            .ok_or_else(|| TokenError::InvalidFormat("Unterminated string value".to_string()))?;
        value_start + 1 + closing + 1
    } else {
        // Bare value (number / bool / null): ends at ',' or '}'
        s[value_start..]
            .find([',', '}'])
            .map(|i| value_start + i)
            .unwrap_or(s.len())
    };

    let value_str = s[value_start..value_end].to_string();
    let value_idx = value_start - offset;
    let value_len = value_end - value_start;

    // Include trailing delimiter (',' or '}') in claim_len
    let mut trail = value_end;
    while trail < s.len() && s.as_bytes()[trail].is_ascii_whitespace() {
        trail += 1;
    }
    let claim_len =
        if trail < s.len() && (s.as_bytes()[trail] == b',' || s.as_bytes()[trail] == b'}') {
            trail + 1 - offset
        } else {
            trail - offset
        };

    Ok(Claim {
        key: key.to_string(),
        value: value_str,
        indices: ClaimIndices {
            offset,
            claim_len,
            colon_idx,
            value_idx,
            value_len,
        },
    })
}

/// Parse the JWT payload's `sub` / `iss` / `aud` claims and return an
/// [`AnchorSecret`] with the JSON quotes stripped so values can be fed to
/// [`crate::anchor::poseidon::derive_x_from_secret`] unchanged (the
/// derivation wraps each claim in `"…"` internally).
///
/// Errors map to [`ApplicationError::InvalidProveRequest`] with a dotted
/// `credentials[{cred_idx}].jwt[.payload]` field path so callers in
/// [`crate::groth16::prover::prove`] surface precise diagnostics.
pub(crate) fn parse_anchor_secret_from_jwt(
    jwt_bytes: &[u8],
    cred_idx: usize,
) -> Result<AnchorSecret, ApplicationError> {
    let jwt_str =
        core::str::from_utf8(jwt_bytes).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("not UTF-8: {}", e),
        })?;
    let parts: Vec<&str> = jwt_str.split('.').collect();
    if parts.len() != 3 {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("expected 3 dot-separated JWT segments, got {}", parts.len()),
        });
    }
    let payload_bytes =
        decode_any_base64(parts[1]).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt.payload", cred_idx),
            message: format!("base64 decode failed: {}", e),
        })?;
    let payload_str = core::str::from_utf8(&payload_bytes).map_err(|e| {
        ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt.payload", cred_idx),
            message: format!("not UTF-8: {}", e),
        }
    })?;

    let subject = extract_string_claim(payload_str, "sub", cred_idx)?;
    let issuer = extract_string_claim(payload_str, "iss", cred_idx)?;
    let audience = extract_string_claim(payload_str, "aud", cred_idx)?;

    Ok(AnchorSecret {
        subject,
        issuer,
        audience,
    })
}

/// Look up a quoted JSON string claim in the JWT payload and return the raw
/// value with the wrapping `"` characters stripped. Returns
/// [`ApplicationError::InvalidProveRequest`] if the claim value is not
/// surrounded by `"…"`.
fn extract_string_claim(
    payload: &str,
    key: &str,
    cred_idx: usize,
) -> Result<String, ApplicationError> {
    let claim =
        parse_claim_from_str(payload, key).map_err(|e| ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("claim `{}`: {}", key, e),
        })?;
    let value = claim.value;
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(ApplicationError::InvalidProveRequest {
            field: format!("credentials[{}].jwt", cred_idx),
            message: format!("claim `{}` is not a JSON string", key),
        });
    }
    // Strip surrounding quotes — value is ASCII-quoted, so byte slicing is safe.
    Ok(value[1..value.len() - 1].to_string())
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
