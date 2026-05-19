//! JWT claim parser: extracts named fields from JSON payloads.
//!
//! [`locate_claim`] is the single source of truth for locating a JSON claim by
//! key in a compact JWT payload string. It returns [`ClaimIndices`] — a pure
//! byte-range description of where the claim lives — that is identical to what
//! the circuit's `claim_extractor` gadget constrains.
//!
//! [`parse_claim_from_str`] is a thin convenience wrapper: it calls
//! [`locate_claim`], slices the value bytes out of the payload, and returns a
//! [`Claim`] with the decoded value string attached.
//!
//! [`parse_anchor_secret_from_jwt`] builds an [`AnchorSecret`] by calling
//! [`locate_claim`] for `sub`, `iss`, and `aud` — guaranteeing that the byte
//! ranges used for anchor-secret derivation are byte-for-byte identical to
//! those the circuit constrains.
//!
//! # Whitespace policy
//!
//! JWT payloads **MUST** be compact JSON (no inserted whitespace) per
//! RFC 7519 §7.2 step 6 ("Create a UTF-8 encoding"). The parser accepts
//! whitespace between tokens as a lenient extension, but the circuit gadget
//! only constrains the compact representation. To keep both paths in sync,
//! callers that need circuit-compatible indices should supply compact JSON.
//!
//! # Escaped-quote handling
//!
//! Well-formed JWT claim values (issuer, subject, audience) MUST NOT contain
//! embedded `\"` escape sequences per RFC 7519 and the OIDC Core spec. The
//! parser is not confused by `\"` because string values end at the *closing*
//! unescaped `"` found by a forward scan that explicitly skips `\"` pairs.
//!
//! [`TokenError`] converts automatically into [`crate::error::ApplicationError`]
//! via the `From` impl in [`crate::error`].

use circuit::token::{Claim, ClaimIndices};
use gadget::base64::{Base64Error, decode_any_base64};
use thiserror::Error;

use crate::dto::AnchorSecret;
use crate::error::ApplicationError;

/// Failure modes for JWT claim parsing.
///
/// Returned by [`parse_claim_from_str`] and [`locate_claim`] (via conversion);
/// converts into [`crate::error::ApplicationError::ParseError`] via the `From`
/// impl in [`crate::error`].
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

/// Locate a JSON claim in a flat JWT payload string.
///
/// This is the **single source of truth** for claim location used by both the
/// anchor-secret derivation path and the circuit-witness building path. The
/// two paths previously used different parsers; this function is the unified
/// replacement so that both paths refer to exactly the same byte range.
///
/// # Inputs
/// * `payload` — decoded (UTF-8) JWT payload, e.g.
///   `{"aud":"audience","exp":1700000000,"iss":"https://…","sub":"user_0"}`
/// * `key` — unquoted claim name, e.g. `"aud"`.
///
/// # Returns
/// [`ClaimIndices`] where:
/// * `offset`    — byte position of the opening `"` of the key in `payload`.
/// * `claim_len` — bytes from `offset` through the trailing `,` or `}` (inclusive).
/// * `colon_idx` — byte offset of `:` relative to `offset`.
/// * `value_idx` — byte offset of the first byte of the value relative to `offset`.
/// * `value_len` — length of the value in bytes (includes surrounding `"` for strings).
///
/// # Errors
/// * [`TokenError::NotFoundKeyError`] — key absent from the payload.
/// * [`TokenError::InvalidFormat`] — `:` missing after key, unterminated string
///   value, or no `,`/`}` terminator after the value.
///
/// # Panics
/// Never (pure function, no allocation beyond a short needle string).
pub fn locate_claim(payload: &str, key: &str) -> Result<ClaimIndices, TokenError> {
    let needle = {
        let mut s = String::with_capacity(key.len() + 2);
        s.push('"');
        s.push_str(key);
        s.push('"');
        s
    };
    let bytes = payload.as_bytes();

    let key_pos = payload
        .find(&needle)
        .ok_or_else(|| TokenError::NotFoundKeyError(key.to_string()))?;

    let mut p = key_pos + needle.len();

    // Skip optional whitespace before ':'.
    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() || bytes[p] != b':' {
        return Err(TokenError::InvalidFormat(format!(
            "claim `{}` missing `:` separator",
            key
        )));
    }
    let colon_abs = p;
    p += 1;

    // Skip optional whitespace before value.
    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() {
        return Err(TokenError::InvalidFormat(format!(
            "claim `{}` has no value after `:`",
            key
        )));
    }

    let value_start_abs = p;
    let opens_with_quote = bytes[p] == b'"';
    if opens_with_quote {
        // Quoted string value: scan forward, skipping `\"` escape sequences,
        // until the closing `"`.
        p += 1;
        loop {
            if p >= bytes.len() {
                return Err(TokenError::InvalidFormat(format!(
                    "claim `{}` quoted value not terminated",
                    key
                )));
            }
            match bytes[p] {
                b'\\' => {
                    // Escape sequence: skip the next byte unconditionally so
                    // that `\"` does not prematurely close the string.
                    p += 2;
                }
                b'"' => {
                    // Closing quote found.
                    p += 1;
                    break;
                }
                _ => {
                    p += 1;
                }
            }
        }
    } else {
        // Bare value (number / bool / null / array / object):
        // advance until the first `,` or `}` that is at the top level
        // (not inside a nested string, array, or object).
        let mut string_depth = 0usize; // 1 when inside a "…" nested string
        let mut bracket_depth = 0usize; // depth of [ … ] nesting
        let mut brace_depth = 0usize; // depth of { … } nesting
        loop {
            if p >= bytes.len() {
                break;
            }
            match bytes[p] {
                b'\\' if string_depth > 0 => {
                    p += 2; // escape sequence inside a nested string
                }
                b'"' => {
                    string_depth = if string_depth == 0 { 1 } else { 0 };
                    p += 1;
                }
                b'[' if string_depth == 0 => {
                    bracket_depth += 1;
                    p += 1;
                }
                b']' if string_depth == 0 => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                    p += 1;
                }
                b'{' if string_depth == 0 => {
                    brace_depth += 1;
                    p += 1;
                }
                b'}' if string_depth == 0 && (bracket_depth > 0 || brace_depth > 0) => {
                    brace_depth = brace_depth.saturating_sub(1);
                    p += 1;
                }
                b',' | b'}' if string_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                    break;
                }
                _ => {
                    p += 1;
                }
            }
        }
    }
    let value_end_abs = p;

    // Skip optional whitespace after value, then require `,` or `}`.
    while p < bytes.len() && bytes[p].is_ascii_whitespace() {
        p += 1;
    }
    if p >= bytes.len() || (bytes[p] != b',' && bytes[p] != b'}') {
        return Err(TokenError::InvalidFormat(format!(
            "claim `{}` not terminated by `,` or `}}`",
            key
        )));
    }
    let terminator_abs = p;

    let offset = key_pos;
    let claim_len = terminator_abs + 1 - offset;
    let colon_idx = colon_abs - offset;
    let value_idx = value_start_abs - offset;
    let value_len = value_end_abs - value_start_abs;

    Ok(ClaimIndices {
        offset,
        claim_len,
        colon_idx,
        value_idx,
        value_len,
    })
}

/// Parses a JSON claim from a string and extracts its metadata.
///
/// Thin wrapper around [`locate_claim`]: calls it to obtain the
/// [`ClaimIndices`], then slices the value bytes from `s` to build the
/// [`Claim`] value string. Both the anchor-secret path and the circuit-witness
/// path therefore use the **same byte range** for every claim.
pub fn parse_claim_from_str(s: &str, key: &str) -> Result<Claim, TokenError> {
    let indices = locate_claim(s, key)?;

    let value_start = indices.offset + indices.value_idx;
    let value_end = value_start + indices.value_len;
    let value_str = s[value_start..value_end].to_string();

    Ok(Claim {
        key: key.to_string(),
        value: value_str,
        indices,
    })
}

/// Parse the JWT payload's `sub` / `iss` / `aud` claims and return an
/// [`AnchorSecret`] with the JSON quotes stripped so values can be fed to
/// [`crate::anchor::poseidon::derive_x_from_secret`] unchanged (the
/// derivation wraps each claim in `"…"` internally).
///
/// Uses [`locate_claim`] internally — the same function that
/// `circuit_input::build_jwt_stage` uses to compute `ClaimIndices` — so the
/// byte ranges used for anchor derivation and for circuit constraints are
/// guaranteed to match.
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

    #[test]
    fn locate_claim_matches_canonical_payload() {
        let payload = r#"{"aud":"test-audience","exp":1700000000,"iss":"https://x","nonce":"0xdead","sub":"u_0"}"#;
        let aud = locate_claim(payload, "aud").expect("aud claim");
        assert_eq!(aud.offset, 1);
        let exp = locate_claim(payload, "exp").expect("exp claim");
        let val_byte = payload.as_bytes()[exp.offset + exp.value_idx];
        assert_eq!(val_byte, b'1');
        let sub = locate_claim(payload, "sub").expect("sub claim");
        assert_eq!(payload.as_bytes()[sub.offset + sub.claim_len - 1], b'}');
    }

    #[test]
    fn locate_claim_and_parse_claim_agree_on_indices() {
        // Soundness regression gate: both paths must return the same ClaimIndices.
        // ClaimIndices does not derive PartialEq so we compare fields individually.
        let l = locate_claim(SAMPLE_PAYLOAD, "aud").expect("locate aud");
        let p = parse_claim_from_str(SAMPLE_PAYLOAD, "aud").expect("parse aud");
        assert_eq!(l.offset, p.indices.offset, "offset mismatch");
        assert_eq!(l.claim_len, p.indices.claim_len, "claim_len mismatch");
        assert_eq!(l.colon_idx, p.indices.colon_idx, "colon_idx mismatch");
        assert_eq!(l.value_idx, p.indices.value_idx, "value_idx mismatch");
        assert_eq!(l.value_len, p.indices.value_len, "value_len mismatch");
    }

    #[test]
    fn string_value_with_comma_inside_is_located_correctly() {
        // Value contains ',' inside the string — bare-value scanner must not stop early.
        // NOTE: in a quoted string value the comma is not a terminator.
        let payload = r#"{"key":"val,ue","other":1}"#;
        let claim = parse_claim_from_str(payload, "key").expect("key claim");
        assert_eq!(claim.value, r#""val,ue""#);
    }

    #[test]
    fn string_value_with_brace_inside_is_located_correctly() {
        let payload = r#"{"key":"val}ue","other":1}"#;
        let claim = parse_claim_from_str(payload, "key").expect("key claim");
        assert_eq!(claim.value, r#""val}ue""#);
    }

    #[test]
    fn locate_claim_missing_returns_error_not_empty_range() {
        let payload = r#"{"aud":"audience","sub":"user"}"#;
        match locate_claim(payload, "exp") {
            Err(TokenError::NotFoundKeyError(k)) => assert_eq!(k, "exp"),
            other => panic!("expected NotFoundKeyError, got {:?}", other),
        }
    }

    #[test]
    fn locate_claim_empty_string_value() {
        let payload = r#"{"key":"","other":1}"#;
        let claim = parse_claim_from_str(payload, "key").expect("empty string claim");
        assert_eq!(claim.value, r#""""#);
        assert_eq!(claim.indices.value_len, 2);
    }

    #[test]
    fn locate_claim_empty_array_value() {
        // An empty array as a bare (non-quoted) value.
        let payload = r#"{"key":[],"other":1}"#;
        let indices = locate_claim(payload, "key").expect("empty array claim");
        let val_bytes = &payload.as_bytes()
            [indices.offset + indices.value_idx..indices.offset + indices.value_idx + indices.value_len];
        assert_eq!(val_bytes, b"[]");
    }
}
