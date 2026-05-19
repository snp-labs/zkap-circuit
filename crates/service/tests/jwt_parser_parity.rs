//! Property tests: the unified [`zkap_service::jwt::parser::locate_claim`]
//! function must agree with [`zkap_service::jwt::parser::parse_claim_from_str`]
//! and must satisfy round-trip / edge-case properties for all claim shapes.
//!
//! # What is tested
//!
//! 1. **Index agreement** — `locate_claim` and `parse_claim_from_str` return
//!    the same `ClaimIndices` fields (offset, claim_len, colon_idx,
//!    value_idx, value_len) for every generated payload and key.
//!
//! 2. **Round-trip** — the byte slice `payload[value_start..value_end]`
//!    can be parsed back by `serde_json::from_str` to the original
//!    `serde_json::Value`.
//!
//! 3. **Soundness gate** — for the canonical `aud` claim used in anchor-secret
//!    derivation, the byte range returned by `locate_claim` matches the one
//!    that `parse_anchor_secret_from_jwt` uses internally (verified via
//!    `parse_claim_from_str` which is itself a thin wrapper over `locate_claim`).
//!
//! # Whitespace policy
//!
//! `locate_claim` is defined over **compact** JSON only (no inserted
//! whitespace between tokens), which is what RFC 7519 §7.2 mandates. The
//! proptest strategy therefore generates compact payloads only.  Pretty-printed
//! JSON is exercised in a separate hand-written test that documents the
//! expected behaviour (the locator rejects pretty-printed payloads because the
//! `value` for bare numbers ends at the first `,`/`}` after the digits, and
//! with pretty-printing the terminator is on the next line).
//!
//! # Running
//!
//! ```
//! cargo test -p zkap-service --release --test jwt_parser_parity
//! ```

use proptest::prelude::*;
use serde_json::{Map, Value};
use zkap_service::jwt::parser::{TokenError, locate_claim, parse_claim_from_str};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Serialize a `serde_json::Map` to a compact JSON object string.
fn compact_json(map: &Map<String, Value>) -> String {
    serde_json::to_string(map).expect("serialize map")
}

/// Extract the located value bytes from the payload string.
fn located_value_str(payload: &str, key: &str) -> String {
    let idx = locate_claim(payload, key).expect("locate_claim");
    let start = idx.offset + idx.value_idx;
    let end = start + idx.value_len;
    payload[start..end].to_string()
}

/// Tuple representation of [`circuit::token::ClaimIndices`] fields for comparison.
/// `ClaimIndices` does not derive `PartialEq`, so we project to a plain tuple.
struct IndicesTuple {
    offset: usize,
    claim_len: usize,
    colon_idx: usize,
    value_idx: usize,
    value_len: usize,
}

impl IndicesTuple {
    fn assert_eq(&self, other: &IndicesTuple, label: &str) {
        assert_eq!(self.offset,    other.offset,    "{}: offset mismatch",    label);
        assert_eq!(self.claim_len, other.claim_len, "{}: claim_len mismatch", label);
        assert_eq!(self.colon_idx, other.colon_idx, "{}: colon_idx mismatch", label);
        assert_eq!(self.value_idx, other.value_idx, "{}: value_idx mismatch", label);
        assert_eq!(self.value_len, other.value_len, "{}: value_len mismatch", label);
    }

    fn prop_assert_eq(&self, other: &IndicesTuple, label: &str) -> Result<(), TestCaseError> {
        prop_assert_eq!(self.offset,    other.offset,    "{}: offset mismatch",    label);
        prop_assert_eq!(self.claim_len, other.claim_len, "{}: claim_len mismatch", label);
        prop_assert_eq!(self.colon_idx, other.colon_idx, "{}: colon_idx mismatch", label);
        prop_assert_eq!(self.value_idx, other.value_idx, "{}: value_idx mismatch", label);
        prop_assert_eq!(self.value_len, other.value_len, "{}: value_len mismatch", label);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Proptest strategies
// ---------------------------------------------------------------------------

/// Generate a valid JSON key (alphanumeric + underscore, non-empty, ≤ 16 chars).
fn arb_key() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,15}".prop_map(|s| s)
}

/// Generate a JSON value that does NOT contain `\"` escape sequences (well-formed
/// JWT claim values per RFC 7519 / OIDC Core never contain embedded quotes in
/// the string value itself). This keeps the round-trip assertion simple.
fn arb_claim_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        // String — no embedded quotes or backslashes to keep the payload compact
        // and avoid escape sequences that the circuit doesn't see.
        "[a-zA-Z0-9 _:/.@-]{0,40}".prop_map(Value::String),
        // Non-negative integer
        (0u64..u64::MAX).prop_map(|n| Value::Number(n.into())),
        // Bool
        any::<bool>().prop_map(Value::Bool),
        // Array of strings (models multi-audience JWT)
        prop::collection::vec("[a-zA-Z0-9._-]{0,20}".prop_map(Value::String), 0..=3)
            .prop_map(Value::Array),
    ]
}

/// Generate a JSON object with 1..=6 distinct keys, each mapping to an
/// arb_claim_value, as a compact string along with the key list.
fn arb_payload() -> impl Strategy<Value = (Map<String, Value>, Vec<String>)> {
    prop::collection::hash_map(arb_key(), arb_claim_value(), 1..=6).prop_map(|hm| {
        let mut map = Map::new();
        let mut keys = Vec::new();
        for (k, v) in hm {
            keys.push(k.clone());
            map.insert(k, v);
        }
        (map, keys)
    })
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// locate_claim and parse_claim_from_str must return the same ClaimIndices
    /// for every generated compact payload and randomly chosen key.
    #[test]
    fn prop_locate_and_parse_agree(
        (map, keys) in arb_payload(),
        key_idx in any::<proptest::sample::Index>(),
    ) {
        let key = &keys[key_idx.index(keys.len())];
        let payload = compact_json(&map);

        let loc = locate_claim(&payload, key).expect("locate_claim on known key");
        let parsed = parse_claim_from_str(&payload, key).expect("parse_claim_from_str on known key");

        let l = IndicesTuple { offset: loc.offset, claim_len: loc.claim_len, colon_idx: loc.colon_idx, value_idx: loc.value_idx, value_len: loc.value_len };
        let r = IndicesTuple { offset: parsed.indices.offset, claim_len: parsed.indices.claim_len, colon_idx: parsed.indices.colon_idx, value_idx: parsed.indices.value_idx, value_len: parsed.indices.value_len };
        l.prop_assert_eq(&r, "locate vs parse")?;
    }

    /// The value bytes extracted by locate_claim round-trip through serde_json.
    #[test]
    fn prop_value_bytes_round_trip(
        (map, keys) in arb_payload(),
        key_idx in any::<proptest::sample::Index>(),
    ) {
        let key = &keys[key_idx.index(keys.len())];
        let payload = compact_json(&map);

        let extracted = located_value_str(&payload, key);
        let original_value = &map[key];

        // Parse the extracted bytes back with serde_json.
        let reparsed: Value = serde_json::from_str(&extracted)
            .unwrap_or_else(|e| panic!("round-trip failed for key={key:?} extracted={extracted:?}: {e}"));

        // Numbers serialised as serde_json::Value::Number may not round-trip
        // through f64, but u64 values always do.
        prop_assert_eq!(&reparsed, original_value,
            "round-trip mismatch for key={:?} payload={:?}", key, payload);
    }

    /// A missing claim always returns NotFoundKeyError, never a silent empty range.
    #[test]
    fn prop_missing_claim_is_error(
        (map, _keys) in arb_payload(),
        // "__missing__" is never generated by arb_key()
    ) {
        let payload = compact_json(&map);
        match locate_claim(&payload, "__missing__") {
            Err(TokenError::NotFoundKeyError(k)) => {
                prop_assert_eq!(k, "__missing__");
            }
            _other => prop_assert!(false, "expected NotFoundKeyError for __missing__ key"),
        }
    }
}

// ---------------------------------------------------------------------------
// Hand-written edge-case tests
// ---------------------------------------------------------------------------

/// Claim value that contains `,` inside a JSON string must not confuse the
/// string-value scanner into stopping early.
#[test]
fn string_value_containing_comma() {
    let payload = r#"{"key":"val,ue","other":1}"#;
    let v = located_value_str(payload, "key");
    assert_eq!(v, r#""val,ue""#, "comma inside string value must not terminate scan");
    let reparsed: Value = serde_json::from_str(&v).expect("round-trip");
    assert_eq!(reparsed, Value::String("val,ue".into()));
}

/// Claim value that contains `}` inside a JSON string.
#[test]
fn string_value_containing_brace() {
    let payload = r#"{"key":"val}ue","other":1}"#;
    let v = located_value_str(payload, "key");
    assert_eq!(v, r#""val}ue""#, "brace inside string value must not terminate scan");
}

/// Claim is the last claim in the object — terminator is `}` not `,`.
#[test]
fn last_claim_terminated_by_brace() {
    let payload = r#"{"aud":"audience","sub":"user"}"#;
    let idx = locate_claim(payload, "sub").expect("sub");
    assert_eq!(
        payload.as_bytes()[idx.offset + idx.claim_len - 1],
        b'}',
        "last claim must be terminated by `}}`"
    );
}

/// Missing claim returns `NotFoundKeyError`, not an empty range.
#[test]
fn missing_claim_returns_error() {
    let payload = r#"{"aud":"audience","sub":"user"}"#;
    match locate_claim(payload, "exp") {
        Err(TokenError::NotFoundKeyError(k)) => assert_eq!(k, "exp"),
        other => panic!("expected NotFoundKeyError, got {:?}", other),
    }
}

/// Empty string value `""`.
#[test]
fn empty_string_value() {
    let payload = r#"{"key":"","other":1}"#;
    let idx = locate_claim(payload, "key").expect("key");
    assert_eq!(idx.value_len, 2, "empty string occupies exactly 2 bytes (the two quotes)");
    let v = located_value_str(payload, "key");
    assert_eq!(v, r#""""#);
    let reparsed: Value = serde_json::from_str(&v).expect("round-trip");
    assert_eq!(reparsed, Value::String(String::new()));
}

/// Empty array value `[]`.
#[test]
fn empty_array_value() {
    let payload = r#"{"key":[],"other":1}"#;
    let v = located_value_str(payload, "key");
    assert_eq!(v, "[]");
    let reparsed: Value = serde_json::from_str(&v).expect("round-trip");
    assert_eq!(reparsed, Value::Array(vec![]));
}

/// Soundness regression gate: for the canonical `aud` claim, the byte range
/// returned by `locate_claim` equals what `parse_claim_from_str` uses, which
/// is the same function `parse_anchor_secret_from_jwt` calls internally.
/// This pins the invariant that anchor-secret derivation and circuit-witness
/// building refer to the same bytes.
#[test]
fn aud_locate_matches_parse_soundness_gate() {
    let payload = r#"{"aud":"test-audience","exp":1700000000,"iss":"https://accounts.google.com","nonce":"abc123","sub":"user_0"}"#;

    let loc = locate_claim(payload, "aud").expect("locate aud");
    let parsed = parse_claim_from_str(payload, "aud").expect("parse aud");

    // locate_claim IS the implementation of parse_claim_from_str; their
    // indices must always agree.  Any divergence means one path has been
    // accidentally changed to use a different parser.
    let l = IndicesTuple { offset: loc.offset, claim_len: loc.claim_len, colon_idx: loc.colon_idx, value_idx: loc.value_idx, value_len: loc.value_len };
    let r = IndicesTuple { offset: parsed.indices.offset, claim_len: parsed.indices.claim_len, colon_idx: parsed.indices.colon_idx, value_idx: parsed.indices.value_idx, value_len: parsed.indices.value_len };
    l.assert_eq(&r, "aud soundness regression");

    // The extracted value must be the JSON string (with surrounding quotes).
    let value_start = loc.offset + loc.value_idx;
    let value_end = value_start + loc.value_len;
    assert_eq!(&payload[value_start..value_end], r#""test-audience""#);
}
