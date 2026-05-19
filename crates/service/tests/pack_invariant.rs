//! Release-mode guard: `load_circuit_config` must reject a `CircuitConfig`
//! whose `max_aud_len`, `max_iss_len`, or `max_sub_len` is not a multiple of
//! 31 before the prover is ever invoked.
//!
//! Motivation: `pack_bytes_to_field_native` packs claim bytes into BN254 field
//! elements using 31-byte chunks.  If a `max_*_len` is not a multiple of 31,
//! `chunks(31)` silently drops the trailing bytes, producing wrong field
//! elements and therefore wrong `h_id` / `partial_rhs` public inputs — with
//! no panic and no immediate test failure.
//!
//! The fix (F2) promotes the invariant into `CircuitConfig::validate()`.
//! These tests pin that the rejection happens at the config-load boundary, not
//! deep in the prover, and that it fires in `--release` mode (where
//! `debug_assert!` compiles out).

use std::io::Write as _;

use zkap_service::{error::ApplicationError, load_circuit_config};

/// Write JSON to a named temp file and return its path.
fn write_temp_json(tag: &str, json: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "zkap-pack-invariant-{}-{}-{}.json",
        tag,
        std::process::id(),
        nanos
    ));
    let mut f = std::fs::File::create(&path).expect("create temp file");
    f.write_all(json.as_bytes()).expect("write temp file");
    path
}

/// A valid base config JSON — all `max_*_len` values that flow through
/// `pack_bytes_to_field_native` are multiples of 31.
const VALID_CONFIG_JSON: &str = r#"{
  "max_jwt_b64_len": 1024,
  "max_payload_b64_len": 640,
  "max_aud_len": 155,
  "max_exp_len": 20,
  "max_iss_len": 93,
  "max_nonce_len": 93,
  "max_sub_len": 93,
  "n": 6,
  "k": 3,
  "tree_height": 4,
  "num_audience_limit": 5,
  "claims": ["aud", "exp", "iss", "nonce", "sub"],
  "forbidden_string": "forbidden"
}"#;

#[test]
fn load_circuit_config_accepts_valid_multiples_of_31() {
    let path = write_temp_json("valid", VALID_CONFIG_JSON);
    load_circuit_config(&path).expect("valid config (all multiples of 31) must load");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_circuit_config_rejects_max_aud_len_not_multiple_of_31() {
    let json = VALID_CONFIG_JSON.replace("\"max_aud_len\": 155", "\"max_aud_len\": 100");
    let path = write_temp_json("bad-aud", &json);
    let err = load_circuit_config(&path).expect_err("must reject max_aud_len=100");
    let _ = std::fs::remove_file(&path);

    match err {
        ApplicationError::InvalidFormat(msg) => {
            assert!(
                msg.contains("max_aud_len"),
                "error message must name the offending field, got: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got: {other:?}"),
    }
}

#[test]
fn load_circuit_config_rejects_max_iss_len_not_multiple_of_31() {
    let json = VALID_CONFIG_JSON.replace("\"max_iss_len\": 93", "\"max_iss_len\": 100");
    let path = write_temp_json("bad-iss", &json);
    let err = load_circuit_config(&path).expect_err("must reject max_iss_len=100");
    let _ = std::fs::remove_file(&path);

    match err {
        ApplicationError::InvalidFormat(msg) => {
            assert!(
                msg.contains("max_iss_len"),
                "error message must name the offending field, got: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got: {other:?}"),
    }
}

#[test]
fn load_circuit_config_rejects_max_sub_len_not_multiple_of_31() {
    let json = VALID_CONFIG_JSON.replace("\"max_sub_len\": 93", "\"max_sub_len\": 100");
    let path = write_temp_json("bad-sub", &json);
    let err = load_circuit_config(&path).expect_err("must reject max_sub_len=100");
    let _ = std::fs::remove_file(&path);

    match err {
        ApplicationError::InvalidFormat(msg) => {
            assert!(
                msg.contains("max_sub_len"),
                "error message must name the offending field, got: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got: {other:?}"),
    }
}
