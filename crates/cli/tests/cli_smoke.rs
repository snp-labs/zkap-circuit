//! Smoke tests for the `zkap-cli` binaries.
//!
//! These exercise the actual binary entry points end-to-end so that changes
//! to argument parsing, stdout/stderr contracts, or output JSON shapes are
//! caught at the CLI boundary — the library-level paths inside
//! `zkap_service::generate_aud_hash` / `generate_leaf_hash` are already
//! covered by service crate tests.
//!
//! `generate_setup` is intentionally not covered here because its
//! `zkap_service::setup` call runs the full Groth16 trusted setup, which
//! is far too heavy for a smoke test. A separate slow-test bin exercise
//! belongs in a dedicated integration suite.

use std::path::{Path, PathBuf};
use std::process::Command;

const SAMPLE_CONFIG: &str = r#"{
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
}
"#;

/// A scratch directory under `std::env::temp_dir()` that cleans up on drop.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(test_name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "zkap_cli_smoke_{}_{}_{}",
            test_name,
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_sample_config(scratch: &ScratchDir) -> PathBuf {
    let cfg_path = scratch.join("config.json");
    std::fs::write(&cfg_path, SAMPLE_CONFIG).expect("write sample config");
    cfg_path
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("read {} failed: {}", path.display(), e));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse {} as JSON failed: {}", path.display(), e))
}

#[test]
fn generate_hash_aud_smoke() {
    let scratch = ScratchDir::new("aud");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("aud.json");

    let status = Command::new(env!("CARGO_BIN_EXE_generate_hash"))
        .arg("--config")
        .arg(&cfg)
        .arg("aud")
        .arg("--values")
        .arg("alice.example,bob.example")
        .arg("--out")
        .arg(&out)
        .status()
        .expect("spawn generate_hash");
    assert!(status.success(), "generate_hash aud exited with {status}");

    let json = read_json(&out);
    let inputs = json["input"].as_array().expect("input is array");
    assert_eq!(inputs.len(), 2, "expected 2 audience inputs");
    assert_eq!(inputs[0].as_str(), Some("alice.example"));
    assert_eq!(inputs[1].as_str(), Some("bob.example"));

    let aud_to_field = json["output"]["aud_to_field"]
        .as_array()
        .expect("output.aud_to_field is array");
    // The service pads / repeats audiences up to `num_audience_limit` from
    // the config (5 here). The CLI surfaces the padded list verbatim.
    assert_eq!(aud_to_field.len(), 5);
    let combined = json["output"]["h_aud_lists"]
        .as_str()
        .expect("output.h_aud_lists is string");
    assert!(combined.starts_with("0x"), "expected 0x-prefixed hex");
}

#[test]
fn generate_hash_leaf_smoke() {
    let scratch = ScratchDir::new("leaf");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("leaf.json");

    // `AQAB` is the canonical base64 encoding of `[1, 0, 1]`; service-side
    // tests use the same placeholder for `pk_b64` smoke coverage.
    let status = Command::new(env!("CARGO_BIN_EXE_generate_hash"))
        .arg("--config")
        .arg(&cfg)
        .arg("leaf")
        .arg("--iss")
        .arg("https://issuer1.example,https://issuer2.example")
        .arg("--pk")
        .arg("AQAB,AQAB")
        .arg("--out")
        .arg(&out)
        .status()
        .expect("spawn generate_hash");
    assert!(status.success(), "generate_hash leaf exited with {status}");

    let json = read_json(&out);
    let inputs = json["input"].as_array().expect("input is array");
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0]["iss"].as_str(), Some("https://issuer1.example"));
    assert_eq!(inputs[1]["pk"].as_str(), Some("AQAB"));

    let outputs = json["output"].as_array().expect("output is array");
    assert_eq!(outputs.len(), 2);
    let leaf1 = outputs[0].as_str().expect("leaf is string");
    let leaf2 = outputs[1].as_str().expect("leaf is string");
    assert!(leaf1.starts_with("0x"));
    assert!(leaf2.starts_with("0x"));
    // Different issuer strings → different leaves.
    assert_ne!(leaf1, leaf2, "leaves must differ when iss differs");
}

#[test]
fn generate_hash_leaf_iss_pk_count_mismatch_exits_nonzero() {
    let scratch = ScratchDir::new("leaf_mismatch");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("leaf.json");

    let output = Command::new(env!("CARGO_BIN_EXE_generate_hash"))
        .arg("--config")
        .arg(&cfg)
        .arg("leaf")
        .arg("--iss")
        .arg("https://only-one.example")
        .arg("--pk")
        .arg("AQAB,AQAB")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("spawn generate_hash");
    assert!(!output.status.success(), "expected nonzero exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Mismatch"),
        "stderr should mention 'Mismatch', got: {stderr}"
    );
}
