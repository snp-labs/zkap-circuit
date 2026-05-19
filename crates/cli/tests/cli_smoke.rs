//! Smoke tests for the `zkap-cli` binaries.
//!
//! These exercise the actual binary entry points end-to-end so that changes
//! to argument parsing, stdout/stderr contracts, or output JSON shapes are
//! caught at the CLI boundary — the library-level paths inside
//! `zkap_service::generate_audience_hashes` /
//! `zkap_service::generate_issuer_key_hash` are already covered by service
//! crate tests.
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
    use base64::Engine;

    let scratch = ScratchDir::new("leaf");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("leaf.json");

    // `zkap_service::generate_issuer_key_hash` enforces the RSA-2048
    // modulus length (exactly 256 bytes after base64 decoding); use a
    // valid-shape placeholder to exercise the success path.
    let modulus_bytes = {
        let mut v = vec![0xABu8; 256];
        v[0] = 0xC0;
        v[255] = 0x01;
        v
    };
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&modulus_bytes);
    let pk_arg = format!("{pk_b64},{pk_b64}");

    let status = Command::new(env!("CARGO_BIN_EXE_generate_hash"))
        .arg("--config")
        .arg(&cfg)
        .arg("leaf")
        .arg("--iss")
        .arg("https://issuer1.example,https://issuer2.example")
        .arg("--pk")
        .arg(&pk_arg)
        .arg("--out")
        .arg(&out)
        .status()
        .expect("spawn generate_hash");
    assert!(status.success(), "generate_hash leaf exited with {status}");

    let json = read_json(&out);
    let inputs = json["input"].as_array().expect("input is array");
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0]["iss"].as_str(), Some("https://issuer1.example"));
    assert_eq!(inputs[1]["pk"].as_str(), Some(pk_b64.as_str()));

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

/// `generate_setup --verifying-key-out <PATH>` without `--signing-key`
/// must be rejected — emitting a public key alone is nonsensical.
#[test]
fn generate_setup_verifying_key_out_requires_signing_key() {
    let scratch = ScratchDir::new("vk_out_gate");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");
    let vk_out = scratch.join("vk.pub");

    let output = Command::new(env!("CARGO_BIN_EXE_generate_setup"))
        .arg("--config")
        .arg(&cfg)
        .arg("--output")
        .arg(&out)
        .arg("--circuit-id")
        .arg("test-circuit")
        .arg("--verifying-key-out")
        .arg(&vk_out)
        .output()
        .expect("spawn generate_setup");

    assert!(
        !output.status.success(),
        "generate_setup must exit non-zero when --verifying-key-out is passed without --signing-key"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--verifying-key-out") && stderr.contains("--signing-key"),
        "stderr must explain the dependency, got: {stderr}"
    );
}

/// `generate_setup --signing-key <PATH>` with a malformed key file
/// (wrong byte length) must reject before running Groth16 setup —
/// validates the CLI key-shape gate.
#[test]
fn generate_setup_signing_key_wrong_length_rejected() {
    let scratch = ScratchDir::new("signing_key_bad_len");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");
    // Wrong length: 16 bytes (must be 32).
    let bad_key = scratch.join("signing.key.bad");
    std::fs::write(&bad_key, [0u8; 16]).expect("write bad key");

    let output = Command::new(env!("CARGO_BIN_EXE_generate_setup"))
        .arg("--config")
        .arg(&cfg)
        .arg("--output")
        .arg(&out)
        .arg("--circuit-id")
        .arg("test-circuit")
        .arg("--signing-key")
        .arg(&bad_key)
        .output()
        .expect("spawn generate_setup");

    assert!(
        !output.status.success(),
        "generate_setup must exit non-zero on a wrong-length signing key"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("32 raw bytes"),
        "stderr must explain the expected key length, got: {stderr}"
    );
}

/// End-to-end: `generate_setup --signing-key <PATH>` produces a
/// manifest with a non-empty `signature` field that verifies
/// against the corresponding public key.
///
/// `#[ignore]`d by default because it runs the full Groth16 setup
/// (`n=6, k=3, tree_height=4`), which takes minutes in release mode.
/// Opt in via `cargo test --release -- --ignored`. The fast-path
/// integration coverage lives in
/// `crates/service/tests/manifest_signing.rs`.
#[test]
#[ignore = "runs real Groth16 trusted setup; opt in via --ignored"]
fn generate_setup_with_signing_key_writes_signed_manifest() {
    use ed25519_dalek::{SigningKey, Verifier};

    let scratch = ScratchDir::new("signed_e2e");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");

    // Deterministic 32-byte key for reproducibility.
    let seed: [u8; 32] = [0x42; 32];
    let sk_path = scratch.join("signing.key");
    std::fs::write(&sk_path, seed).expect("write signing key");
    let vk_out = scratch.join("verifying.key");

    let output = Command::new(env!("CARGO_BIN_EXE_generate_setup"))
        .arg("--config")
        .arg(&cfg)
        .arg("--output")
        .arg(&out)
        .arg("--circuit-id")
        .arg("test-circuit")
        .arg("--signing-key")
        .arg(&sk_path)
        .arg("--verifying-key-out")
        .arg(&vk_out)
        .output()
        .expect("spawn generate_setup");
    assert!(
        output.status.success(),
        "generate_setup must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Manifest must carry a signature.
    let manifest_path = out.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).expect("read manifest.json");
    let manifest: zkap_service::manifest::Manifest =
        serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");
    let sig_hex = manifest
        .signature
        .as_deref()
        .expect("manifest must carry a signature when --signing-key was passed");
    assert!(!sig_hex.is_empty(), "signature must be non-empty");

    // Verifying-key-out must be 32 raw bytes matching the derived public key.
    let vk_bytes = std::fs::read(&vk_out).expect("read verifying.key");
    assert_eq!(vk_bytes.len(), 32, "verifying-key-out must be 32 bytes");

    // End-to-end: signature verifies against derived public key.
    let signing_key = SigningKey::from_bytes(&seed);
    let derived_vk = signing_key.verifying_key();
    assert_eq!(
        vk_bytes.as_slice(),
        derived_vk.to_bytes().as_slice(),
        "--verifying-key-out must match the public key derived from --signing-key"
    );

    let signed_payload = manifest
        .canonical_signing_bytes()
        .expect("canonical signing bytes");
    let sig_raw = hex::decode(sig_hex).expect("hex decode signature");
    let sig_array: [u8; 64] = sig_raw.as_slice().try_into().expect("64-byte signature");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    derived_vk
        .verify(&signed_payload, &sig)
        .expect("signature must verify against derived key");
}

/// End-to-end sanity: omitting `--signing-key` keeps the manifest
/// unsigned (`signature: None`), preserving the pre-F5 default. Also
/// `#[ignore]`d because it runs the full Groth16 setup.
#[test]
#[ignore = "runs real Groth16 trusted setup; opt in via --ignored"]
fn generate_setup_without_signing_key_writes_unsigned_manifest() {
    let scratch = ScratchDir::new("unsigned_e2e");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");

    let output = Command::new(env!("CARGO_BIN_EXE_generate_setup"))
        .arg("--config")
        .arg(&cfg)
        .arg("--output")
        .arg(&out)
        .arg("--circuit-id")
        .arg("test-circuit")
        .output()
        .expect("spawn generate_setup");
    assert!(
        output.status.success(),
        "generate_setup must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest_path = out.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).expect("read manifest.json");
    let manifest: zkap_service::manifest::Manifest =
        serde_json::from_slice(&manifest_bytes).expect("parse manifest.json");
    assert!(
        manifest.signature.is_none(),
        "manifest must be unsigned when --signing-key is omitted (got {:?})",
        manifest.signature
    );
}

/// `generate_setup --rng-seed <hex>` must be rejected unless `--allow-test-only` is also set.
///
/// This guards the safety invariant: a deterministic-seed bundle can only be
/// produced when the operator explicitly acknowledges it is test-only.
#[test]
fn generate_setup_rng_seed_requires_allow_test_only() {
    let scratch = ScratchDir::new("setup_seed_gate");
    let cfg = write_sample_config(&scratch);
    let out = scratch.join("out");
    std::fs::create_dir_all(&out).expect("create out dir");

    // 32-byte all-zeros seed, hex-encoded.
    let seed_hex = "0000000000000000000000000000000000000000000000000000000000000000";

    let output = Command::new(env!("CARGO_BIN_EXE_generate_setup"))
        .arg("--config")
        .arg(&cfg)
        .arg("--output")
        .arg(&out)
        .arg("--circuit-id")
        .arg("test-circuit")
        .arg("--rng-seed")
        .arg(seed_hex)
        // NOTE: --allow-test-only is intentionally omitted.
        .output()
        .expect("spawn generate_setup");

    assert!(
        !output.status.success(),
        "generate_setup must exit non-zero when --rng-seed is given without --allow-test-only"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--allow-test-only"),
        "stderr must mention '--allow-test-only', got: {stderr}"
    );
}
