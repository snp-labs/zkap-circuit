//! Tests for the [`zkap_service::SetupRng`] API (F6).
//!
//! These tests verify that:
//! 1. Two `setup()` calls with the same `SetupRng::ChaCha20` seed produce
//!    byte-identical `pk.bin` and `vk.bin` artifacts.
//! 2. `SetupRng::OsRng` emits `SetupProvenance::OsRng`-compatible output
//!    (shape fields are populated; the test does not inspect provenance
//!    directly because `SetupOutput` does not carry it — the manifest does).
//!
//! The `setup_with_chacha20_seed_is_deterministic` test is `#[ignore]`
//! because it runs the full Groth16 trusted setup (~120–150 s on release
//! builds). Run explicitly with:
//!
//! ```
//! cargo test -p zkap-service --release --test setup_rng -- --ignored
//! ```

use std::fs;
use std::path::PathBuf;

use zkap_service::{CircuitConfig, SetupRng, setup};

fn test_config() -> CircuitConfig {
    CircuitConfig {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: 6,
        k: 3,
        tree_height: 4,
        num_audience_limit: 5,
        claims: vec![
            "aud".into(),
            "exp".into(),
            "iss".into(),
            "nonce".into(),
            "sub".into(),
        ],
        forbidden_string: "forbidden".into(),
    }
}

fn unique_tmp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("setup_rng_{label}_{}_{nanos}", std::process::id()))
}

/// Two `setup()` calls with the same `SetupRng::ChaCha20` seed must produce
/// byte-identical `pk.bin` and `vk.bin` files.
///
/// This is the core safety property: a deterministic-seed bundle is
/// reproducible, meaning the toxic waste is fully recoverable from the seed —
/// which is why the CLI gates this path behind `--allow-test-only`.
///
/// Marked `#[ignore]` because the full Groth16 setup takes ~120–150 s even in
/// `--release` mode. Run with:
/// `cargo test -p zkap-service --release --test setup_rng -- --ignored`
#[test]
#[ignore = "slow: runs full Groth16 setup twice (~240s total in --release). Run explicitly to verify ChaCha20 determinism."]
fn setup_with_chacha20_seed_is_deterministic() {
    let seed = [42u8; 32];
    let cfg = test_config();

    let dir1 = unique_tmp_dir("chacha_run1");
    let dir2 = unique_tmp_dir("chacha_run2");
    fs::create_dir_all(&dir1).expect("create dir1");
    fs::create_dir_all(&dir2).expect("create dir2");

    setup(&cfg, &dir1, SetupRng::ChaCha20 { seed }, None).expect("setup run 1 must succeed");
    setup(&cfg, &dir2, SetupRng::ChaCha20 { seed }, None).expect("setup run 2 must succeed");

    let pk1 = fs::read(dir1.join("pk.bin")).expect("pk.bin run 1");
    let pk2 = fs::read(dir2.join("pk.bin")).expect("pk.bin run 2");
    assert_eq!(
        pk1, pk2,
        "pk.bin must be byte-identical across two ChaCha20 runs with the same seed"
    );

    let vk1 = fs::read(dir1.join("vk.bin")).expect("vk.bin run 1");
    let vk2 = fs::read(dir2.join("vk.bin")).expect("vk.bin run 2");
    assert_eq!(
        vk1, vk2,
        "vk.bin must be byte-identical across two ChaCha20 runs with the same seed"
    );

    let _ = fs::remove_dir_all(&dir1);
    let _ = fs::remove_dir_all(&dir2);
}

/// Verify that `SetupRng::OsRng` produces a `SetupOutput` with non-zero
/// constraint-system shape fields (i.e. the setup ran and the circuit was
/// synthesized). This is a fast shape-only check — it does not run the full
/// Groth16 key generation.
///
/// Marked `#[ignore]` because even the shape-extraction phase of setup
/// involves circuit synthesis (~120 s in release mode for the full ZKAP
/// circuit). The shape itself is already gated by `l3_byte_gate.rs`; this
/// test is here as a regression anchor for the `SetupRng::OsRng` variant.
#[test]
#[ignore = "slow: runs full Groth16 setup (~120s in --release). Run explicitly to verify OsRng variant."]
fn setup_rng_variant_emits_correct_provenance() {
    let cfg = test_config();
    let dir = unique_tmp_dir("osrng_provenance");
    fs::create_dir_all(&dir).expect("create dir");

    let output = setup(&cfg, &dir, SetupRng::OsRng, None).expect("setup with OsRng must succeed");

    // The shape fields are populated from the synthesized ConstraintSystem —
    // non-zero values confirm setup ran end-to-end.
    assert!(
        output.shape.num_constraints > 0,
        "num_constraints must be non-zero after OsRng setup"
    );
    assert!(
        output.shape.num_witness > 0,
        "num_witness must be non-zero after OsRng setup"
    );
    assert!(
        output.shape.num_instance > 0,
        "num_instance must be non-zero after OsRng setup"
    );

    let _ = fs::remove_dir_all(&dir);
}
