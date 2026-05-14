//! Service crate integration tests
//!
//! Tests that exercise public API functions across module boundaries.
//! The `#[ignore]` tests require CRS generation and are slow (~30s+).
//! Run with: `cargo test -p zkap-service --test service_integration -- --ignored`

use zkap_service::{
    CircuitConfig, Secret, generate_anchor, generate_aud_hash, generate_hash, generate_leaf_hash,
};

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

// ============ Cross-module integration tests ============

#[test]
fn test_anchor_generation_and_hash_pipeline() {
    let params = test_config();

    let secrets: Vec<Secret> = (0..params.n)
        .map(|i| Secret {
            sub: format!("user_{}", i),
            iss: "https://accounts.google.com".to_string(),
            aud: "test-audience".to_string(),
        })
        .collect();

    let anchor = generate_anchor(&params, secrets).unwrap();

    // Anchor should have n - k + 1 elements
    assert_eq!(anchor.len(), (params.n - params.k + 1) as usize);

    // Hash the anchor elements — outputs are 0x-prefixed hex strings
    let h = generate_hash(anchor).unwrap();
    assert!(h.starts_with("0x"), "hash should be 0x-prefixed hex: {}", h);
}

#[test]
fn test_aud_hash_and_leaf_hash_consistency() {
    let params = test_config();

    let aud_list = vec!["test-audience".to_string(), "second-aud".to_string()];
    let aud_result = generate_aud_hash(&params, aud_list.clone()).unwrap();

    // Same input → same output
    let aud_result2 = generate_aud_hash(&params, aud_list).unwrap();
    assert_eq!(aud_result.individual, aud_result2.individual);
    assert_eq!(aud_result.combined, aud_result2.combined);

    // Fields length should equal num_audience_limit
    assert_eq!(
        aud_result.individual.len(),
        params.num_audience_limit as usize
    );

    // All outputs are 0x-prefixed hex
    assert!(aud_result.combined.starts_with("0x"));

    // Generate leaf hash with a minimal PK — deterministic
    let pk_b64 = "AQAB";
    let leaf1 = generate_leaf_hash(&params, "https://accounts.google.com", pk_b64).unwrap();
    let leaf2 = generate_leaf_hash(&params, "https://accounts.google.com", pk_b64).unwrap();
    assert_eq!(leaf1, leaf2);
    assert!(leaf1.starts_with("0x"));
}

#[test]
fn test_anchor_deterministic_with_same_secrets() {
    let params = test_config();

    let secrets: Vec<Secret> = (0..params.n)
        .map(|i| Secret {
            sub: format!("user_{}", i),
            iss: "issuer".to_string(),
            aud: "aud".to_string(),
        })
        .collect();

    let anchor1 = generate_anchor(&params, secrets.clone()).unwrap();
    let anchor2 = generate_anchor(&params, secrets).unwrap();
    assert_eq!(anchor1, anchor2);
}

#[test]
fn test_anchor_different_secrets_different_output() {
    let params = test_config();

    let secrets_a: Vec<Secret> = (0..params.n)
        .map(|i| Secret {
            sub: format!("alice_{}", i),
            iss: "issuer".to_string(),
            aud: "aud".to_string(),
        })
        .collect();

    let secrets_b: Vec<Secret> = (0..params.n)
        .map(|i| Secret {
            sub: format!("bob_{}", i),
            iss: "issuer".to_string(),
            aud: "aud".to_string(),
        })
        .collect();

    let anchor_a = generate_anchor(&params, secrets_a).unwrap();
    let anchor_b = generate_anchor(&params, secrets_b).unwrap();
    assert_ne!(anchor_a, anchor_b);
}

// ============ Slow tests (require CRS) ============

#[test]
#[ignore]
fn test_setup_creates_all_artifacts() {
    use zkap_service::setup;

    let params = test_config();
    let tmp_dir = std::env::temp_dir().join("zkap-test-artifacts");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    setup(&params, &tmp_dir, &mut rand::rngs::OsRng, None).expect("setup() failed");

    // Post-migration (Commit 2 of the 2026-05 ark-ar1cs boundary plan)
    // setup output: six core files. `manifest.json` is written by the
    // CLI (`generate_setup`), not by `service::setup`.
    assert!(
        tmp_dir.join("circuit.ar1cs").exists(),
        "circuit.ar1cs missing"
    );
    assert!(tmp_dir.join("pk.bin").exists(), "pk.bin missing");
    assert!(tmp_dir.join("vk.bin").exists(), "vk.bin missing");
    assert!(tmp_dir.join("pvk.bin").exists(), "pvk.bin missing");
    assert!(
        tmp_dir.join("Groth16Verifier.sol").exists(),
        "Groth16Verifier.sol missing"
    );
    assert!(tmp_dir.join("config.json").exists(), "config.json missing");

    // manifest.json is the CLI's responsibility — service::setup must
    // not produce it.
    assert!(
        !tmp_dir.join("manifest.json").exists(),
        "manifest.json must be CLI-owned, not written by service::setup"
    );

    // Legacy artifacts must NOT reappear after the boundary migration.
    for legacy in ["pk.arzkey", "pk.key", "vk.key", "pvk.key"] {
        assert!(
            !tmp_dir.join(legacy).exists(),
            "legacy artifact {legacy} must not be produced after Commit 2"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
#[ignore]
fn test_setup_config_json_round_trip() {
    use zkap_service::{load_circuit_config, setup};

    let params = test_config();
    let tmp_dir = std::env::temp_dir().join("zkap-test-config-roundtrip");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    setup(&params, &tmp_dir, &mut rand::rngs::OsRng, None).expect("setup() failed");

    let loaded =
        load_circuit_config(&tmp_dir.join("config.json")).expect("load_circuit_config failed");

    assert_eq!(loaded.max_jwt_b64_len, params.max_jwt_b64_len);
    assert_eq!(loaded.max_payload_b64_len, params.max_payload_b64_len);
    assert_eq!(loaded.max_aud_len, params.max_aud_len);
    assert_eq!(loaded.max_iss_len, params.max_iss_len);
    assert_eq!(loaded.max_sub_len, params.max_sub_len);
    assert_eq!(loaded.n, params.n);
    assert_eq!(loaded.k, params.k);
    assert_eq!(loaded.tree_height, params.tree_height);
    assert_eq!(loaded.num_audience_limit, params.num_audience_limit);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// Acceptance: after Commit 5 of the 2026-05 ark-ar1cs boundary
/// migration there is no in-crate verify wrapper — callers obtain a
/// borrow of the bundled `PreparedVerifyingKey` and pass it straight
/// to `Groth16::verify_proof`. This test pins the pattern.
#[test]
#[ignore]
fn test_setup_and_verify_via_arkworks_direct() {
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use ark_groth16::{Groth16, Proof};
    use circuit::types::{BN254, F};
    use zkap_service::setup;

    let params = test_config();
    let tmp_dir = std::env::temp_dir().join("zkap-test-setup-verify-direct");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let setup_output =
        setup(&params, &tmp_dir, &mut rand::rngs::OsRng, None).expect("setup() failed");

    // VK should have the right number of public inputs.
    assert!(setup_output.public_input_count() > 0);

    // A zero-valued affine point + zero instance vector is not a real
    // proof, but it exercises the canonical call path
    // (`Groth16::verify_proof` against the bundled `PreparedVerifyingKey`).
    let dummy_proof: Proof<BN254> = Proof {
        a: G1Affine::new_unchecked(Fq::from(0u64), Fq::from(0u64)),
        b: G2Affine::new_unchecked(
            Fq2::new(Fq::from(0u64), Fq::from(0u64)),
            Fq2::new(Fq::from(0u64), Fq::from(0u64)),
        ),
        c: G1Affine::new_unchecked(Fq::from(0u64), Fq::from(0u64)),
    };
    let dummy_inputs: Vec<F> = vec![F::from(0u64); 8];

    let pvk = setup_output.prepared_verifying_key();
    let result = Groth16::<BN254>::verify_proof(pvk, &dummy_proof, &dummy_inputs);
    // The arkworks verifier may either return Ok(false) or an error
    // for a malformed pairing input; both outcomes confirm the call
    // path is wired up. What we must NOT see is a panic or an
    // accidental Ok(true) on garbage.
    if let Ok(verified) = result {
        assert!(
            !verified,
            "Groth16::verify_proof must not accept a zeroed dummy proof"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
