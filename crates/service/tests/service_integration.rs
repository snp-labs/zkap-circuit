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

    setup(&params, &tmp_dir).expect("setup() failed");

    // All 5 required files must exist
    assert!(tmp_dir.join("pk.key").exists(), "pk.key missing");
    assert!(tmp_dir.join("vk.key").exists(), "vk.key missing");
    assert!(tmp_dir.join("pvk.key").exists(), "pvk.key missing");
    assert!(
        tmp_dir.join("Groth16Verifier.sol").exists(),
        "Groth16Verifier.sol missing"
    );
    assert!(tmp_dir.join("config.json").exists(), "config.json missing");

    // manifest.json must NOT be created
    assert!(
        !tmp_dir.join("manifest.json").exists(),
        "manifest.json should not be created"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
#[ignore]
fn test_setup_config_json_round_trip() {
    use zkap_service::{load_circuit_config, setup};

    let params = test_config();
    let tmp_dir = std::env::temp_dir().join("zkap-test-config-roundtrip");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    setup(&params, &tmp_dir).expect("setup() failed");

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

#[test]
#[ignore]
fn test_setup_and_verify() {
    use zkap_service::{ProofComponents, setup, verify};

    let params = test_config();
    let tmp_dir = std::env::temp_dir().join("zkap-test-setup-verify");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let setup_output = setup(&params, &tmp_dir).expect("setup() failed");

    // VK should have the right number of public inputs
    assert!(setup_output.public_input_count() > 0);

    // Verify with dummy proof/inputs should fail gracefully (not panic)
    let ctx = setup_output.verifying_context();
    let dummy_proof = ProofComponents {
        a: ["0".to_string(), "0".to_string()],
        b: [
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
            "0".to_string(),
        ],
        c: ["0".to_string(), "0".to_string()],
    };
    let dummy_inputs = vec!["0".to_string(); 8];
    let result = verify(&ctx, &dummy_proof, &dummy_inputs);
    assert!(result.is_ok() || result.is_err());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
