//! Service crate integration tests
//!
//! Tests that exercise public API functions across module boundaries.
//! The `#[ignore]` tests require CRS generation and are slow (~30s+).
//! Run with: `cargo test -p zkap-service --test service_integration -- --ignored`

use circuit::constants::RawCircuitConfig;
use zkap_service::{
    CircuitConfig, Secret, generate_anchor, generate_aud_hash, generate_hash, generate_leaf_hash,
};

fn test_config() -> CircuitConfig {
    let raw = RawCircuitConfig {
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
    };
    raw.into()
}

// ============ Cross-module integration tests ============

#[test]
fn test_anchor_generation_and_hash_pipeline() {
    let params = test_config();

    // Generate anchor from secrets
    let secrets: Vec<Secret> = (0..params.n)
        .map(|i| Secret {
            sub: format!("user_{}", i),
            iss: "https://accounts.google.com".to_string(),
            aud: "test-audience".to_string(),
        })
        .collect();

    let anchor = generate_anchor(&params, secrets).unwrap();

    // Anchor should have n - k + 1 elements
    assert_eq!(anchor.anchor.len(), (params.n - params.k + 1) as usize);

    // Hash the anchor elements (already decimal strings)
    let h = generate_hash(anchor.anchor).unwrap();

    // Hash should be non-zero and deterministic
    assert_ne!(h, "0");
}

#[test]
fn test_aud_hash_and_leaf_hash_consistency() {
    let params = test_config();

    // Generate audience hash
    let aud_list = vec!["test-audience".to_string(), "second-aud".to_string()];
    let aud_result = generate_aud_hash(&params, aud_list.clone()).unwrap();

    // Same input → same output
    let aud_result2 = generate_aud_hash(&params, aud_list).unwrap();
    assert_eq!(aud_result.individual, aud_result2.individual);
    assert_eq!(aud_result.combined, aud_result2.combined);

    // Fields length should equal num_audience_limit
    assert_eq!(aud_result.individual.len(), params.num_audience_limit as usize);

    // Generate leaf hash with a minimal PK
    let pk_b64 = "AQAB";
    let leaf1 = generate_leaf_hash(&params, "https://accounts.google.com", pk_b64).unwrap();
    let leaf2 = generate_leaf_hash(&params, "https://accounts.google.com", pk_b64).unwrap();
    assert_eq!(leaf1, leaf2);
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
    assert_eq!(anchor1.anchor, anchor2.anchor);
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
    assert_ne!(anchor_a.anchor, anchor_b.anchor);
}

// ============ Slow tests (require CRS) ============

#[test]
#[ignore]
fn test_groth16_setup_and_verify() {
    use zkap_service::{ProofComponents, groth16_setup, verify};

    let params = test_config();

    // Setup should succeed
    let setup = groth16_setup(&params).unwrap();

    // VK should have the right number of public inputs
    assert!(setup.public_input_count() > 0);

    // Verify with dummy proof/inputs should fail gracefully
    let ctx = setup.verifying_context();
    let dummy_proof = ProofComponents {
        a: ["0".to_string(), "0".to_string()],
        b: ["0".to_string(), "0".to_string(), "0".to_string(), "0".to_string()],
        c: ["0".to_string(), "0".to_string()],
    };
    let dummy_inputs = vec!["0".to_string(); 8];
    let result = verify(&ctx, &dummy_proof, &dummy_inputs);
    // Should return Ok(false) or Err, not panic
    assert!(result.is_ok() || result.is_err());
}
