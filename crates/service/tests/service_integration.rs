//! Service crate integration tests
//!
//! Tests that exercise public API functions across module boundaries.
//! The `#[ignore]` tests require CRS generation and are slow (~30s+).
//! Run with: `cargo test -p zkap-service --test service_integration -- --ignored`

use zkap_service::{
    AnchorSecret, AudienceHashRequest, CircuitConfig, GenerateAnchorRequest, HashRequest,
    IssuerKeyHashRequest, generate_anchor, generate_audience_hashes, generate_issuer_key_hash,
    generate_poseidon_hash,
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

    let secrets: Vec<AnchorSecret> = (0..params.n)
        .map(|i| AnchorSecret {
            subject: format!("user_{}", i),
            issuer: "https://accounts.google.com".to_string(),
            audience: "test-audience".to_string(),
        })
        .collect();

    let resp = generate_anchor(&params, GenerateAnchorRequest { secrets }).unwrap();

    // Anchor should have n - k + 1 elements
    assert_eq!(
        resp.anchor_evaluations.len(),
        (params.n - params.k + 1) as usize
    );
    assert!(resp.hanchor.starts_with("0x"));
    for ev in &resp.anchor_evaluations {
        assert!(ev.starts_with("0x"));
    }

    // Hanchor cross-check: chain-hashing the evaluations via the public
    // `generate_poseidon_hash` (`H(v[0])`, then `H(prev, v[i])`) yields the
    // same `hanchor` value the service produces internally — proving the
    // service's built-in chain hash matches the documented recipe.
    let mut chained = generate_poseidon_hash(HashRequest {
        field_elements: vec![resp.anchor_evaluations[0].clone()],
    })
    .unwrap()
    .hash;
    for ev in resp.anchor_evaluations.iter().skip(1) {
        chained = generate_poseidon_hash(HashRequest {
            field_elements: vec![chained, ev.clone()],
        })
        .unwrap()
        .hash;
    }
    assert_eq!(
        chained, resp.hanchor,
        "service hanchor must equal the public chain-hash recipe"
    );
}

#[test]
fn test_audience_and_issuer_key_hash_consistency() {
    use base64::Engine;

    let params = test_config();

    let aud_list = vec!["test-audience".to_string(), "second-aud".to_string()];
    let aud_result = generate_audience_hashes(
        &params,
        AudienceHashRequest {
            audiences: aud_list.clone(),
        },
    )
    .unwrap();

    // Same input → same output
    let aud_result2 = generate_audience_hashes(
        &params,
        AudienceHashRequest {
            audiences: aud_list,
        },
    )
    .unwrap();
    assert_eq!(aud_result.audience_hashes, aud_result2.audience_hashes);
    assert_eq!(
        aud_result.audience_list_hash,
        aud_result2.audience_list_hash
    );

    // Per-audience array length equals num_audience_limit (padded with
    // forbidden_string).
    assert_eq!(
        aud_result.audience_hashes.len(),
        params.num_audience_limit as usize
    );

    // All outputs are 0x-prefixed hex.
    assert!(aud_result.audience_list_hash.starts_with("0x"));

    // Issuer-key Merkle leaf — RSA-2048 modulus is 256 bytes; the bit
    // pattern is irrelevant for the host-side hash flow.
    let modulus_bytes = {
        let mut v = vec![0xAB; 256];
        v[0] = 0xC0;
        v[255] = 0x01;
        v
    };
    let rsa_modulus_b64 = base64::engine::general_purpose::STANDARD.encode(modulus_bytes);

    let leaf1 = generate_issuer_key_hash(
        &params,
        IssuerKeyHashRequest {
            issuer: "https://accounts.google.com".into(),
            rsa_modulus_b64: rsa_modulus_b64.clone(),
        },
    )
    .unwrap();
    let leaf2 = generate_issuer_key_hash(
        &params,
        IssuerKeyHashRequest {
            issuer: "https://accounts.google.com".into(),
            rsa_modulus_b64,
        },
    )
    .unwrap();
    assert_eq!(leaf1.hash, leaf2.hash);
    assert!(leaf1.hash.starts_with("0x"));
}

#[test]
fn test_anchor_deterministic_with_same_secrets() {
    let params = test_config();

    let secrets: Vec<AnchorSecret> = (0..params.n)
        .map(|i| AnchorSecret {
            subject: format!("user_{}", i),
            issuer: "issuer".to_string(),
            audience: "aud".to_string(),
        })
        .collect();

    let r1 = generate_anchor(
        &params,
        GenerateAnchorRequest {
            secrets: secrets.clone(),
        },
    )
    .unwrap();
    let r2 = generate_anchor(&params, GenerateAnchorRequest { secrets }).unwrap();
    assert_eq!(r1.anchor_evaluations, r2.anchor_evaluations);
    assert_eq!(r1.hanchor, r2.hanchor);
}

#[test]
fn test_anchor_different_secrets_different_output() {
    let params = test_config();

    let secrets_a: Vec<AnchorSecret> = (0..params.n)
        .map(|i| AnchorSecret {
            subject: format!("alice_{}", i),
            issuer: "issuer".to_string(),
            audience: "aud".to_string(),
        })
        .collect();

    let secrets_b: Vec<AnchorSecret> = (0..params.n)
        .map(|i| AnchorSecret {
            subject: format!("bob_{}", i),
            issuer: "issuer".to_string(),
            audience: "aud".to_string(),
        })
        .collect();

    let r_a = generate_anchor(&params, GenerateAnchorRequest { secrets: secrets_a }).unwrap();
    let r_b = generate_anchor(&params, GenerateAnchorRequest { secrets: secrets_b }).unwrap();
    assert_ne!(r_a.anchor_evaluations, r_b.anchor_evaluations);
    assert_ne!(r_a.hanchor, r_b.hanchor);
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

    // The bundle layout is enforced structurally by
    // `scripts/check-bundle-layout.sh` (CI gate); no need to enumerate
    // retired filenames here.

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
