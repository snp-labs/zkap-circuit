//! Full Groth16 proof lifecycle example for the ZKAP protocol.
//!
//! Demonstrates all 7 public API functions of `zkap-service`:
//!   - `groth16_setup`    — Step 2: Trusted setup (CRS generation)
//!   - `generate_hash`    — Step 3: General-purpose Poseidon hash (nonce computation)
//!   - `generate_leaf_hash` — Step 4: Merkle leaf hash
//!   - `generate_anchor`  — Step 5: Threshold anchor generation
//!   - `generate_aud_hash` — Step 6: Audience hash
//!   - `prove`            — Step 6: Zero-knowledge proof generation
//!   - `verify`           — Step 7: Proof verification
//!
//! Run with:
//!   cargo run -p zkap-service --example groth16_proof --release
//!
//! NOTE: The trusted setup step is computationally expensive.
//!       Use --release for reasonable performance (~2-5 minutes total).

use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::rand::SeedableRng;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};

use ark_utils::hex_decimal_to_field;
use zkap_service::constants::{F, PoseidonHash, RawCircuitConfig};
use zkap_service::{
    CircuitConfig, CrsPersistConfig, RawProofRequest, Secret, generate_anchor, generate_aud_hash,
    generate_hash, generate_leaf_hash, groth16_setup_and_save, prove, verify,
};

use gadget::hashes::poseidon::get_poseidon_params;
use gadget::merkletree::tree_config::MerkleTreeParams;

// ============================================================
// Constants
// ============================================================

const N: usize = 6;
const K: usize = 3;
const TREE_HEIGHT: u64 = 4;
const AUD: &str = "test-audience";
const ISS: &str = "https://issuer.example.com";
const EXP: u64 = 1700000000;

fn main() {
    println!("=== ZKAP Groth16 Proof Lifecycle Example ===\n");

    // ============================================================
    // Step 1: Circuit Configuration
    // ============================================================
    println!(
        "[Step 1] Creating circuit configuration (N={}, K={})...",
        N, K
    );

    let config = build_config();
    println!(
        "  Circuit params: JWT max={}B, payload max={}B, tree_height={}",
        config.max_jwt_b64_len, config.max_payload_b64_len, config.tree_height
    );

    // ============================================================
    // Step 2: Groth16 Trusted Setup (CRS Generation)
    //   API: groth16_setup()
    // ============================================================
    println!("\n[Step 2] Running Groth16 trusted setup (CRS generation)...");

    // groth16_setup_and_save handles PK/VK serialisation and manifest.json in one call
    let pk_dir = std::env::temp_dir().join("zkap-example");
    std::fs::create_dir_all(&pk_dir).expect("Failed to create temp dir");
    let persist_config = CrsPersistConfig {
        output_dir: pk_dir.clone(),
        profile: "example".to_string(),
    };
    let (setup_output, crs_paths) =
        groth16_setup_and_save(&config, &persist_config).expect("Groth16 setup and save failed");
    let pk_path = crs_paths.pk.clone();
    println!(
        "  Setup complete: {} public inputs, CRS written to {}",
        setup_output.public_input_count(),
        pk_dir.display()
    );

    // ============================================================
    // Step 3: RSA Key Generation + JWT Construction
    //   API: generate_hash() — for nonce computation
    // ============================================================
    println!(
        "\n[Step 3] Generating {} RSA-2048 keys and signing JWTs...",
        K
    );

    let random = F::from(12345u64);
    let h_sign_user_op = F::from(67890u64);
    let nonce_str = generate_hash(vec![
        field_to_decimal(&h_sign_user_op),
        field_to_decimal(&random),
    ])
    .expect("Nonce hash failed");
    let nonce: F = hex_decimal_to_field(&nonce_str).expect("Parse nonce");
    let nonce_hex = format!("0x{}", hex::encode(nonce.into_bigint().to_bytes_be()));

    let mut jwts = Vec::new();
    let mut rsa_keys = Vec::new();

    for i in 0..K {
        let sub = format!("user_{}", i);
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(99 + i as u64);
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let jwt = build_and_sign_jwt(AUD, EXP, ISS, &nonce_hex, &sub, &priv_key);

        println!("  JWT[{}]: sub={}, signed with RSA-2048", i, sub);
        jwts.push(jwt);
        rsa_keys.push(priv_key);
    }

    // ============================================================
    // Step 4: Merkle Tree Construction
    //   API: generate_leaf_hash() — for computing leaf hashes
    // ============================================================
    println!(
        "\n[Step 4] Building issuer Merkle tree (height={})...",
        TREE_HEIGHT
    );

    let poseidon_params = get_poseidon_params::<F>();
    let num_leaves = 1usize << TREE_HEIGHT;
    let b64_engine = base64::engine::general_purpose::STANDARD;

    // IMPORTANT: The circuit extracts ISS from JWT claims WITH JSON quotes,
    // so we must pass the quoted form to generate_leaf_hash for consistency.
    let quoted_iss = format!("\"{}\"", ISS);
    let mut leaf_digests = vec![F::zero(); num_leaves];
    let mut pk_ops = Vec::new();

    for i in 0..K {
        let n_bytes = rsa_keys[i].to_public_key().n().to_bytes_be();
        let pk_b64 = b64_engine.encode(&n_bytes);
        let leaf_str = generate_leaf_hash(&config, &quoted_iss, &pk_b64).expect("Leaf hash failed");
        let leaf: F = hex_decimal_to_field(&leaf_str).expect("Parse leaf");
        // Merkle tree needs the inner-hash of the leaf (Poseidon(leaf))
        let leaf_digest = PoseidonHash::evaluate(&poseidon_params, [leaf]).unwrap();
        leaf_digests[i] = leaf_digest;
        pk_ops.push(pk_b64);
    }

    let tree = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(
        &poseidon_params,
        &poseidon_params,
        leaf_digests,
    )
    .expect("Merkle tree construction failed");
    let root = tree.root();
    println!("  Tree root: {}...", &field_to_decimal(&root)[..20]);

    // Extract merkle paths as string vectors for RawProofRequest
    // Format: [leaf_sibling_hash, auth_path_nodes...] (auth path in reverse order)
    let mut merkle_paths: Vec<Vec<String>> = Vec::new();
    let leaf_indices: Vec<u64> = (0..K as u64).collect();

    for i in 0..K {
        let proof = tree.generate_proof(i).unwrap();
        let mut path_strings = vec![field_to_decimal(&proof.leaf_sibling_hash)];
        // auth_path must be reversed for the service API (it reverses back internally)
        for node in proof.auth_path.iter().rev() {
            path_strings.push(field_to_decimal(node));
        }
        merkle_paths.push(path_strings);
    }
    println!("  {} merkle proofs extracted", K);

    // ============================================================
    // Step 5: Anchor Generation
    //   API: generate_anchor() — for threshold membership
    //   API: generate_hash() — for hanchor chain hash
    // ============================================================
    println!(
        "\n[Step 5] Generating threshold anchor (N={}, K={})...",
        N, K
    );

    // Secret values must include JSON quotes (matching JWT claim extraction)
    let mut all_secrets = Vec::new();
    for i in 0..K {
        all_secrets.push(Secret {
            sub: format!("\"user_{}\"", i),
            iss: format!("\"{}\"", ISS),
            aud: format!("\"{}\"", AUD),
        });
    }
    for i in 0..(N - K) {
        all_secrets.push(Secret {
            sub: format!("\"dummy_sub_{}\"", i),
            iss: format!("\"dummy_iss_{}\"", i),
            aud: format!("\"dummy_aud_{}\"", i),
        });
    }

    let anchor_result = generate_anchor(&config, all_secrets).expect("Anchor generation failed");

    // Compute hanchor via chain hash using generate_hash()
    let mut hanchor = generate_hash(vec![anchor_result.anchor[0].clone()]).expect("Hash failed");
    for v in &anchor_result.anchor[1..] {
        hanchor = generate_hash(vec![hanchor.clone(), v.clone()]).expect("Hash failed");
    }

    let anchor_evals = anchor_result.anchor.clone();
    println!(
        "  Anchor: {} evals, hanchor computed via generate_hash()",
        anchor_evals.len()
    );

    // ============================================================
    // Step 6: Proof Generation
    //   API: generate_aud_hash() — for audience hash
    //   API: prove() — for zero-knowledge proof generation
    // ============================================================
    println!(
        "\n[Step 6] Generating {} Groth16 proofs via prove() API...",
        K
    );

    // Audience list (quoted form, matching circuit extraction)
    let quoted_aud = format!("\"{}\"", AUD);
    let aud_result = generate_aud_hash(&config, vec![quoted_aud]).expect("Audience hash failed");
    let aud_hash_list: Vec<String> = aud_result.individual;

    // Construct RawProofRequest with all prepared data
    let raw_request = RawProofRequest::new(
        pk_path.clone(),
        jwts,
        pk_ops,
        merkle_paths,
        leaf_indices,
        field_to_decimal(&root),
        anchor_evals,
        hanchor,
        field_to_decimal(&h_sign_user_op),
        field_to_decimal(&random),
        aud_hash_list,
    );

    let proof_result = prove(&config, raw_request).expect("Proof generation failed");
    for i in 0..K {
        println!("  Proof {}/{} generated", i + 1, K);
    }

    // ============================================================
    // Step 7: Proof Verification
    //   API: verify() — accepts VerifyingContext + ProofComponents + String inputs
    // ============================================================
    println!("\n[Step 7] Verifying proofs...");

    let ctx = setup_output.verifying_context();
    for (i, proof_comp) in proof_result.proofs.iter().enumerate() {
        let pub_inputs = proof_result.public_inputs_for(i);
        let valid = verify(&ctx, proof_comp, &pub_inputs).expect("Verification call failed");
        println!(
            "  Proof {}/{}: {}",
            i + 1,
            K,
            if valid { "VALID" } else { "INVALID" }
        );
        assert!(valid, "Proof {} should be valid", i);
    }

    // Demonstrate: tampered public input fails verification
    let mut tampered_inputs = proof_result.public_inputs_for(0);
    tampered_inputs[0] = "0".to_string(); // corrupt hanchor
    let invalid =
        verify(&ctx, &proof_result.proofs[0], &tampered_inputs).expect("Verification call failed");
    println!(
        "  Tampered proof: {}",
        if invalid {
            "VALID (unexpected!)"
        } else {
            "INVALID (expected)"
        }
    );
    assert!(!invalid, "Tampered proof should not verify");

    // Cleanup temp files
    let _ = std::fs::remove_dir_all(&pk_dir);

    println!("\n=== All steps completed successfully! ===");
}

// ============================================================
// Helper Functions
// ============================================================

fn build_config() -> CircuitConfig {
    let raw = RawCircuitConfig {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: N as u64,
        k: K as u64,
        tree_height: TREE_HEIGHT,
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

fn build_and_sign_jwt(
    aud: &str,
    exp: u64,
    iss: &str,
    nonce_hex: &str,
    sub: &str,
    priv_key: &rsa::RsaPrivateKey,
) -> String {
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let payload = format!(
        r#"{{"aud":"{}","exp":{},"iss":"{}","nonce":"{}","sub":"{}"}}"#,
        aud, exp, iss, nonce_hex, sub
    );
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = engine.encode(header);
    let payload_b64 = engine.encode(&payload);
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = engine.encode(signature.to_bytes());
    format!("{}.{}", signing_input, sig_b64)
}

fn field_to_decimal(f: &F) -> String {
    f.into_bigint().to_string()
}
