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
use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};

use zkap_service::constants::{F, PoseidonHash, RawCircuitConfig};
use zkap_service::{
    CircuitConfig, RawProofRequest, Secret, generate_anchor, generate_aud_hash, generate_hash,
    generate_leaf_hash, groth16_setup, prove, verify,
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

    let setup_output = groth16_setup(&config).expect("Groth16 setup failed");
    println!(
        "  Setup complete: VK has {} public input elements",
        setup_output.vk.gamma_abc_g1.len()
    );

    // Serialize proving key to temp directory (prove() loads pk from disk)
    let pk_dir = std::env::temp_dir().join("zkap-example");
    std::fs::create_dir_all(&pk_dir).expect("Failed to create temp dir");
    let pk_path = pk_dir.join("pk.key");

    let mut pk_file = std::fs::File::create(&pk_path).expect("Failed to create pk file");
    setup_output
        .pk
        .serialize_uncompressed(&mut pk_file)
        .expect("Failed to serialize pk");
    drop(pk_file);

    // Write manifest.json (required by prove() for parameter validation)
    let manifest_path = pk_dir.join("manifest.json");
    let manifest = format!(
        r#"{{"profile":"example","params":{{"MAX_JWT_B64_LEN":{},"MAX_PAYLOAD_B64_LEN":{},"MAX_AUD_LEN":{},"MAX_EXP_LEN":{},"MAX_ISS_LEN":{},"MAX_NONCE_LEN":{},"MAX_SUB_LEN":{},"N":{},"K":{},"TREE_HEIGHT":{},"NUM_AUDIENCE_LIMIT":{}}}}}"#,
        config.max_jwt_b64_len,
        config.max_payload_b64_len,
        config.max_aud_len,
        config.max_exp_len,
        config.max_iss_len,
        config.max_nonce_len,
        config.max_sub_len,
        config.n,
        config.k,
        config.tree_height,
        config.num_audience_limit,
    );
    std::fs::write(&manifest_path, &manifest).expect("Failed to write manifest.json");
    println!("  PK serialized to {}", pk_path.display());

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
    let nonce = generate_hash(vec![
        field_to_decimal(&h_sign_user_op),
        field_to_decimal(&random),
    ])
    .expect("Nonce hash failed");
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
        let leaf = generate_leaf_hash(&config, &quoted_iss, &pk_b64).expect("Leaf hash failed");
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
    let leaf_indices: Vec<usize> = (0..K).collect();

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

    let anchor = generate_anchor(&config, all_secrets).expect("Anchor generation failed");

    // Compute hanchor via chain hash using generate_hash()
    let mut hanchor = generate_hash(vec![field_to_decimal(&anchor.0[0])]).expect("Hash failed");
    for v in &anchor.0[1..] {
        hanchor = generate_hash(vec![field_to_decimal(&hanchor), field_to_decimal(v)])
            .expect("Hash failed");
    }

    // Build anchor string array: [anchor_values..., hanchor]
    let mut anchor_strings: Vec<String> = anchor.0.iter().map(field_to_decimal).collect();
    anchor_strings.push(field_to_decimal(&hanchor));
    println!(
        "  Anchor: {} values, hanchor computed via generate_hash()",
        anchor.0.len()
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
    let (aud_fields, _h_aud_list) =
        generate_aud_hash(&config, vec![quoted_aud]).expect("Audience hash failed");
    let aud_list: Vec<String> = aud_fields.iter().map(field_to_decimal).collect();

    // Construct RawProofRequest with all prepared data
    let raw_request = RawProofRequest::new(
        pk_path.clone(),
        jwts,
        pk_ops,
        merkle_paths,
        leaf_indices,
        field_to_decimal(&root),
        anchor_strings,
        field_to_decimal(&h_sign_user_op),
        field_to_decimal(&random),
        aud_list,
    );

    let (proofs, all_public_inputs) = prove(&config, raw_request).expect("Proof generation failed");
    for i in 0..K {
        println!("  Proof {}/{} generated", i + 1, K);
    }

    // ============================================================
    // Step 7: Proof Verification
    //   API: verify() — for proof verification
    // ============================================================
    println!("\n[Step 7] Verifying proofs...");

    let pvk = setup_output.pvk;
    for (i, (proof, pub_input)) in proofs.iter().zip(all_public_inputs.iter()).enumerate() {
        let valid = verify(&pvk, proof, pub_input).expect("Verification call failed");
        println!(
            "  Proof {}/{}: {}",
            i + 1,
            K,
            if valid { "VALID" } else { "INVALID" }
        );
        assert!(valid, "Proof {} should be valid", i);
    }

    // Demonstrate: tampered public input fails verification
    let mut tampered = all_public_inputs[0].clone();
    tampered[0] += F::from(1u64);
    let invalid = verify(&pvk, &proofs[0], &tampered).expect("Verification call failed");
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
