//! Full Groth16 proof lifecycle example for the ZKAP protocol.
//!
//! Demonstrates the complete 7-step pipeline:
//!   1. Circuit configuration
//!   2. Groth16 trusted setup (CRS generation)
//!   3. RSA key generation + JWT construction
//!   4. Merkle tree construction (issuer registry)
//!   5. Anchor generation (threshold membership)
//!   6. Zero-knowledge proof generation
//!   7. Proof verification
//!
//! This example uses the zkap-service API for setup, anchor, and hash generation,
//! and constructs circuit inputs directly to show the full data flow.
//!
//! Run with:
//!   cargo run -p zkap-service --example groth16_proof --release
//!
//! NOTE: The trusted setup step is computationally expensive.
//!       Use --release for reasonable performance (~2-5 minutes total).

use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_groth16::Groth16;
use ark_std::rand::SeedableRng;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use signature::{SignatureEncoding, Signer};

use zkap_service::{
    CircuitConfig, PAD_CHAR, Secret,
    generate_anchor, generate_aud_hash, generate_leaf_hash,
    verify,
};
use zkap_service::constants::{BN254, BNP, CG, F, PoseidonHash, RawCircuitConfig};

use circuit::input::*;
use circuit::token::ClaimIndices;
use circuit::zkap::ZkapCircuit;
use gadget::anchor::poseidon::{PoseidonAnchorPublicKey, build_anchor_witness};
use gadget::base64::{get_base64_table, IndexBits};
use gadget::hashes::poseidon::get_poseidon_params;
use gadget::matrix::VandermondeMatrix;
use gadget::merkletree::tree_config::MerkleTreeParams;
use gadget::signature::rsa::{PublicKey as RsaCircuitPubKey, Signature as RsaCircuitSig};

use ark_utils::{try_str_to_fields, pad};
use regex::Regex;

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
    println!("[Step 1] Creating circuit configuration (N={}, K={})...", N, K);

    let config = build_config();
    let poseidon_params = get_poseidon_params::<F>();
    println!("  Circuit params: JWT max={}B, payload max={}B, tree_height={}",
        config.max_jwt_b64_len, config.max_payload_b64_len, config.tree_height);

    // Step 2 (Groth16 trusted setup) is deferred to Step 6 where we use a real
    // circuit input for setup. This ensures the proving key matches the constraint structure.

    // ============================================================
    // Step 3: RSA Key Generation + JWT Construction
    // ============================================================
    println!("\n[Step 3] Generating {} RSA-2048 keys and signing JWTs...", K);

    let random = F::from(12345u64);
    let h_sign_user_op = F::from(67890u64);
    let nonce = PoseidonHash::evaluate(&poseidon_params, [h_sign_user_op, random]).unwrap();
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
    // Step 4: Merkle Tree Construction (using service API for leaf hashes)
    // ============================================================
    println!("\n[Step 4] Building issuer Merkle tree (height={})...", TREE_HEIGHT);

    let num_leaves = 1usize << TREE_HEIGHT;
    let engine = base64::engine::general_purpose::STANDARD;

    // Use generate_leaf_hash() service API for each leaf
    // IMPORTANT: The circuit extracts ISS from JWT claims WITH JSON quotes,
    // so we must pass the quoted form to generate_leaf_hash for consistency.
    let quoted_iss = format!("\"{}\"", ISS);
    let mut leaf_digests = vec![F::zero(); num_leaves];
    for i in 0..K {
        let n_bytes = rsa_keys[i].to_public_key().n().to_bytes_be();
        let pk_b64 = engine.encode(&n_bytes);
        let leaf = generate_leaf_hash(&config, &quoted_iss, &pk_b64).expect("Leaf hash failed");
        let leaf_digest = PoseidonHash::evaluate(&poseidon_params, [leaf]).unwrap();
        leaf_digests[i] = leaf_digest;
    }

    let tree = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(
        &poseidon_params, &poseidon_params, leaf_digests,
    ).expect("Merkle tree construction failed");
    let root = tree.root();
    println!("  Tree root: {}...", &field_to_decimal(&root)[..20]);

    let merkle_witnesses: Vec<MerkleWitness<F>> = (0..K)
        .map(|i| MerkleWitness {
            path: tree.generate_proof(i).unwrap(),
            leaf_idx: i,
        })
        .collect();
    println!("  {} merkle proofs extracted", K);

    // ============================================================
    // Step 5: Anchor Generation (using service API)
    // ============================================================
    println!("\n[Step 5] Generating threshold anchor (N={}, K={})...", N, K);

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

    let anchor = generate_anchor(&config, all_secrets.clone()).expect("Anchor generation failed");
    let hanchor = chain_hash_native(&anchor.0, &poseidon_params);
    println!("  Anchor: {} values, hanchor computed", anchor.0.len());

    // Build anchor witness (selector + a/b vectors)
    let matrix = VandermondeMatrix::<F>::new(N, K);
    let pk_anchor = PoseidonAnchorPublicKey { params: poseidon_params.clone() };

    let known_x_list: Vec<F> = all_secrets[..K]
        .iter()
        .map(|s| derive_x(s, &poseidon_params, &config))
        .collect();

    let selector = derive_selector(&pk_anchor, &known_x_list, &anchor, &matrix, &config);
    let witness = build_anchor_witness(&poseidon_params, &known_x_list, &selector, &matrix).unwrap();

    let current_idx_list: Vec<usize> = selector.iter().enumerate()
        .filter(|&(_, &s)| s == 1).map(|(i, _)| i).collect();

    // Shared public inputs
    let mut h_a_inputs = witness.a.clone();
    h_a_inputs.push(random);
    let h_a = PoseidonHash::evaluate(&poseidon_params, h_a_inputs).unwrap();

    let inner: F = witness.a.iter().zip(anchor.0.iter()).map(|(a, anc)| *a * *anc).sum();
    let lhs = inner * random;

    // ============================================================
    // Step 6: Proof Generation
    // ============================================================
    println!("\n[Step 6] Building circuit inputs and generating {} Groth16 proofs...", K);

    // Audience list (using service API)
    // Same as ISS: circuit sees quoted aud, so pass quoted form
    let quoted_aud = format!("\"{}\"", AUD);
    let (aud_fields, h_aud_list) = generate_aud_hash(&config, vec![quoted_aud])
        .expect("Audience hash failed");

    // Build K circuit inputs
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
    let mut circuit_inputs = Vec::new();

    for i in 0..K {
        let jwt_witness = build_jwt_witness(&jwts[i], &rsa_keys[i], &config);
        let current_idx = current_idx_list[i];

        // Compute h_id and partial_rhs for this proof
        let (aud_packed, iss_packed, sub_packed) = pack_claims_native(&jwts[i], &config);
        let mut h_id_inputs = Vec::new();
        h_id_inputs.extend_from_slice(&aud_packed);
        h_id_inputs.extend_from_slice(&iss_packed);
        h_id_inputs.extend_from_slice(&sub_packed);
        let h_id_inner = PoseidonHash::evaluate(&poseidon_params, h_id_inputs).unwrap();
        let h_id = PoseidonHash::evaluate(&poseidon_params, [F::from(current_idx as u64), h_id_inner]).unwrap();
        let partial_rhs = witness.b[current_idx] * h_id * random;

        let circuit_input = ZkapCircuitInput {
            params: config.clone(),
            constants: CircuitConstants {
                vandermonde_matrix: VandermondeMatrix::new(N, K),
                poseidon_param: poseidon_params.clone(),
                base64_table: get_base64_table(),
            },
            public_inputs: CircuitPublicInputs {
                hanchor,
                h_a,
                root,
                h_sign_user_op,
                jwt_exp: F::from(EXP),
                partial_rhs,
                lhs,
                h_aud_list,
            },
            jwt: jwt_witness,
            anchor: AnchorWitness {
                anchor: anchor.clone(),
                a: witness.a.clone(),
                selector: selector.clone(),
                current_idx,
            },
            merkle: merkle_witnesses[i].clone(),
            audience: AudienceWitness { aud_list: aud_fields.clone() },
            misc: MiscWitness { random },
        };

        circuit_inputs.push(circuit_input);
    }

    // Setup with the first real circuit (avoids any mock circuit divergence)
    println!("  Running Groth16 setup with real circuit...");
    let setup_circuit = ZkapCircuit::<CG, BNP>::from_input(circuit_inputs[0].clone());
    let (pk, vk) = Groth16::<BN254>::setup(setup_circuit, &mut rng).unwrap();
    let pvk = ark_groth16::prepare_verifying_key(&vk);

    // Generate proofs
    let mut proofs = Vec::new();
    let mut all_public_inputs = Vec::new();
    for (i, input) in circuit_inputs.into_iter().enumerate() {
        let pub_inputs = input.extract_public_inputs();
        let circuit = ZkapCircuit::<CG, BNP>::from_input(input);
        let proof = Groth16::<BN254>::prove(&pk, circuit, &mut rng)
            .expect("Proof generation failed");
        proofs.push(proof);
        all_public_inputs.push(pub_inputs);
        println!("  Proof {}/{} generated", i + 1, K);
    }

    // ============================================================
    // Step 7: Proof Verification (using service API)
    // ============================================================
    println!("\n[Step 7] Verifying proofs...");

    for (i, (proof, pub_input)) in proofs.iter().zip(all_public_inputs.iter()).enumerate() {
        let valid = verify(&pvk, proof, pub_input).expect("Verification call failed");
        println!("  Proof {}/{}: {}", i + 1, K, if valid { "VALID" } else { "INVALID" });
        assert!(valid, "Proof {} should be valid", i);
    }

    // Demonstrate: tampered public input fails verification
    let mut tampered = all_public_inputs[0].clone();
    tampered[0] += F::from(1u64);
    let invalid = verify(&pvk, &proofs[0], &tampered).expect("Verification call failed");
    println!("  Tampered proof: {}", if invalid { "VALID (unexpected!)" } else { "INVALID (expected)" });
    assert!(!invalid, "Tampered proof should not verify");

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
        claims: vec!["aud".into(), "exp".into(), "iss".into(), "nonce".into(), "sub".into()],
        forbidden_string: "forbidden".into(),
    };
    raw.into()
}

fn build_and_sign_jwt(
    aud: &str, exp: u64, iss: &str, nonce_hex: &str, sub: &str,
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

fn chain_hash_native(
    values: &[F],
    params: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F>,
) -> F {
    let mut h = PoseidonHash::evaluate(params, [values[0]]).unwrap();
    for v in &values[1..] {
        h = PoseidonHash::evaluate(params, [h, *v]).unwrap();
    }
    h
}

/// Parse a JWT claim from the decoded payload string (same as circuit test helper)
fn parse_claim_from_str(s: &str, key: &str) -> ClaimIndices {
    let escaped_key = regex::escape(key);
    let pattern = format!(r#"\s*("{}")\s*:\s*("?[^",]*"?)\s*([,\}}])"#, escaped_key);
    let re = Regex::new(&pattern).unwrap();
    let caps = re.captures(s).unwrap_or_else(|| panic!("Key '{}' not found", key));
    let full_match = caps.get(0).unwrap();
    let full_match_str = full_match.as_str();
    let offset = full_match.start();
    let claim_len = full_match_str.len();
    let captured_value = caps.get(2).unwrap().as_str();
    let colon_idx = full_match_str.find(':').unwrap();
    let rel_search_start = colon_idx + 1;
    let value_idx = full_match_str[rel_search_start..]
        .find(captured_value)
        .map(|i| i + rel_search_start)
        .unwrap();
    let value_len = captured_value.len();
    ClaimIndices { offset, claim_len, colon_idx, value_idx, value_len }
}

fn build_jwt_witness(jwt: &str, rsa_priv_key: &rsa::RsaPrivateKey, cfg: &CircuitConfig) -> JwtWitness {
    let parts: Vec<&str> = jwt.split('.').collect();
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);
    let full_jwt = format!("{}.{}", header_b64, payload_b64);
    let total_len = full_jwt.len();
    let pad_start_byte_idx = total_len;

    // SHA256 padding
    let mut sha_padded = full_jwt.as_bytes().to_vec();
    sha_padded.push(0x80);
    while (sha_padded.len() % 64) != 56 { sha_padded.push(0x00); }
    let bit_len = (total_len as u64) * 8;
    sha_padded.extend_from_slice(&bit_len.to_be_bytes());
    let nblocks = sha_padded.len() / 64 - 1;
    sha_padded.resize(cfg.max_jwt_b64_len as usize, 0x00);

    let pay_offset_b64 = header_b64.len() + 1;
    let pay_len_b64 = payload_b64.len();
    let index_bits = IndexBits::from_base64_url(payload_b64, cfg.max_payload_b64_len as usize).unwrap();

    // Decode payload for claim extraction
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(payload_b64).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();
    let claims: Vec<&str> = cfg.claims.iter().map(|c| std::str::from_utf8(c).unwrap()).collect();
    let claim_indices: Vec<ClaimIndices> = claims.iter()
        .map(|key| parse_claim_from_str(&payload_str, key))
        .collect();

    // RSA key
    let pub_key = rsa_priv_key.to_public_key();
    let pk = RsaCircuitPubKey {
        n: pub_key.n().to_bytes_be().to_vec(),
        e: pub_key.e().to_bytes_be().to_vec(),
    };
    let sig = RsaCircuitSig(engine.decode(sig_b64).unwrap());

    JwtWitness {
        nblocks, claim_indices, pay_offset_b64, pay_len_b64,
        sha_pad_jwt_b64: sha_padded, index_bits, pk, sig, total_len, pad_start_byte_idx,
    }
}

/// Pack claim bytes into field elements (31 bytes per chunk, big-endian)
fn pack_bytes_to_field_native(bytes: &[u8]) -> Vec<F> {
    let limb_width = 31;
    assert!(bytes.len().is_multiple_of(limb_width));
    bytes.chunks(limb_width).map(F::from_be_bytes_mod_order).collect()
}

fn claim_value_bytes(payload_str: &str, key: &str, max_len: usize) -> Vec<u8> {
    let escaped_key = regex::escape(key);
    let pattern = format!(r#"\s*("{}")\s*:\s*("?[^",]*"?)\s*([,\}}])"#, escaped_key);
    let re = Regex::new(&pattern).unwrap();
    let caps = re.captures(payload_str).unwrap();
    let value = caps.get(2).unwrap().as_str();
    let mut bytes = value.as_bytes().to_vec();
    bytes.resize(max_len, 0x00);
    bytes
}

fn pack_claims_native(jwt: &str, cfg: &CircuitConfig) -> (Vec<F>, Vec<F>, Vec<F>) {
    let parts: Vec<&str> = jwt.split('.').collect();
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(parts[1]).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();
    let aud = pack_bytes_to_field_native(&claim_value_bytes(&payload_str, "aud", cfg.max_aud_len as usize));
    let iss = pack_bytes_to_field_native(&claim_value_bytes(&payload_str, "iss", cfg.max_iss_len as usize));
    let sub = pack_bytes_to_field_native(&claim_value_bytes(&payload_str, "sub", cfg.max_sub_len as usize));
    (aud, iss, sub)
}

fn derive_x(secret: &Secret, params: &ark_crypto_primitives::sponge::poseidon::PoseidonConfig<F>, cfg: &CircuitConfig) -> F {
    let padded_aud = pad(&secret.aud, cfg.max_aud_len as usize, PAD_CHAR).unwrap();
    let padded_iss = pad(&secret.iss, cfg.max_iss_len as usize, PAD_CHAR).unwrap();
    let padded_sub = pad(&secret.sub, cfg.max_sub_len as usize, PAD_CHAR).unwrap();
    let input = format!("{}{}{}", padded_aud, padded_iss, padded_sub);
    let limbs = try_str_to_fields::<F>(&input).unwrap();
    PoseidonHash::evaluate(params, limbs).unwrap()
}

fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut combo = vec![0usize; k];
    fn helper(start: usize, depth: usize, n: usize, k: usize, combo: &mut Vec<usize>, result: &mut Vec<Vec<usize>>) {
        if depth == k { result.push(combo.clone()); return; }
        for i in start..=(n - k + depth) {
            combo[depth] = i;
            helper(i + 1, depth + 1, n, k, combo, result);
        }
    }
    helper(0, 0, n, k, &mut combo, &mut result);
    result
}

fn derive_selector(
    pk: &PoseidonAnchorPublicKey<F>, known_x_list: &[F],
    anchor: &gadget::anchor::poseidon::PoseidonAnchor<F>,
    matrix: &VandermondeMatrix<F>, cfg: &CircuitConfig,
) -> Vec<u8> {
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    for combo in combinations(n, k) {
        let mut selector = vec![0u8; n];
        for &idx in &combo { selector[idx] = 1; }
        if let Ok(w) = build_anchor_witness(&pk.params, known_x_list, &selector, matrix) {
            let lhs: F = w.a.iter().zip(anchor.0.iter()).map(|(a, anc)| *a * *anc).sum();
            let rhs: F = w.b.iter().zip(w.h_known.iter()).map(|(b, h)| *b * *h).sum();
            if lhs == rhs { return selector; }
        }
    }
    panic!("No valid selector found");
}
