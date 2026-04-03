//! Groth16 integration tests for BaeraeLightWeightCircuit
//! Run: cargo test -p circuit --test groth16_integration --features baerae

use ark_bn254::Bn254;
use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::MerkleTree,
    snark::{CircuitSpecificSetupSNARK, SNARK},
    sponge::poseidon::PoseidonConfig,
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::SeedableRng;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

use regex::Regex;
use ark_utils::field_serde::ascii_to_field_be;
use ark_utils::text::pad;
use circuit::{
    baerae::{BaeraeLightWeightCircuit, input::*},
    constants::{BNP, CG, ZkapConfig, ZkPasskeyConfig},
    token::ClaimIndices,
};
use gadget::{
    anchor::poseidon::{
        PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
        build_anchor_witness,
    },
    anchor::AnchorScheme,
    base64::{get_base64_table, IndexBits},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
    merkletree::tree_config::MerkleTreeParams,
    signature::rsa::{PublicKey as RsaCircuitPubKey, Signature as RsaCircuitSig},
};

/// Test-local copy of parse_claim_from_str (moved to service crate)
fn parse_claim_from_str(s: &str, key: &str) -> circuit::token::Claim {
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
    let value_str = captured_value.to_string();
    let rel_search_start = colon_idx + 1;
    let value_idx = full_match_str[rel_search_start..]
        .find(captured_value)
        .map(|i| i + rel_search_start)
        .unwrap();
    let value_len = captured_value.len();

    circuit::token::Claim {
        key: key.to_string(),
        value: value_str,
        indices: ClaimIndices {
            offset,
            claim_len,
            colon_idx,
            value_idx,
            value_len,
        },
    }
}

type F = <CG as CurveGroup>::BaseField;
type TestCircuit = BaeraeLightWeightCircuit<CG, BNP, ZkapConfig>;

// ============================================================
// Test Secrets
// ============================================================

struct TestSecret {
    aud: &'static str,
    iss: &'static str,
    sub: &'static str,
    exp: u64,
}

const TEST_SECRETS: [TestSecret; 3] = [
    TestSecret { aud: "test-audience", iss: "https://accounts.google.com", sub: "user_0", exp: 1700000000 },
    TestSecret { aud: "test-audience", iss: "https://accounts.google.com", sub: "user_1", exp: 1700000000 },
    TestSecret { aud: "test-audience", iss: "https://accounts.google.com", sub: "user_2", exp: 1700000000 },
];

// ============================================================
// Helper Functions
// ============================================================

/// Compute nonce = Poseidon(h_sign_user_op, random) and return "0x" + hex(nonce)
fn build_nonce_hex(h_sign_user_op: F, random: F, params: &PoseidonConfig<F>) -> String {
    let nonce = CRH::<F>::evaluate(params, [h_sign_user_op, random]).unwrap();
    format!("0x{}", hex::encode(nonce.into_bigint().to_bytes_be()))
}

/// Build a JWT with given claims and sign it with a generated RSA-2048 key.
fn build_jwt_and_sign(
    aud: &str,
    exp: u64,
    iss: &str,
    nonce_hex: &str,
    sub: &str,
    rsa_seed: u64,
) -> (String, rsa::RsaPrivateKey) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(rsa_seed);
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();

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
    let sig_b64 = engine.encode(&signature.to_bytes());

    let jwt = format!("{}.{}", signing_input, sig_b64);
    (jwt, priv_key)
}

/// Parse a JWT string into JwtWitness
fn build_jwt_witness(jwt: &str, rsa_priv_key: &rsa::RsaPrivateKey) -> JwtWitness {
    let parts: Vec<&str> = jwt.split('.').collect();
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let full_jwt = format!("{}.{}", header_b64, payload_b64);
    let total_len = full_jwt.len();
    let pad_start_byte_idx = total_len;

    // SHA256 padding
    let mut sha_padded = full_jwt.as_bytes().to_vec();
    sha_padded.push(0x80);
    while (sha_padded.len() % 64) != 56 {
        sha_padded.push(0x00);
    }
    let bit_len = (total_len as u64) * 8;
    sha_padded.extend_from_slice(&bit_len.to_be_bytes());

    let nblocks = sha_padded.len() / 64 - 1;
    sha_padded.resize(ZkapConfig::MAX_JWT_B64_LEN, 0x00);

    let pay_offset_b64 = header_b64.len() + 1;
    let pay_len_b64 = payload_b64.len();

    // IndexBits
    let index_bits =
        IndexBits::from_base64_url(payload_b64, ZkapConfig::MAX_PAYLOAD_B64_LEN).unwrap();

    // Decode payload for claim extraction
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(payload_b64).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();

    // ClaimIndices for each claim
    let claim_indices: Vec<ClaimIndices> = ZkapConfig::CLAIMS
        .iter()
        .map(|key| {
            let claim = parse_claim_from_str(&payload_str, key).unwrap();
            claim.indices
        })
        .collect();

    // RSA PublicKey
    let pub_key = rsa_priv_key.to_public_key();
    let n_bytes = pub_key.n().to_bytes_be();
    let e_bytes = pub_key.e().to_bytes_be();
    let pk = RsaCircuitPubKey {
        n: n_bytes.to_vec(),
        e: e_bytes.to_vec(),
    };

    // Signature
    let sig_bytes = engine.decode(sig_b64).unwrap();
    let sig = RsaCircuitSig(sig_bytes);

    JwtWitness {
        nblocks,
        claim_indices,
        pay_offset_b64,
        pay_len_b64,
        sha_pad_jwt_b64: sha_padded,
        index_bits,
        pk,
        sig,
        total_len,
        pad_start_byte_idx,
    }
}

/// Pack bytes into field elements (31 bytes per chunk, big-endian) - same as circuit's
/// pack_decompose_bytes_unchecked
fn pack_bytes_to_field_native(bytes: &[u8]) -> Vec<F> {
    let limb_width = 31; // (254 - 1) / 8 = 31 for BN254
    assert!(bytes.len() % limb_width == 0);
    bytes
        .chunks(limb_width)
        .map(|chunk| F::from_be_bytes_mod_order(chunk))
        .collect()
}

/// Get the claim value bytes as the circuit would see them (with quotes for strings,
/// zero-padded to max_len)
fn claim_value_bytes(payload_str: &str, key: &str, max_len: usize) -> Vec<u8> {
    let claim = parse_claim_from_str(payload_str, key).unwrap();
    let value_str = &claim.value;
    let mut bytes = value_str.as_bytes().to_vec();
    bytes.resize(max_len, 0x00);
    bytes
}

/// Compute x = Poseidon(pad(aud) || pad(iss) || pad(sub)) as field limbs
/// This uses the same null-padded representation for the anchor secret derivation
fn derive_x(aud: &str, iss: &str, sub: &str, params: &PoseidonConfig<F>) -> F {
    let padded_aud = pad(aud, ZkapConfig::MAX_AUD_LEN, ZkapConfig::PAD_CHAR).unwrap();
    let padded_iss = pad(iss, ZkapConfig::MAX_ISS_LEN, ZkapConfig::PAD_CHAR).unwrap();
    let padded_sub = pad(sub, ZkapConfig::MAX_SUB_LEN, ZkapConfig::PAD_CHAR).unwrap();

    let input = format!("{}{}{}", padded_aud, padded_iss, padded_sub);
    let limbs = ascii_to_field_be::<F>(&input).unwrap();
    CRH::<F>::evaluate(params, limbs).unwrap()
}

/// Generate all k-element index subsets of 0..n
fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut combo = vec![0usize; k];
    fn helper(
        start: usize,
        depth: usize,
        n: usize,
        k: usize,
        combo: &mut Vec<usize>,
        result: &mut Vec<Vec<usize>>,
    ) {
        if depth == k {
            result.push(combo.clone());
            return;
        }
        for i in start..=(n - k + depth) {
            combo[depth] = i;
            helper(i + 1, depth + 1, n, k, combo, result);
        }
    }
    helper(0, 0, n, k, &mut combo, &mut result);
    result
}

/// Brute-force find a valid selector for the anchor
fn derive_selector(
    pk: &PoseidonAnchorPublicKey<F>,
    known_x_list: &[F],
    anchor: &PoseidonAnchor<F>,
    matrix: &VandermondeMatrix<F>,
) -> Vec<u8> {
    let n = ZkapConfig::N;
    let k = ZkapConfig::K;

    for combo in combinations(n, k) {
        let mut selector = vec![0u8; n];
        for &idx in &combo {
            selector[idx] = 1;
        }

        if let Ok(witness) = build_anchor_witness(&pk.params, known_x_list, &selector, matrix) {
            // Verify: inner_product(a, anchor) == inner_product(b, h_known)
            let lhs: F = witness
                .a
                .iter()
                .zip(anchor.0.iter())
                .map(|(a, anc)| *a * *anc)
                .sum();
            let rhs: F = witness
                .b
                .iter()
                .zip(witness.h_known.iter())
                .map(|(b, h)| *b * *h)
                .sum();
            if lhs == rhs {
                return selector;
            }
        }
    }
    panic!("No valid selector found");
}

/// Chain hash: H(v[0]), then H(h, v[1]), H(h, v[2]), ...
fn chain_hash_native(values: &[F], params: &PoseidonConfig<F>) -> F {
    let mut h = CRH::<F>::evaluate(params, [values[0]]).unwrap();
    for v in &values[1..] {
        h = CRH::<F>::evaluate(params, [h, *v]).unwrap();
    }
    h
}

// ============================================================
// Anchor Context (shared across K proofs)
// ============================================================

struct AnchorTestContext {
    anchor: PoseidonAnchor<F>,
    a: Vec<F>,
    b: Vec<F>,
    h_known: Vec<F>,
    selector: Vec<u8>,
    hanchor: F,
    current_idx_list: Vec<usize>,
}

/// Build anchor context for K real secrets + (N-K) dummy secrets
fn build_anchor_context(
    secrets: &[TestSecret],
    params: &PoseidonConfig<F>,
) -> AnchorTestContext {
    let matrix = VandermondeMatrix::<F>::new(ZkapConfig::N, ZkapConfig::K);
    let pk = PoseidonAnchorPublicKey {
        params: params.clone(),
    };

    // K real secrets
    let mut full_x_list = Vec::new();
    for s in secrets {
        full_x_list.push(derive_x(s.aud, s.iss, s.sub, params));
    }

    // N-K dummy secrets
    for i in 0..(ZkapConfig::N - ZkapConfig::K) {
        let dummy_aud = format!("dummy_aud_{}", i);
        let dummy_iss = format!("dummy_iss_{}", i);
        let dummy_sub = format!("dummy_sub_{}", i);
        full_x_list.push(derive_x(&dummy_aud, &dummy_iss, &dummy_sub, params));
    }

    // Generate anchor (N secrets)
    let anchor = PoseidonAnchorScheme::<F>::generate_anchor(
        &pk,
        &PoseidonAnchorSecret(full_x_list.clone()),
        &matrix,
    )
    .unwrap();

    // Derive selector (K known secrets)
    let known_x_list: Vec<F> = full_x_list[..ZkapConfig::K].to_vec();
    let selector = derive_selector(&pk, &known_x_list, &anchor, &matrix);

    // Build witness
    let witness = build_anchor_witness(params, &known_x_list, &selector, &matrix).unwrap();

    // hanchor
    let hanchor = chain_hash_native(&anchor.0, params);

    // current_idx_list: positions where selector == 1
    let current_idx_list: Vec<usize> = selector
        .iter()
        .enumerate()
        .filter(|&(_, &s)| s == 1)
        .map(|(i, _)| i)
        .collect();

    AnchorTestContext {
        anchor,
        a: witness.a.clone(),
        b: witness.b.clone(),
        h_known: witness.h_known.clone(),
        selector,
        hanchor,
        current_idx_list,
    }
}

/// Build Merkle tree witness with K leaves
fn build_merkle_witness_multi(
    leaves_data: &[(Vec<F>, Vec<F>)],
    params: &PoseidonConfig<F>,
) -> (Vec<MerkleWitness<F>>, F) {
    let num_leaves = 1 << ZkapConfig::TREE_HEIGHT;

    // Compute leaf digests
    let mut digests = vec![F::zero(); num_leaves];
    for (i, (iss_limbs, pk_n_limbs)) in leaves_data.iter().enumerate() {
        let mut leaf_inputs = iss_limbs.to_vec();
        leaf_inputs.extend_from_slice(pk_n_limbs);
        let leaf = CRH::<F>::evaluate(params, leaf_inputs).unwrap();
        let leaf_digest = CRH::<F>::evaluate(params, [leaf]).unwrap();
        digests[i] = leaf_digest;
    }

    let tree =
        MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(params, params, digests).unwrap();
    let root = tree.root();

    let witnesses: Vec<MerkleWitness<F>> = (0..leaves_data.len())
        .map(|i| {
            let path = tree.generate_proof(i).unwrap();
            MerkleWitness { path, leaf_idx: i }
        })
        .collect();

    (witnesses, root)
}

/// Build audience list and its hash using packed claim bytes (matching circuit)
fn build_audience_list(aud_packed: &[F], params: &PoseidonConfig<F>) -> (Vec<F>, F) {
    let h_aud = CRH::<F>::evaluate(params, aud_packed.to_vec()).unwrap();

    // Forbidden value: pad "forbidden" with quotes to match circuit format
    let mut forbidden_bytes = format!("\"{}\"", ZkapConfig::FORBIDDEN_STRING).into_bytes();
    forbidden_bytes.resize(ZkapConfig::MAX_AUD_LEN, 0x00);
    let forbidden_packed = pack_bytes_to_field_native(&forbidden_bytes);
    let h_forbidden = CRH::<F>::evaluate(params, forbidden_packed).unwrap();

    let mut aud_list = vec![h_aud];
    while aud_list.len() < ZkapConfig::NUM_AUDIENCE_LIMIT {
        aud_list.push(h_forbidden);
    }

    let h_aud_list = CRH::<F>::evaluate(params, aud_list.clone()).unwrap();

    (aud_list, h_aud_list)
}

/// Extract RSA public key N limbs from a private key (matching circuit allocation)
fn rsa_pk_n_limbs(rsa_priv_key: &rsa::RsaPrivateKey) -> Vec<F> {
    let pub_key = rsa_priv_key.to_public_key();
    let n_bytes = pub_key.n().to_bytes_be();
    let limb_byte_width = 8; // LIMB_WIDTH=64, 64/8 = 8 bytes per limb
    let mut n_le = n_bytes.to_vec();
    n_le.reverse(); // BE -> LE (same as circuit)
    n_le.resize(limb_byte_width * 32, 0);
    n_le.chunks(limb_byte_width)
        .map(|chunk| F::from_le_bytes_mod_order(chunk))
        .collect()
}

/// Main orchestrator: build K complete valid circuit inputs (one per secret/JWT)
fn build_valid_circuit_inputs() -> Vec<BaeraeCircuitInput<F>> {
    let params = get_poseidon_params::<F>();
    let random = F::from(12345u64);
    let h_sign_user_op = F::from(67890u64);
    let nonce_hex = build_nonce_hex(h_sign_user_op, random, &params);

    let secrets = &TEST_SECRETS;

    // Build K JWTs (each with different RSA key)
    let jwt_data: Vec<(String, rsa::RsaPrivateKey)> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| {
            build_jwt_and_sign(s.aud, s.exp, s.iss, &nonce_hex, s.sub, 99 + i as u64)
        })
        .collect();

    // Build anchor context (shared across all K proofs)
    let anchor_ctx = build_anchor_context(secrets, &params);

    // h_a = Poseidon(a..., random)
    let mut h_a_inputs = anchor_ctx.a.clone();
    h_a_inputs.push(random);
    let h_a = CRH::<F>::evaluate(&params, h_a_inputs).unwrap();

    // lhs = inner_product(a, anchor) * random
    let inner: F = anchor_ctx
        .a
        .iter()
        .zip(anchor_ctx.anchor.0.iter())
        .map(|(a, anc)| *a * *anc)
        .sum();
    let lhs = inner * random;

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Build Merkle tree with K leaves
    let leaves_data: Vec<(Vec<F>, Vec<F>)> = jwt_data
        .iter()
        .map(|(jwt, rsa_key)| {
            let jwt_parts: Vec<&str> = jwt.split('.').collect();
            let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
            let payload_str = String::from_utf8(payload_bytes).unwrap();
            let iss_bytes = claim_value_bytes(&payload_str, "iss", ZkapConfig::MAX_ISS_LEN);
            let iss_packed = pack_bytes_to_field_native(&iss_bytes);
            let pk_n_limbs = rsa_pk_n_limbs(rsa_key);
            (iss_packed, pk_n_limbs)
        })
        .collect();

    let (merkle_witnesses, root) = build_merkle_witness_multi(&leaves_data, &params);

    // Audience (shared — all secrets use the same aud)
    let first_jwt = &jwt_data[0].0;
    let jwt_parts: Vec<&str> = first_jwt.split('.').collect();
    let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();
    let aud_bytes = claim_value_bytes(&payload_str, "aud", ZkapConfig::MAX_AUD_LEN);
    let aud_packed = pack_bytes_to_field_native(&aud_bytes);
    let (aud_list, h_aud_list) = build_audience_list(&aud_packed, &params);

    // Build K circuit inputs
    (0..ZkapConfig::K)
        .map(|i| {
            let s = &secrets[i];
            let (jwt, rsa_key) = &jwt_data[i];
            let jwt_witness = build_jwt_witness(jwt, rsa_key);
            let current_idx = anchor_ctx.current_idx_list[i];

            // Compute h_id for this proof
            let jwt_parts: Vec<&str> = jwt.split('.').collect();
            let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
            let payload_str = String::from_utf8(payload_bytes).unwrap();
            let aud_bytes_i = claim_value_bytes(&payload_str, "aud", ZkapConfig::MAX_AUD_LEN);
            let iss_bytes_i = claim_value_bytes(&payload_str, "iss", ZkapConfig::MAX_ISS_LEN);
            let sub_bytes_i = claim_value_bytes(&payload_str, "sub", ZkapConfig::MAX_SUB_LEN);
            let aud_packed_i = pack_bytes_to_field_native(&aud_bytes_i);
            let iss_packed_i = pack_bytes_to_field_native(&iss_bytes_i);
            let sub_packed_i = pack_bytes_to_field_native(&sub_bytes_i);

            let mut h_id_inputs = Vec::new();
            h_id_inputs.extend_from_slice(&aud_packed_i);
            h_id_inputs.extend_from_slice(&iss_packed_i);
            h_id_inputs.extend_from_slice(&sub_packed_i);
            let h_id_inner = CRH::<F>::evaluate(&params, h_id_inputs).unwrap();
            let h_id = CRH::<F>::evaluate(
                &params,
                [F::from(current_idx as u64), h_id_inner],
            )
            .unwrap();

            // partial_rhs = b[current_idx] * h_id * random
            let partial_rhs = anchor_ctx.b[current_idx] * h_id * random;

            let jwt_exp = F::from(s.exp);

            BaeraeCircuitInput {
                constants: CircuitConstants {
                    vandermonde_matrix: VandermondeMatrix::new(ZkapConfig::N, ZkapConfig::K),
                    poseidon_param: params.clone(),
                    base64_table: get_base64_table(),
                },
                public_inputs: CircuitPublicInputs {
                    hanchor: anchor_ctx.hanchor,
                    h_a,
                    root,
                    h_sign_user_op,
                    jwt_exp,
                    partial_rhs,
                    lhs,
                    h_aud_list,
                },
                jwt: jwt_witness,
                anchor: AnchorWitness {
                    anchor: anchor_ctx.anchor.clone(),
                    a: anchor_ctx.a.clone(),
                    selector: anchor_ctx.selector.clone(),
                    current_idx,
                },
                merkle: merkle_witnesses[i].clone(),
                audience: AudienceWitness {
                    aud_list: aud_list.clone(),
                },
                misc: MiscWitness { random },
            }
        })
        .collect()
}

// ============================================================
// Tests
// ============================================================

#[test]
fn groth16_setup_with_mock() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
    let circuit = TestCircuit::generate_mock_circuit();
    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng).unwrap();
    assert!(!pk.vk.gamma_abc_g1.is_empty());
    println!(
        "Setup successful, VK has {} elements",
        vk.gamma_abc_g1.len()
    );
}

#[test]
fn debug_constraint_satisfaction() {
    let inputs = build_valid_circuit_inputs();
    for (i, input) in inputs.into_iter().enumerate() {
        let circuit = TestCircuit::from_input(input);
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        if !cs.is_satisfied().unwrap() {
            println!("Circuit {} constraint system is NOT satisfied!", i);
            println!("Num constraints: {}", cs.num_constraints());
            if let Some(unsatisfied) = cs.which_is_unsatisfied().unwrap() {
                println!("Unsatisfied constraint: {}", unsatisfied);
            }
            panic!("Circuit {} constraints not satisfied", i);
        } else {
            println!(
                "Circuit {}: all {} constraints satisfied!",
                i,
                cs.num_constraints()
            );
        }
    }
}

#[test]
fn groth16_prove_verify_k_proofs() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

    // Setup (use first valid input — all have the same constraint structure)
    let inputs = build_valid_circuit_inputs();
    let k = inputs.len();

    let setup_circuit = TestCircuit::from_input(inputs[0].clone());
    let (pk, vk) = Groth16::<Bn254>::setup(setup_circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&vk);

    // Prove and verify K times (fresh inputs since setup consumed the first batch)
    let inputs = build_valid_circuit_inputs();
    for (i, input) in inputs.into_iter().enumerate() {
        let pub_inputs = input.public_inputs.to_vec();
        let circuit = TestCircuit::from_input(input);

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &pub_inputs).unwrap();
        assert!(valid, "Proof {} should verify", i);
        println!("Proof {}/{} verified successfully", i + 1, k);
    }
}

#[test]
fn groth16_verify_fails_with_wrong_public_inputs() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);

    // Setup with valid circuit
    let inputs = build_valid_circuit_inputs();
    let setup_circuit = TestCircuit::from_input(inputs[0].clone());
    let (pk, vk) = Groth16::<Bn254>::setup(setup_circuit, &mut rng).unwrap();
    let pvk = prepare_verifying_key(&vk);

    let inputs = build_valid_circuit_inputs();
    let input = inputs.into_iter().next().unwrap();
    let mut pub_inputs = input.public_inputs.to_vec();
    let circuit = TestCircuit::from_input(input);

    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Tamper with first public input
    pub_inputs[0] += F::one();
    let valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &pub_inputs).unwrap();
    assert!(
        !valid,
        "Proof should NOT verify with tampered public inputs"
    );
}
