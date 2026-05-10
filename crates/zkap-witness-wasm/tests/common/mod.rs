//! Test fixtures for the wasm-host integration test.
//!
//! Helpers (no `#[test]` blocks) copied from
//! `crates/circuit/tests/groth16_integration.rs` plus the V1 fixture
//! bundle ([`build_v1_fixture_bundle`]) used by `tests/wasm_to_prove.rs`
//! and `tests/v1_round_trip.rs` to drive the V1 `witness_generator`
//! pipeline.
//!
//! Do NOT refactor — keep this in lock-step with the source helpers so
//! the byte-identical native/wasm comparison stays valid.

#![allow(dead_code)]

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::MerkleTree,
    sponge::poseidon::PoseidonConfig,
};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_std::rand::SeedableRng;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

use ark_utils::pad;
use ark_utils::try_str_to_fields;
use circuit::{
    constants::{BNP, CG, CircuitConfig, PAD_CHAR},
    input::*,
    token::ClaimIndices,
    zkap::ZkapCircuit,
};
use gadget::{
    anchor::AnchorScheme,
    anchor::poseidon::{
        PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
        build_anchor_witness,
    },
    base64::{IndexBits, get_base64_table},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
    merkletree::tree_config::MerkleTreeParams,
    signature::rsa::{PublicKey as RsaCircuitPubKey, Signature as RsaCircuitSig},
};
use regex::Regex;

/// Test-local copy of parse_claim_from_str (moved to service crate)
pub fn parse_claim_from_str(s: &str, key: &str) -> circuit::token::Claim {
    let escaped_key = regex::escape(key);
    let pattern = format!(r#"\s*("{}")\s*:\s*("?[^",]*"?)\s*([,\}}])"#, escaped_key);
    let re = Regex::new(&pattern).unwrap();
    let caps = re
        .captures(s)
        .unwrap_or_else(|| panic!("Key '{}' not found", key));
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

pub type F = <CG as CurveGroup>::BaseField;
pub type TestCircuit = ZkapCircuit<CG, BNP>;

/// Build a test CircuitConfig (dev profile)
pub fn test_params() -> CircuitConfig {
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

// ============================================================
// Test Secrets
// ============================================================

pub struct TestSecret {
    pub aud: &'static str,
    pub iss: &'static str,
    pub sub: &'static str,
    pub exp: u64,
}

pub const TEST_SECRETS: [TestSecret; 3] = [
    TestSecret {
        aud: "test-audience",
        iss: "https://accounts.google.com",
        sub: "user_0",
        exp: 1700000000,
    },
    TestSecret {
        aud: "test-audience",
        iss: "https://accounts.google.com",
        sub: "user_1",
        exp: 1700000000,
    },
    TestSecret {
        aud: "test-audience",
        iss: "https://accounts.google.com",
        sub: "user_2",
        exp: 1700000000,
    },
];

// ============================================================
// Helper Functions
// ============================================================

/// Compute nonce = Poseidon(h_sign_user_op, random) and return "0x" + hex(nonce)
pub fn build_nonce_hex(h_sign_user_op: F, random: F, params: &PoseidonConfig<F>) -> String {
    let nonce = CRH::<F>::evaluate(params, [h_sign_user_op, random]).unwrap();
    format!("0x{}", hex::encode(nonce.into_bigint().to_bytes_be()))
}

/// Build a JWT with given claims and sign it with a generated RSA-2048 key.
pub fn build_jwt_and_sign(
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
    let sig_b64 = engine.encode(signature.to_bytes());

    let jwt = format!("{}.{}", signing_input, sig_b64);
    (jwt, priv_key)
}

/// Parse a JWT string into JwtWitness
pub fn build_jwt_witness(
    jwt: &str,
    rsa_priv_key: &rsa::RsaPrivateKey,
    cfg: &CircuitConfig,
) -> JwtWitness {
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
    sha_padded.resize(cfg.max_jwt_b64_len as usize, 0x00);

    let pay_offset_b64 = header_b64.len() + 1;
    let pay_len_b64 = payload_b64.len();

    // IndexBits
    let index_bits =
        IndexBits::from_base64_url(payload_b64, cfg.max_payload_b64_len as usize).unwrap();

    // Decode payload for claim extraction
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload_bytes = engine.decode(payload_b64).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();

    // ClaimIndices for each claim
    let claims: Vec<&str> = cfg.claims.iter().map(|c| c.as_str()).collect();
    let claim_indices: Vec<ClaimIndices> = claims
        .iter()
        .map(|key| {
            let claim = parse_claim_from_str(&payload_str, key);
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
/// pack_decompose_bytes_unchecked.
///
/// Delegates to `zkap_witness_wasm::input::pack_bytes_to_field_native` to keep
/// test fixtures in lock-step with the production conversion path.
pub fn pack_bytes_to_field_native(bytes: &[u8]) -> Vec<F> {
    zkap_witness_wasm::input::pack_bytes_to_field_native(bytes)
}

/// Get the claim value bytes as the circuit would see them (with quotes for strings,
/// zero-padded to max_len)
pub fn claim_value_bytes(payload_str: &str, key: &str, max_len: usize) -> Vec<u8> {
    let claim = parse_claim_from_str(payload_str, key);
    let value_str = &claim.value;
    let mut bytes = value_str.as_bytes().to_vec();
    bytes.resize(max_len, 0x00);
    bytes
}

/// Compute x = Poseidon(pad(aud) || pad(iss) || pad(sub)) as field limbs
/// This uses the same null-padded representation for the anchor secret derivation
pub fn derive_x(
    aud: &str,
    iss: &str,
    sub: &str,
    params: &PoseidonConfig<F>,
    cfg: &CircuitConfig,
) -> F {
    let padded_aud = pad(aud, cfg.max_aud_len as usize, PAD_CHAR).unwrap();
    let padded_iss = pad(iss, cfg.max_iss_len as usize, PAD_CHAR).unwrap();
    let padded_sub = pad(sub, cfg.max_sub_len as usize, PAD_CHAR).unwrap();

    let input = format!("{}{}{}", padded_aud, padded_iss, padded_sub);
    let limbs = try_str_to_fields::<F>(&input).unwrap();
    CRH::<F>::evaluate(params, limbs).unwrap()
}

/// Generate all k-element index subsets of 0..n
pub fn combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
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
pub fn derive_selector(
    pk: &PoseidonAnchorPublicKey<F>,
    known_x_list: &[F],
    anchor: &PoseidonAnchor<F>,
    matrix: &VandermondeMatrix<F>,
    cfg: &CircuitConfig,
) -> Vec<u8> {
    let n = cfg.n as usize;
    let k = cfg.k as usize;

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
///
/// Delegates to `zkap_witness_wasm::input::chain_hash_native` to keep
/// test fixtures in lock-step with the production conversion path.
pub fn chain_hash_native(values: &[F], params: &PoseidonConfig<F>) -> F {
    zkap_witness_wasm::input::chain_hash_native(values, params)
        .expect("chain_hash_native in test fixture must not fail on non-empty input")
}

// ============================================================
// Anchor Context (shared across K proofs)
// ============================================================

pub struct AnchorTestContext {
    pub anchor: PoseidonAnchor<F>,
    pub a: Vec<F>,
    pub b: Vec<F>,
    pub h_known: Vec<F>,
    pub selector: Vec<u8>,
    pub hanchor: F,
    pub current_idx_list: Vec<usize>,
}

/// Build anchor context for K real secrets + (N-K) dummy secrets
pub fn build_anchor_context(
    secrets: &[TestSecret],
    params: &PoseidonConfig<F>,
    cfg: &CircuitConfig,
) -> AnchorTestContext {
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let matrix = VandermondeMatrix::<F>::new(n, k);
    let pk = PoseidonAnchorPublicKey {
        params: params.clone(),
    };

    // K real secrets
    let mut full_x_list = Vec::new();
    for s in secrets {
        full_x_list.push(derive_x(s.aud, s.iss, s.sub, params, cfg));
    }

    // N-K dummy secrets
    for i in 0..(n - k) {
        let dummy_aud = format!("dummy_aud_{}", i);
        let dummy_iss = format!("dummy_iss_{}", i);
        let dummy_sub = format!("dummy_sub_{}", i);
        full_x_list.push(derive_x(&dummy_aud, &dummy_iss, &dummy_sub, params, cfg));
    }

    // Generate anchor (N secrets)
    let anchor = PoseidonAnchorScheme::<F>::generate_anchor(
        &pk,
        &PoseidonAnchorSecret(full_x_list.clone()),
        &matrix,
    )
    .unwrap();

    // Derive selector (K known secrets)
    let known_x_list: Vec<F> = full_x_list[..k].to_vec();
    let selector = derive_selector(&pk, &known_x_list, &anchor, &matrix, cfg);

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
pub fn build_merkle_witness_multi(
    leaves_data: &[(Vec<F>, Vec<F>)],
    params: &PoseidonConfig<F>,
    cfg: &CircuitConfig,
) -> (Vec<MerkleWitness<F>>, F) {
    let num_leaves = 1 << cfg.tree_height;

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
pub fn build_audience_list(
    aud_packed: &[F],
    params: &PoseidonConfig<F>,
    cfg: &CircuitConfig,
) -> (Vec<F>, F) {
    let h_aud = CRH::<F>::evaluate(params, aud_packed.to_vec()).unwrap();

    // Forbidden value: pad "forbidden" with quotes to match circuit format
    let forbidden_str = cfg.forbidden_string.as_str();
    let mut forbidden_bytes = format!("\"{}\"", forbidden_str).into_bytes();
    forbidden_bytes.resize(cfg.max_aud_len as usize, 0x00);
    let forbidden_packed = pack_bytes_to_field_native(&forbidden_bytes);
    let h_forbidden = CRH::<F>::evaluate(params, forbidden_packed).unwrap();

    let mut aud_list = vec![h_aud];
    while aud_list.len() < cfg.num_audience_limit as usize {
        aud_list.push(h_forbidden);
    }

    let h_aud_list = CRH::<F>::evaluate(params, aud_list.clone()).unwrap();

    (aud_list, h_aud_list)
}

/// Extract RSA public key N limbs from a private key (matching circuit allocation)
pub fn rsa_pk_n_limbs(rsa_priv_key: &rsa::RsaPrivateKey) -> Vec<F> {
    let pub_key = rsa_priv_key.to_public_key();
    let n_bytes = pub_key.n().to_bytes_be();
    let limb_byte_width = 8; // LIMB_WIDTH=64, 64/8 = 8 bytes per limb
    let mut n_le = n_bytes.to_vec();
    n_le.reverse(); // BE -> LE (same as circuit)
    n_le.resize(limb_byte_width * 32, 0);
    n_le.chunks(limb_byte_width)
        .map(F::from_le_bytes_mod_order)
        .collect()
}

/// V1 fixture bundle: the K satisfying `ZkapCircuitInput`s plus the K matching
/// `ZkapInputV1` wire payloads built from the same source data (JWT bytes,
/// RSA modulus BE, anchor scalars, Merkle path BE bytes, config).
///
/// PR2 commit 1 / 3 use this to exercise the V1 → ZkapCircuit conversion
/// against the known-satisfying baseline.
pub struct V1FixtureBundle {
    pub circuit_inputs: Vec<ZkapCircuitInput<F>>,
    pub v1_inputs: Vec<zkap_witness_wasm::ZkapInputV1>,
}

/// Helper: pack a field element into 32 BE bytes.
pub fn fe_to_be32_bytes(value: &F) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32 - bytes.len();
    out[start..].copy_from_slice(&bytes);
    out
}

/// Build (i) the K legacy `ZkapCircuitInput<F>` outputs and (ii) the K
/// matching `ZkapInputV1` wire payloads from the same JWT / RSA / anchor /
/// Merkle source data. The V1 payloads MUST round-trip through
/// `ZkapInputV1::into_circuit_input()` to a `ZkapCircuit` whose constraint
/// system is satisfied.
pub fn build_v1_fixture_bundle() -> V1FixtureBundle {
    let cfg = test_params();
    let cfg_v1 = cfg.clone();
    let params = get_poseidon_params::<F>();
    let random = F::from(12345u64);
    let h_sign_user_op = F::from(67890u64);
    let nonce_hex = build_nonce_hex(h_sign_user_op, random, &params);

    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let secrets = &TEST_SECRETS;

    let jwt_data: Vec<(String, rsa::RsaPrivateKey)> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| build_jwt_and_sign(s.aud, s.exp, s.iss, &nonce_hex, s.sub, 99 + i as u64))
        .collect();

    let anchor_ctx = build_anchor_context(secrets, &params, &cfg);

    // known_x_list: K real secret hashes in selector-position order. We
    // re-derive them here (rather than threading them out of
    // build_anchor_context) to keep that helper unchanged.
    let known_x_list: Vec<F> = secrets[..k]
        .iter()
        .map(|s| derive_x(s.aud, s.iss, s.sub, &params, &cfg))
        .collect();

    let mut h_a_inputs = anchor_ctx.a.clone();
    h_a_inputs.push(random);
    let h_a = CRH::<F>::evaluate(&params, h_a_inputs).unwrap();
    let inner: F = anchor_ctx
        .a
        .iter()
        .zip(anchor_ctx.anchor.0.iter())
        .map(|(a, anc)| *a * *anc)
        .sum();
    let lhs = inner * random;

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let leaves_data: Vec<(Vec<F>, Vec<F>)> = jwt_data
        .iter()
        .map(|(jwt, rsa_key)| {
            let jwt_parts: Vec<&str> = jwt.split('.').collect();
            let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
            let payload_str = String::from_utf8(payload_bytes).unwrap();
            let iss_bytes = claim_value_bytes(&payload_str, "iss", cfg.max_iss_len as usize);
            let iss_packed = pack_bytes_to_field_native(&iss_bytes);
            let pk_n_limbs = rsa_pk_n_limbs(rsa_key);
            (iss_packed, pk_n_limbs)
        })
        .collect();

    let (merkle_witnesses, root) = build_merkle_witness_multi(&leaves_data, &params, &cfg);

    let first_jwt = &jwt_data[0].0;
    let jwt_parts: Vec<&str> = first_jwt.split('.').collect();
    let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();
    let aud_bytes = claim_value_bytes(&payload_str, "aud", cfg.max_aud_len as usize);
    let aud_packed = pack_bytes_to_field_native(&aud_bytes);
    let (aud_list, h_aud_list) = build_audience_list(&aud_packed, &params, &cfg);

    let anchor_values_be: Vec<[u8; 32]> =
        anchor_ctx.anchor.0.iter().map(fe_to_be32_bytes).collect();
    let anchor_known_x_be: Vec<[u8; 32]> = known_x_list.iter().map(fe_to_be32_bytes).collect();
    let random_be = fe_to_be32_bytes(&random);
    let h_sign_user_op_be = fe_to_be32_bytes(&h_sign_user_op);
    let merkle_root_be = fe_to_be32_bytes(&root);

    let mut circuit_inputs = Vec::with_capacity(k);
    let mut v1_inputs = Vec::with_capacity(k);

    for i in 0..k {
        let s = &secrets[i];
        let (jwt, rsa_key) = &jwt_data[i];
        let jwt_witness = build_jwt_witness(jwt, rsa_key, &cfg);
        let current_idx = anchor_ctx.current_idx_list[i];

        let jwt_parts: Vec<&str> = jwt.split('.').collect();
        let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
        let payload_str = String::from_utf8(payload_bytes).unwrap();
        let aud_bytes_i = claim_value_bytes(&payload_str, "aud", cfg.max_aud_len as usize);
        let iss_bytes_i = claim_value_bytes(&payload_str, "iss", cfg.max_iss_len as usize);
        let sub_bytes_i = claim_value_bytes(&payload_str, "sub", cfg.max_sub_len as usize);
        let aud_packed_i = pack_bytes_to_field_native(&aud_bytes_i);
        let iss_packed_i = pack_bytes_to_field_native(&iss_bytes_i);
        let sub_packed_i = pack_bytes_to_field_native(&sub_bytes_i);

        let mut h_id_inputs = Vec::new();
        h_id_inputs.extend_from_slice(&aud_packed_i);
        h_id_inputs.extend_from_slice(&iss_packed_i);
        h_id_inputs.extend_from_slice(&sub_packed_i);
        let h_id_inner = CRH::<F>::evaluate(&params, h_id_inputs).unwrap();
        let h_id = CRH::<F>::evaluate(&params, [F::from(current_idx as u64), h_id_inner]).unwrap();
        let partial_rhs = anchor_ctx.b[current_idx] * h_id * random;
        let jwt_exp = F::from(s.exp);

        // anchor.hanchor reuses the chain-hashed anchor across all proofs.
        circuit_inputs.push(ZkapCircuitInput {
            params: cfg.clone(),
            constants: CircuitConstants {
                vandermonde_matrix: VandermondeMatrix::new(n, k),
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
        });

        let merkle_w = &merkle_witnesses[i];
        let merkle_leaf_sibling_hash_be = fe_to_be32_bytes(&merkle_w.path.leaf_sibling_hash);
        let merkle_auth_path_be: Vec<[u8; 32]> = merkle_w
            .path
            .auth_path
            .iter()
            .map(fe_to_be32_bytes)
            .collect();

        let pk = rsa_key.to_public_key();
        let rsa_modulus_be = pk.n().to_bytes_be();

        // Decode the JWT's sig_b64 segment so the V1 wire payload's
        // `rsa_signature_be` matches `base64_decode(sig_b64)` byte-for-byte
        // (the wasm side enforces this consistency).
        let jwt_parts: Vec<&str> = jwt.split('.').collect();
        let rsa_signature_be = engine.decode(jwt_parts[2]).expect("decode JWT sig_b64");

        v1_inputs.push(zkap_witness_wasm::ZkapInputV1 {
            jwt_bytes: jwt.as_bytes().to_vec(),
            rsa_modulus_be,
            rsa_signature_be,
            random_be,
            h_sign_user_op_be,
            anchor_values_be: anchor_values_be.clone(),
            anchor_known_x_be: anchor_known_x_be.clone(),
            anchor_selector: anchor_ctx.selector.clone(),
            anchor_current_idx: current_idx as u64,
            merkle_root_be,
            merkle_leaf_sibling_hash_be,
            merkle_auth_path_be,
            merkle_leaf_idx: merkle_w.leaf_idx as u64,
            circuit_config: cfg_v1.clone(),
        });
    }

    V1FixtureBundle {
        circuit_inputs,
        v1_inputs,
    }
}

/// Main orchestrator: build K complete valid circuit inputs (one per secret/JWT)
pub fn build_valid_circuit_inputs() -> Vec<ZkapCircuitInput<F>> {
    let cfg = test_params();
    let params = get_poseidon_params::<F>();
    let random = F::from(12345u64);
    let h_sign_user_op = F::from(67890u64);
    let nonce_hex = build_nonce_hex(h_sign_user_op, random, &params);

    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let secrets = &TEST_SECRETS;

    // Build K JWTs (each with different RSA key)
    let jwt_data: Vec<(String, rsa::RsaPrivateKey)> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| build_jwt_and_sign(s.aud, s.exp, s.iss, &nonce_hex, s.sub, 99 + i as u64))
        .collect();

    // Build anchor context (shared across all K proofs)
    let anchor_ctx = build_anchor_context(secrets, &params, &cfg);

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
            let iss_bytes = claim_value_bytes(&payload_str, "iss", cfg.max_iss_len as usize);
            let iss_packed = pack_bytes_to_field_native(&iss_bytes);
            let pk_n_limbs = rsa_pk_n_limbs(rsa_key);
            (iss_packed, pk_n_limbs)
        })
        .collect();

    let (merkle_witnesses, root) = build_merkle_witness_multi(&leaves_data, &params, &cfg);

    // Audience (shared -- all secrets use the same aud)
    let first_jwt = &jwt_data[0].0;
    let jwt_parts: Vec<&str> = first_jwt.split('.').collect();
    let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
    let payload_str = String::from_utf8(payload_bytes).unwrap();
    let aud_bytes = claim_value_bytes(&payload_str, "aud", cfg.max_aud_len as usize);
    let aud_packed = pack_bytes_to_field_native(&aud_bytes);
    let (aud_list, h_aud_list) = build_audience_list(&aud_packed, &params, &cfg);

    // Build K circuit inputs
    (0..k)
        .map(|i| {
            let s = &secrets[i];
            let (jwt, rsa_key) = &jwt_data[i];
            let jwt_witness = build_jwt_witness(jwt, rsa_key, &cfg);
            let current_idx = anchor_ctx.current_idx_list[i];

            // Compute h_id for this proof
            let jwt_parts: Vec<&str> = jwt.split('.').collect();
            let payload_bytes = engine.decode(jwt_parts[1]).unwrap();
            let payload_str = String::from_utf8(payload_bytes).unwrap();
            let aud_bytes_i = claim_value_bytes(&payload_str, "aud", cfg.max_aud_len as usize);
            let iss_bytes_i = claim_value_bytes(&payload_str, "iss", cfg.max_iss_len as usize);
            let sub_bytes_i = claim_value_bytes(&payload_str, "sub", cfg.max_sub_len as usize);
            let aud_packed_i = pack_bytes_to_field_native(&aud_bytes_i);
            let iss_packed_i = pack_bytes_to_field_native(&iss_bytes_i);
            let sub_packed_i = pack_bytes_to_field_native(&sub_bytes_i);

            let mut h_id_inputs = Vec::new();
            h_id_inputs.extend_from_slice(&aud_packed_i);
            h_id_inputs.extend_from_slice(&iss_packed_i);
            h_id_inputs.extend_from_slice(&sub_packed_i);
            let h_id_inner = CRH::<F>::evaluate(&params, h_id_inputs).unwrap();
            let h_id =
                CRH::<F>::evaluate(&params, [F::from(current_idx as u64), h_id_inner]).unwrap();

            // partial_rhs = b[current_idx] * h_id * random
            let partial_rhs = anchor_ctx.b[current_idx] * h_id * random;

            let jwt_exp = F::from(s.exp);

            ZkapCircuitInput {
                params: cfg.clone(),
                constants: CircuitConstants {
                    vandermonde_matrix: VandermondeMatrix::new(n, k),
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
