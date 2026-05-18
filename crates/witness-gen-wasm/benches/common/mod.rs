//! Shared fixture builder for the witness-gen-wasm bench + parity
//! test.
//!
//! The witness path verifies an RSA-2048 signature inside the
//! constraint system, so we cannot hand-roll a synthetic
//! `ProveRequest`. This module re-derives a real one (JWT plus RSA
//! key, anchor, and issuer-key Merkle tree) using deterministic
//! seeds, so every k variant produces the same bytes across runs.
//!
//! This is a lift of the relevant input-construction code from
//! `crates/service/tests/groth16_e2e_prove_verify.rs` and
//! `crates/service/tests/gen_proof_fixture.rs`, kept small (≈150
//! lines) by dropping the JS-camelCase serialization shell and the
//! manifest-dir I/O — the bench just needs `(CircuitConfig,
//! ProveRequest)` pairs.
//!
//! The chosen toy config keeps `tree_height = 4` (small Merkle tree)
//! and short JWT/payload max-lengths so that witness synthesis is
//! still representative but doesn't dominate the bench time with
//! padding. `n = k` (all credentials real, zero dummies) for clean
//! per-k scaling.

pub mod wasm_runner;

use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::MerkleTree,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{PrimeField, Zero};
use ark_std::rand::SeedableRng;
use base64::Engine;
use circuit::types::F;
use gadget::{hashes::poseidon::get_poseidon_params, merkletree::tree_config::MerkleTreeParams};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

use zkap_service::{
    AnchorSecret, CircuitConfig, GenerateAnchorRequest, HashRequest, ProveCredential, ProveRequest,
    generate_anchor, generate_poseidon_hash,
};

const URL_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
const STD_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

const BN254_LIMB_WIDTH: usize = 31;
const RSA_LIMB_BYTES: usize = 8;
const RSA_NUM_LIMBS: usize = 32;

/// Bench-only deterministic circuit config — small `tree_height` and
/// `max_*_len` values to keep witness synthesis fast while still
/// exercising the full claim-extraction + RSA-verify path.
fn bench_config(k: u64) -> CircuitConfig {
    CircuitConfig {
        max_jwt_b64_len: 1024,
        max_payload_b64_len: 640,
        max_aud_len: 155,
        max_exp_len: 20,
        max_iss_len: 93,
        max_nonce_len: 93,
        max_sub_len: 93,
        n: k,
        k,
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
        r#"{{"aud":"{aud}","exp":{exp},"iss":"{iss}","nonce":"{nonce_hex}","sub":"{sub}"}}"#
    );

    let header_b64 = URL_B64.encode(header);
    let payload_b64 = URL_B64.encode(&payload);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_B64.encode(signature.to_bytes());

    (format!("{signing_input}.{sig_b64}"), priv_key)
}

fn pack_bytes_be_31(bytes: &[u8]) -> Vec<F> {
    assert!(
        bytes.len().is_multiple_of(BN254_LIMB_WIDTH),
        "iss buffer length must be a multiple of 31 (BN254 limb width)"
    );
    bytes
        .chunks(BN254_LIMB_WIDTH)
        .map(F::from_be_bytes_mod_order)
        .collect()
}

fn iss_packed_with_quotes(iss: &str, max_iss_len: usize) -> Vec<F> {
    let mut bytes = Vec::with_capacity(iss.len() + 2);
    bytes.push(b'"');
    bytes.extend_from_slice(iss.as_bytes());
    bytes.push(b'"');
    bytes.resize(max_iss_len, 0x00);
    pack_bytes_be_31(&bytes)
}

fn rsa_n_limbs(priv_key: &rsa::RsaPrivateKey) -> Vec<F> {
    let pub_key = priv_key.to_public_key();
    let n_be = pub_key.n().to_bytes_be();
    let mut n_le = n_be;
    n_le.reverse();
    n_le.resize(RSA_LIMB_BYTES * RSA_NUM_LIMBS, 0);
    n_le.chunks(RSA_LIMB_BYTES)
        .map(F::from_le_bytes_mod_order)
        .collect()
}

fn merkle_leaf_digest(
    iss: &str,
    priv_key: &rsa::RsaPrivateKey,
    cfg: &CircuitConfig,
    params: &PoseidonConfig<F>,
) -> F {
    let mut leaf_inputs = iss_packed_with_quotes(iss, cfg.max_iss_len as usize);
    leaf_inputs.extend(rsa_n_limbs(priv_key));
    let leaf = CRH::<F>::evaluate(params, leaf_inputs).expect("Poseidon leaf");
    CRH::<F>::evaluate(params, [leaf]).expect("Poseidon leaf digest")
}

/// Build a fully-valid `(CircuitConfig, ProveRequest)` pair for the
/// given `k` (= n = k, all real credentials).
///
/// Deterministic: identical seeds produce byte-identical JSON across
/// runs, which is what the parity test relies on for the
/// rlib-vs-wasm equivalence check.
pub fn build_fixture(k: u64) -> (CircuitConfig, ProveRequest) {
    let cfg = bench_config(k);
    let k_usize = k as usize;
    let tree_height = cfg.tree_height as usize;
    let params = get_poseidon_params::<F>();

    // Shared inputs (deterministic).
    let random_fr = F::from(12345u64);
    let h_sign_user_op_fr = F::from(67890u64);
    let nonce_hash = generate_poseidon_hash(HashRequest {
        field_elements: vec![
            ark_utils::field_to_hex(h_sign_user_op_fr),
            ark_utils::field_to_hex(random_fr),
        ],
    })
    .expect("nonce poseidon hash")
    .hash;

    let aud = "test-audience";
    let iss = "https://accounts.google.com";
    let exp = 1_700_000_000u64;

    // k JWTs, distinct RSA-2048 keys.
    let jwts: Vec<(String, rsa::RsaPrivateKey, String)> = (0..k_usize)
        .map(|i| {
            let sub = format!("user_{i}");
            let (jwt, priv_key) =
                build_jwt_and_sign(aud, exp, iss, &nonce_hash, &sub, 99 + i as u64);
            (jwt, priv_key, sub)
        })
        .collect();

    // Anchor: n = k, zero dummies.
    let anchor_secrets: Vec<AnchorSecret> = jwts
        .iter()
        .map(|(_, _, sub)| AnchorSecret {
            subject: sub.clone(),
            issuer: iss.into(),
            audience: aud.into(),
        })
        .collect();
    let anchor_resp = generate_anchor(
        &cfg,
        GenerateAnchorRequest {
            secrets: anchor_secrets,
        },
    )
    .expect("generate_anchor must succeed");

    // Merkle tree of issuer-key leaves at indices 0..k.
    let num_leaves = 1usize << tree_height;
    let mut digests = vec![F::zero(); num_leaves];
    for (i, (_, priv_key, _)) in jwts.iter().enumerate() {
        digests[i] = merkle_leaf_digest(iss, priv_key, &cfg, &params);
    }
    let tree = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(&params, &params, digests)
        .expect("Merkle tree build");
    let root_hex = ark_utils::field_to_hex(tree.root());

    let credentials: Vec<ProveCredential> = jwts
        .iter()
        .enumerate()
        .map(|(i, (jwt, priv_key, _))| {
            let proof_path = tree.generate_proof(i).expect("Merkle proof");
            let mut merkle_path = Vec::with_capacity(1 + proof_path.auth_path.len());
            merkle_path.push(ark_utils::field_to_hex(proof_path.leaf_sibling_hash));
            for sib in &proof_path.auth_path {
                merkle_path.push(ark_utils::field_to_hex(*sib));
            }
            assert_eq!(merkle_path.len(), tree_height);

            let pub_key = priv_key.to_public_key();
            let mut n_be = pub_key.n().to_bytes_be();
            if n_be.len() < 256 {
                let mut padded = vec![0u8; 256 - n_be.len()];
                padded.append(&mut n_be);
                n_be = padded;
            }

            ProveCredential {
                jwt: jwt.clone(),
                rsa_modulus_b64: STD_B64.encode(&n_be),
                merkle_path,
                merkle_leaf_idx: i as u64,
            }
        })
        .collect();

    let request = ProveRequest {
        random: ark_utils::field_to_hex(random_fr),
        h_sign_user_op: ark_utils::field_to_hex(h_sign_user_op_fr),
        anchor: anchor_resp.anchor_evaluations,
        merkle_root: root_hex,
        credentials,
    };

    (cfg, request)
}

/// Serialize a `(CircuitConfig, ProveRequest)` pair to the JSON bytes
/// accepted by `synthesize_witness_bytes` and the wasm
/// `synthesize_witness` export.
pub fn fixture_json(cfg: &CircuitConfig, req: &ProveRequest) -> (Vec<u8>, Vec<u8>) {
    let req_json = serde_json::to_vec(req).expect("serialize ProveRequest");
    let cfg_json = serde_json::to_vec(cfg).expect("serialize CircuitConfig");
    (req_json, cfg_json)
}

/// Locate the cdylib wasm artifact produced by
/// `cargo build --target wasm32-unknown-unknown --release
/// -p zkap-witness-gen-wasm`.
///
/// Walks up from `CARGO_MANIFEST_DIR` (= `crates/witness-gen-wasm`)
/// until it finds `target/wasm32-unknown-unknown/release/
/// zkap_witness_gen_wasm.wasm`. Panics with an actionable message if
/// the artifact isn't built — bench / parity caller is expected to
/// build it first (see `crates/witness-gen-wasm/PERF.md`).
pub fn wasm_artifact_path() -> std::path::PathBuf {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/witness-gen-wasm");
    let path = workspace_root
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release")
        .join("zkap_witness_gen_wasm.wasm");
    assert!(
        path.exists(),
        "wasm artifact missing at {} — run:\n  cargo build --target wasm32-unknown-unknown --release -p zkap-witness-gen-wasm",
        path.display()
    );
    path
}
