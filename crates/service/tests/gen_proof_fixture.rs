//! Emit a `proof_fixture.json` next to a real CRS bundle so the sdk-node
//! ava suite can exercise the happy-path `prove()` flow end-to-end.
//!
//! Output shape mirrors what `__test__/proof.spec.ts` reads via
//! `ZKAP_PROOF_FIXTURE_JSON`:
//!
//!   {
//!     "manifestDir": "<abs path to CRS bundle>",
//!     "config":      { camelCase JsCircuitConfig fields },
//!     "request":     { camelCase JsProofRequest fields, minus manifestDir }
//!   }
//!
//! The recipe (JWT signing, anchor evaluations, Merkle tree of issuer-key
//! leaves) follows `groth16_e2e_prove_verify::e2e_setup_prove_verify_via_public_api`
//! but parameterises on the bundle's own `config.json` so it works against
//! any deployed bundle (1-of-1, 3-of-3, …) — not just the e2e test's
//! private F2 setup.
//!
//! Run with (default manifest dir = `dist/1-of-1` relative to repo root):
//!
//!   cargo test --release -p zkap-service --test gen_proof_fixture \
//!       -- --ignored --nocapture
//!
//! Override the bundle directory with `ZKAP_PROOF_MANIFEST_DIR=<abs>`. The
//! fixture is written to `<manifestDir>/proof_fixture.json` and the path
//! is printed so the caller can plug it into
//! `ZKAP_PROOF_FIXTURE_JSON` when invoking `npm test` in sdk-node.

use std::path::PathBuf;

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
use serde::Serialize;
use sha2::Sha256;

use zkap_service::{
    AnchorSecret, CircuitConfig, GenerateAnchorRequest, HashRequest, generate_anchor,
    generate_poseidon_hash, load_circuit_config,
};

// ---------- output JSON shape (camelCase for sdk-node consumption) ----------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsCircuitConfig {
    max_jwt_b64_len: u64,
    max_payload_b64_len: u64,
    max_aud_len: u64,
    max_exp_len: u64,
    max_iss_len: u64,
    max_nonce_len: u64,
    max_sub_len: u64,
    n: u64,
    k: u64,
    tree_height: u64,
    num_audience_limit: u64,
    claims: Vec<String>,
    forbidden_string: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsProveCredential {
    jwt: String,
    rsa_modulus_b64: String,
    merkle_path: Vec<String>,
    merkle_leaf_idx: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsProofRequest {
    random: String,
    h_sign_user_op: String,
    anchor: Vec<String>,
    merkle_root: String,
    credentials: Vec<JsProveCredential>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixture {
    manifest_dir: String,
    config: JsCircuitConfig,
    request: JsProofRequest,
}

// ---------- JWT / merkle helpers (mirrored from groth16_e2e_prove_verify) ----------

const URL_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
const STD_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

const BN254_LIMB_WIDTH: usize = 31;
const RSA_LIMB_BYTES: usize = 8;
const RSA_NUM_LIMBS: usize = 32;

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

fn cfg_to_js(cfg: &CircuitConfig) -> JsCircuitConfig {
    JsCircuitConfig {
        max_jwt_b64_len: cfg.max_jwt_b64_len,
        max_payload_b64_len: cfg.max_payload_b64_len,
        max_aud_len: cfg.max_aud_len,
        max_exp_len: cfg.max_exp_len,
        max_iss_len: cfg.max_iss_len,
        max_nonce_len: cfg.max_nonce_len,
        max_sub_len: cfg.max_sub_len,
        n: cfg.n,
        k: cfg.k,
        tree_height: cfg.tree_height,
        num_audience_limit: cfg.num_audience_limit,
        claims: cfg.claims.clone(),
        forbidden_string: cfg.forbidden_string.clone(),
    }
}

// ---------- the test ----------

#[test]
#[ignore = "writes proof_fixture.json next to a real CRS bundle; RSA-2048 keygen + Merkle tree build take a few seconds"]
fn gen_proof_fixture_for_manifest_dir() {
    let manifest_dir: PathBuf = std::env::var("ZKAP_PROOF_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Default: <repo>/dist/1-of-1 relative to this crate.
            // CARGO_MANIFEST_DIR = crates/service, so the repo root is two
            // levels up.
            let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            crate_dir
                .parent()
                .and_then(|p| p.parent())
                .expect("repo root")
                .join("dist/1-of-1")
        });
    assert!(
        manifest_dir.join("manifest.json").exists(),
        "manifest.json missing under {} — run generate_setup first",
        manifest_dir.display()
    );
    assert!(
        manifest_dir.join("config.json").exists(),
        "config.json missing under {}",
        manifest_dir.display()
    );

    let cfg =
        load_circuit_config(&manifest_dir.join("config.json")).expect("load CRS bundle config");
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let tree_height = cfg.tree_height as usize;
    assert!(k >= 1, "config.k must be >= 1");
    assert!(n >= k, "config.n must be >= config.k");

    let params = get_poseidon_params::<F>();

    // ── 1. Shared inputs: deterministic random / h_sign_user_op. ────────
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

    // ── 2. k JWTs (each with a distinct RSA-2048 key, deterministic seeds). ─
    let aud = "test-audience";
    let iss = "https://accounts.google.com";
    let exp = 1_700_000_000u64;

    let jwts: Vec<(String, rsa::RsaPrivateKey, String /*sub*/)> = (0..k)
        .map(|i| {
            let sub = format!("user_{i}");
            let (jwt, priv_key) =
                build_jwt_and_sign(aud, exp, iss, &nonce_hash, &sub, 99 + i as u64);
            (jwt, priv_key, sub)
        })
        .collect();

    // ── 3. Anchor: first k real subjects + (n - k) dummies. ────────────
    let mut anchor_secrets: Vec<AnchorSecret> = jwts
        .iter()
        .map(|(_, _, sub)| AnchorSecret {
            subject: sub.clone(),
            issuer: iss.into(),
            audience: aud.into(),
        })
        .collect();
    for i in 0..(n - k) {
        anchor_secrets.push(AnchorSecret {
            subject: format!("dummy_sub_{i}"),
            issuer: format!("dummy_iss_{i}"),
            audience: format!("dummy_aud_{i}"),
        });
    }
    let anchor_resp = generate_anchor(
        &cfg,
        GenerateAnchorRequest {
            secrets: anchor_secrets,
        },
    )
    .expect("generate_anchor must succeed");
    assert_eq!(anchor_resp.anchor_evaluations.len(), n - k + 1);

    // ── 4. Merkle tree of issuer-key leaves at indices 0..k. ───────────
    let num_leaves = 1usize << tree_height;
    let mut digests = vec![F::zero(); num_leaves];
    for (i, (_, priv_key, _)) in jwts.iter().enumerate() {
        digests[i] = merkle_leaf_digest(iss, priv_key, &cfg, &params);
    }
    let tree = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(&params, &params, digests)
        .expect("Merkle tree build");
    let root_hex = ark_utils::field_to_hex(tree.root());

    // ── 5. Assemble credentials. ───────────────────────────────────────
    let credentials: Vec<JsProveCredential> = jwts
        .iter()
        .enumerate()
        .map(|(i, (jwt, priv_key, _))| {
            let proof_path = tree.generate_proof(i).expect("Merkle proof");
            let mut merkle_path = Vec::with_capacity(1 + proof_path.auth_path.len());
            merkle_path.push(ark_utils::field_to_hex(proof_path.leaf_sibling_hash));
            for sib in &proof_path.auth_path {
                merkle_path.push(ark_utils::field_to_hex(*sib));
            }
            assert_eq!(
                merkle_path.len(),
                tree_height,
                "merkle_path length must equal cfg.tree_height"
            );

            let pub_key = priv_key.to_public_key();
            let mut n_be = pub_key.n().to_bytes_be();
            if n_be.len() < 256 {
                let mut padded = vec![0u8; 256 - n_be.len()];
                padded.append(&mut n_be);
                n_be = padded;
            }
            assert_eq!(n_be.len(), 256, "RSA-2048 modulus must be 256 BE bytes");

            JsProveCredential {
                jwt: jwt.clone(),
                rsa_modulus_b64: STD_B64.encode(&n_be),
                merkle_path,
                merkle_leaf_idx: i as u64,
            }
        })
        .collect();

    let request = JsProofRequest {
        random: ark_utils::field_to_hex(random_fr),
        h_sign_user_op: ark_utils::field_to_hex(h_sign_user_op_fr),
        anchor: anchor_resp.anchor_evaluations,
        merkle_root: root_hex,
        credentials,
    };

    // ── 6. Write JSON. ─────────────────────────────────────────────────
    let fixture = ProofFixture {
        manifest_dir: manifest_dir
            .canonicalize()
            .expect("canonicalize manifest dir")
            .to_string_lossy()
            .into_owned(),
        config: cfg_to_js(&cfg),
        request,
    };

    let out_path = manifest_dir.join("proof_fixture.json");
    let bytes = serde_json::to_vec_pretty(&fixture).expect("serialize fixture");
    std::fs::write(&out_path, &bytes).expect("write proof_fixture.json");

    println!(
        "\nproof_fixture.json written: {}\n  bundle : n={} k={} tree_height={}\n\nFor sdk-node:\n  ZKAP_PROOF_FIXTURE_JSON={} npm test\n",
        out_path.display(),
        cfg.n,
        cfg.k,
        cfg.tree_height,
        out_path.display(),
    );
}
