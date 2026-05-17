//! End-to-end happy-path test for the service `prove` function:
//!
//!   `service::setup` → `prove(&ArtifactSet, &ProveRequest)` →
//!   `Groth16::verify_proof(&pvk, &proof, &pub_inputs)`
//!
//! This is the “stronger fixture” called out in `native_prove_e2e.rs`'s
//! `prove_rejects_invalid_request` doc-comment: a real RSA-signed JWT
//! batch with a consistent anchor and Merkle tree, driven through the
//! public `ProveRequest` DTO and verified against the `PreparedVerifyingKey`
//! bundled on the `ArtifactSet`.
//!
//! Run with:
//!
//!   cargo test --release -p zkap-service --test groth16_e2e_prove_verify -- --ignored --nocapture
//!
//! It is `#[ignore]`-gated because `service::setup` runs the full Groth16
//! trusted setup (~4-5 s under the F1 config).

use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_crypto_primitives::{
    crh::{CRHScheme, poseidon::CRH},
    merkle_tree::MerkleTree,
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, Proof};
use ark_std::rand::SeedableRng;
use ark_utils::hex_decimal_to_field;
use base64::Engine;
use circuit::types::F;
use gadget::{hashes::poseidon::get_poseidon_params, merkletree::tree_config::MerkleTreeParams};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::Sha256;

use zkap_service::{
    AnchorSecret, ArtifactSet, CircuitConfig, GenerateAnchorRequest, HashRequest, ProveCredential,
    ProveRequest, generate_anchor, generate_poseidon_hash, prove, setup,
};

// ============================================================
// Config / constants
// ============================================================

fn e2e_config() -> CircuitConfig {
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

struct TestSecret {
    aud: &'static str,
    iss: &'static str,
    sub: &'static str,
    exp: u64,
}

const TEST_SECRETS: [TestSecret; 3] = [
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

const URL_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;
const STD_B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

// ============================================================
// JWT fixture builders
// ============================================================

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
    // Claim ordering MUST match cfg.claims so the in-circuit claim
    // extractor sees the indices the host-side recipe computes.
    let payload = format!(
        r#"{{"aud":"{aud}","exp":{exp},"iss":"{iss}","nonce":"{nonce_hex}","sub":"{sub}"}}"#
    );

    let header_b64 = URL_B64.encode(header);
    let payload_b64 = URL_B64.encode(&payload);
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_B64.encode(signature.to_bytes());

    let jwt = format!("{signing_input}.{sig_b64}");
    (jwt, priv_key)
}

// ============================================================
// Merkle-leaf hash (must match the in-circuit recipe in
// `crates/circuit/src/zkap.rs`: `H(iss_packed || pk_n_limbs)`,
// then `H(leaf)` for the leaf digest fed into the Merkle tree).
// `iss_packed` is the quote-wrapped iss bytes padded to
// `cfg.max_iss_len` and packed into BN254-Fr limbs (31 bytes / limb,
// big-endian). `pk_n_limbs` is the 256-byte RSA modulus reversed to
// little-endian and chunked into 8-byte BN254-Fr limbs.
// ============================================================

const BN254_LIMB_WIDTH: usize = 31;
const RSA_LIMB_BYTES: usize = 8;
const RSA_NUM_LIMBS: usize = 32;

fn pack_bytes_be_31(bytes: &[u8]) -> Vec<F> {
    assert!(
        bytes.len().is_multiple_of(BN254_LIMB_WIDTH),
        "iss buffer length must be a multiple of 31 (the BN254 limb width)"
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

// ============================================================
// hex → Proof<Bn254> + hex → Vec<F> reconstruction
// (inverse of `ProofComponents::from(&Proof<BN254>)` /
// `field_to_hex` in `crates/zkap-evm-verifier/src/solidity_types.rs`).
// ============================================================

fn fq_from_hex(s: &str) -> Fq {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).expect("valid hex for Fq");
    Fq::from_be_bytes_mod_order(&bytes)
}

fn proof_from_components(comp: &zkap_service::ProofComponents) -> Proof<Bn254> {
    // a, c: [hex(x), hex(y)]
    let a = G1Affine::new_unchecked(fq_from_hex(&comp.a[0]), fq_from_hex(&comp.a[1]));
    let c = G1Affine::new_unchecked(fq_from_hex(&comp.c[0]), fq_from_hex(&comp.c[1]));
    // b: [hex(b.x.c1), hex(b.x.c0), hex(b.y.c1), hex(b.y.c0)]
    let bx = Fq2::new(fq_from_hex(&comp.b[1]), fq_from_hex(&comp.b[0]));
    let by = Fq2::new(fq_from_hex(&comp.b[3]), fq_from_hex(&comp.b[2]));
    let b = G2Affine::new_unchecked(bx, by);
    Proof { a, b, c }
}

fn pub_inputs_from_hex(hexes: &[String]) -> Vec<F> {
    hexes
        .iter()
        .map(|s| hex_decimal_to_field::<F>(s).expect("valid Fr hex"))
        .collect()
}

// ============================================================
// Main test
// ============================================================

#[test]
#[ignore = "slow: full Groth16 setup (~4-5 s F1 config) plus k proofs and k verifications"]
fn e2e_setup_prove_verify_via_public_api() {
    let cfg = e2e_config();
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let tree_height = cfg.tree_height as usize;
    let secrets = &TEST_SECRETS;
    assert_eq!(secrets.len(), k);

    let params = get_poseidon_params::<F>();

    // ── 1. Trusted setup → ArtifactSet (in-memory). ─────────────────────
    let tmp_dir = std::env::temp_dir().join(format!(
        "zkap_e2e_prove_verify_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("create setup scratch dir");

    let setup_output = setup(&cfg, &tmp_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");
    let set: ArtifactSet = setup_output.into_artifact_set();

    // ── 2. Build the shared `random` / `h_sign_user_op` / nonce. ────────
    let random_fr = F::from(12345u64);
    let h_sign_user_op_fr = F::from(67890u64);

    // The in-circuit nonce constraint requires
    //   payload.nonce == Poseidon(h_sign_user_op, random)
    // — `generate_poseidon_hash` is the documented host-side recipe.
    let nonce_hash = generate_poseidon_hash(HashRequest {
        field_elements: vec![
            ark_utils::field_to_hex(h_sign_user_op_fr),
            ark_utils::field_to_hex(random_fr),
        ],
    })
    .expect("nonce poseidon hash")
    .hash;

    // ── 3. Build k JWTs (each signed with a distinct RSA-2048 key). ─────
    let jwts: Vec<(String, rsa::RsaPrivateKey)> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| build_jwt_and_sign(s.aud, s.exp, s.iss, &nonce_hash, s.sub, 99 + i as u64))
        .collect();

    // ── 4. Build the n-secret anchor (first k = real JWT subjects; last
    //      n-k = dummies). `generate_anchor`'s recipe matches the
    //      in-circuit `derive_x_from_secret` / chain-hash so the
    //      resulting `anchor_evaluations` line up bit-for-bit with what
    //      `prove` consumes. ───────────────────────────────────────────
    let mut anchor_secrets: Vec<AnchorSecret> = secrets
        .iter()
        .map(|s| AnchorSecret {
            subject: s.sub.into(),
            issuer: s.iss.into(),
            audience: s.aud.into(),
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

    // ── 5. Build the Merkle tree of issuer-key leaves. Credential i's
    //      leaf is placed at position i; remaining slots are zero. The
    //      leaf recipe MUST mirror `crates/circuit/src/zkap.rs`'s
    //      `H(iss_packed || pk_n_limbs)` (with `iss` quote-wrapped to
    //      match the in-circuit JWT extractor's bytes), then the outer
    //      `H(leaf)` consumed by `ark_crypto_primitives::MerkleTree`'s
    //      `new_with_leaf_digest`. ──────────────────────────────────────
    let num_leaves = 1usize << tree_height;
    let mut digests = vec![F::zero(); num_leaves];
    for (i, (_, priv_key)) in jwts.iter().enumerate() {
        digests[i] = merkle_leaf_digest(secrets[i].iss, priv_key, &cfg, &params);
    }
    let tree = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(&params, &params, digests)
        .expect("Merkle tree build");
    let root_fr = tree.root();
    let root_hex = ark_utils::field_to_hex(root_fr);

    // ── 6. Assemble the `ProveRequest`. The Merkle-path slice
    //      `[leaf_sibling_hash, auth_path_0, auth_path_1, ...]` matches
    //      what the adapter splits at `prove_request_to_decoded`. ───────
    let credentials: Vec<ProveCredential> = jwts
        .iter()
        .enumerate()
        .map(|(i, (jwt, priv_key))| {
            let proof_path = tree.generate_proof(i).expect("Merkle proof");
            let mut merkle_path = Vec::with_capacity(1 + proof_path.auth_path.len());
            merkle_path.push(ark_utils::field_to_hex(proof_path.leaf_sibling_hash));
            for sib in &proof_path.auth_path {
                merkle_path.push(ark_utils::field_to_hex(*sib));
            }

            let pub_key = priv_key.to_public_key();
            let mut n_be = pub_key.n().to_bytes_be();
            // RSA-2048 → exactly 256 bytes BE; ark/rsa already gives 256
            // here, but the resize is defensive against leading-zero
            // truncation surprising us in CI environments.
            if n_be.len() < 256 {
                let mut padded = vec![0u8; 256 - n_be.len()];
                padded.append(&mut n_be);
                n_be = padded;
            }
            assert_eq!(n_be.len(), 256, "RSA-2048 modulus must be 256 BE bytes");

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
        anchor: anchor_resp.anchor_evaluations.clone(),
        merkle_root: root_hex,
        credentials,
    };

    // ── 7. prove(). ─────────────────────────────────────────────────────
    let response = prove(&set, &request).expect("prove must succeed on a valid request");
    assert_eq!(response.proofs.len(), k);
    assert_eq!(response.jwt_exp.len(), k);
    assert_eq!(response.verification_rhs.len(), k);

    // Cross-check that the response's anchor chain hash equals what
    // `generate_anchor` reported — the same `hanchor` field must show
    // up on both sides.
    assert_eq!(
        response.shared_public_inputs.hanchor, anchor_resp.hanchor,
        "service `hanchor` should equal the prove-response shared hanchor"
    );

    // ── 8. Verify each proof against the bundled PreparedVerifyingKey. ──
    let pvk = &set.pvk;
    for i in 0..k {
        let proof = proof_from_components(&response.proofs[i]);
        let pub_inputs = pub_inputs_from_hex(&response.public_inputs_for(i));
        assert_eq!(pub_inputs.len(), 8, "8-element canonical instance vector");

        let ok = Groth16::<Bn254>::verify_proof(pvk, &proof, &pub_inputs)
            .expect("verify_proof must not error on a real proof");
        assert!(
            ok,
            "proof[{}] must verify against the setup's PreparedVerifyingKey",
            i
        );
        println!("proof[{i}] verified ✓");
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ============================================================
// Negative check: tampering a public input breaks verification.
// Re-uses the prove output from a second setup+prove run; kept as a
// separate `#[ignore]` test so the happy path stays minimal.
// ============================================================

#[test]
#[ignore = "slow: full Groth16 setup + prove for a tamper-detection check"]
fn e2e_verify_rejects_tampered_public_input() {
    let cfg = e2e_config();
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    let tree_height = cfg.tree_height as usize;
    let secrets = &TEST_SECRETS;

    let params = get_poseidon_params::<F>();

    let tmp_dir = std::env::temp_dir().join(format!(
        "zkap_e2e_tamper_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("create setup scratch dir");

    let setup_output = setup(&cfg, &tmp_dir, &mut ark_std::rand::rngs::OsRng, None).expect("setup");
    let set = setup_output.into_artifact_set();

    let random_fr = F::from(12345u64);
    let h_sign_user_op_fr = F::from(67890u64);
    let nonce_hash = generate_poseidon_hash(HashRequest {
        field_elements: vec![
            ark_utils::field_to_hex(h_sign_user_op_fr),
            ark_utils::field_to_hex(random_fr),
        ],
    })
    .unwrap()
    .hash;

    let jwts: Vec<(String, rsa::RsaPrivateKey)> = secrets
        .iter()
        .enumerate()
        .map(|(i, s)| build_jwt_and_sign(s.aud, s.exp, s.iss, &nonce_hash, s.sub, 99 + i as u64))
        .collect();

    let mut anchor_secrets: Vec<AnchorSecret> = secrets
        .iter()
        .map(|s| AnchorSecret {
            subject: s.sub.into(),
            issuer: s.iss.into(),
            audience: s.aud.into(),
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
    .unwrap();

    let num_leaves = 1usize << tree_height;
    let mut digests = vec![F::zero(); num_leaves];
    for (i, (_, priv_key)) in jwts.iter().enumerate() {
        digests[i] = merkle_leaf_digest(secrets[i].iss, priv_key, &cfg, &params);
    }
    let tree = MerkleTree::<MerkleTreeParams<F>>::new_with_leaf_digest(&params, &params, digests)
        .expect("tree");
    let root_hex = ark_utils::field_to_hex(tree.root());

    let credentials: Vec<ProveCredential> = jwts
        .iter()
        .enumerate()
        .map(|(i, (jwt, priv_key))| {
            let p = tree.generate_proof(i).unwrap();
            let mut mp = Vec::with_capacity(1 + p.auth_path.len());
            mp.push(ark_utils::field_to_hex(p.leaf_sibling_hash));
            for sib in &p.auth_path {
                mp.push(ark_utils::field_to_hex(*sib));
            }
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
                merkle_path: mp,
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
    let response = prove(&set, &request).expect("prove");

    // Sanity: untampered proofs verify.
    let proof0 = proof_from_components(&response.proofs[0]);
    let pub0 = pub_inputs_from_hex(&response.public_inputs_for(0));
    assert!(
        Groth16::<Bn254>::verify_proof(&set.pvk, &proof0, &pub0).unwrap(),
        "control: untampered proof must verify before the negative case"
    );

    // Tamper with the `hanchor` instance slot (index 0). Verification
    // must reject.
    let mut tampered = pub0.clone();
    tampered[0] += F::from(1u64);
    let verified = Groth16::<Bn254>::verify_proof(&set.pvk, &proof0, &tampered).unwrap_or(false);
    assert!(
        !verified,
        "verify_proof must reject a proof with a tampered public input"
    );

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// Compile-time guard that this test file pulls in only public items —
// catches accidental reliance on `pub(crate)` helpers if the boundary
// shape ever drifts.
#[allow(dead_code)]
fn _api_surface_guard(set: &ArtifactSet, req: &ProveRequest) {
    let _: Result<zkap_service::ProveResponse, zkap_service::error::ApplicationError> =
        prove(set, req);
    // `FromStr` is brought in so `ark_bn254::Fr::from_str` stays
    // available even if hex_decimal_to_field's re-export ever moves.
    let _ = F::from_str("0");
}
