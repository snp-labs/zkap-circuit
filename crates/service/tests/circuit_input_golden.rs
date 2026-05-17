//! Regression gate (REGRESSION RULE per plan §3 Finding 3.1) against
//! accidental drift in the post-`witness_*`-removal prove pipeline.
//!
//! # Why this exists
//!
//! After Commit 3 of the `witness_{error,input,request}.rs` removal the
//! prove path is:
//!
//! ```text
//! ProveRequest
//!   → adapter::prove_request_to_decoded   (config.validate + shape + decode)
//!   → derive_x_from_secret per credential (parses JWT for sub/iss/aud)
//!   → derive_selector_from_x_list_and_anchor
//!   → per credential: circuit_input::{build_anchor_stage,
//!     build_jwt_stage, build_audience_stage, build_merkle_witness,
//!     compute_public_inputs}
//!   → ZkapCircuit::from_input → ar_ar1cs::{synthesize_full_assignment, prove}
//! ```
//!
//! The full happy-path proof requires a hand-built JWT + RSA + anchor
//! fixture that satisfies every R1CS constraint (~800 lines; the
//! canonical copy lives in `circuit::tests::groth16_integration` and
//! takes minutes even in release mode). Replicating that here is
//! redundant: `groth16_integration` already covers the satisfaction
//! check.
//!
//! # Choice of regression invariant
//!
//! The spec offered three flavours of regression gate (full byte-level
//! golden, two-paths-must-be-equal, shape-only smoke). The full
//! byte-level golden would require a working ArtifactSet + a
//! satisfying ProveRequest — see above. The two-paths invariant can't
//! be expressed across the integration-test boundary because the stage
//! builders in [`zkap_service::groth16::prover::circuit_input`] are
//! `pub(crate)`.
//!
//! What we lock in instead — a **deterministic-failure regression**:
//!
//! 1. Build the cheapest possible `ArtifactSet` (via in-memory
//!    `setup → into_artifact_set`) and a deterministic
//!    cryptographically-junk `ProveRequest` that satisfies every
//!    adapter shape check.
//! 2. Call `prove(&set, &req)` twice in a row and assert that both
//!    calls return the **same** `ApplicationError::InvalidProveRequest`
//!    variant with the **same** `field` path. This pins:
//!    * which validation gate fires first (drift in the order of
//!      `cfg.validate → shape checks → derive_x → derive_selector`
//!      would change the `field`);
//!    * the variant of `ApplicationError` returned (drift from
//!      `InvalidProveRequest` to `CryptographicError` /
//!      `PoseidonHashError` / `ProofGenerationFailed` would fail);
//!    * end-to-end runtime determinism (rejection occurs in the
//!      pre-randomness phase, so the two calls *must* match modulo
//!      RNG-dependent steps).
//!
//! This is weaker than a byte-level public-inputs golden, but it
//! catches the realistic failure modes a witness-files removal would
//! actually introduce (wrong adapter order, wrong error mapping, lost
//! `field_path` propagation) while running in ≤ ~5s in release mode.
//!
//! Marked `#[ignore]` so it stays out of the default fast test path —
//! `cargo test --release -p zkap-service --test circuit_input_golden
//! -- --ignored` exercises it. The plan calls for it to be the
//! pre-merge gate on this refactor.

use std::path::PathBuf;

use zkap_service::error::ApplicationError;
use zkap_service::{ArtifactSet, CircuitConfig, ProveCredential, ProveRequest, prove, setup};

fn fixture_config() -> CircuitConfig {
    // Matches the `sample_config_v1`-style F1 fixture used in
    // `native_prove_e2e.rs` / `service_integration.rs`. Cheapest config
    // that still exercises every adapter stage: n=6, k=3, tree_height=4.
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

/// Deterministic, cryptographically-junk JWT. Shape-valid (3
/// dot-separated segments, 256-byte signature, JSON payload with the
/// five canonical claims) so the adapter decodes it without error.
fn fixture_jwt() -> String {
    use base64::Engine;
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        br#"{"aud":"a","exp":1700000000,"iss":"i","nonce":"n","sub":"s"}"#,
    );
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xAAu8; 256]);
    format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
}

/// Build a deterministic `ProveRequest`. The anchor / merkle_root /
/// random / h_sign_user_op fields are fixed zero-padded field
/// encodings; the JWT is `fixture_jwt()`; the RSA modulus is a
/// 256-byte all-`0xCD` blob. The request is shape-valid but the
/// anchor scalars don't match any JWT-derived `x` so the selector
/// derivation in `prove()` is guaranteed to fail deterministically.
fn fixture_request(cfg: &CircuitConfig) -> ProveRequest {
    use base64::Engine;
    let k = cfg.k as usize;
    let anchor_len = (cfg.n - cfg.k + 1) as usize;
    let tree_height = cfg.tree_height as usize;

    let zero_fe = "0x00".to_string();
    let rsa_modulus_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xCDu8; 256]);

    ProveRequest {
        random: zero_fe.clone(),
        h_sign_user_op: zero_fe.clone(),
        anchor: vec![zero_fe.clone(); anchor_len],
        merkle_root: zero_fe.clone(),
        credentials: (0..k)
            .map(|_| ProveCredential {
                jwt: fixture_jwt(),
                rsa_modulus_b64: rsa_modulus_b64.clone(),
                merkle_path: vec![zero_fe.clone(); tree_height],
                merkle_leaf_idx: 0,
            })
            .collect(),
    }
}

fn unique_tmp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("zkap_circuit_input_golden_{tag}_{nanos}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create scratch dir");
    p
}

/// Locks down the deterministic failure mode of `prove()` against the
/// canonical fixture. See module docs for the regression rationale.
#[test]
#[ignore = "slow: drives the full Groth16 setup via service::setup (~4-5s F1 config)"]
fn prove_failure_mode_is_deterministic_for_canonical_fixture() {
    let cfg = fixture_config();
    let out_dir = unique_tmp_dir("failure_mode");
    let setup_output = setup(&cfg, &out_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");
    let set: ArtifactSet = setup_output.into_artifact_set();

    let req = fixture_request(&cfg);

    // Run prove() twice; both calls must surface the same deterministic
    // error variant + field path. Drift in the validation order or
    // error mapping shows up here immediately.
    let result_a = prove(&set, &req);
    let result_b = prove(&set, &req);

    let (field_a, field_b) = match (&result_a, &result_b) {
        (
            Err(ApplicationError::InvalidProveRequest { field: fa, .. }),
            Err(ApplicationError::InvalidProveRequest { field: fb, .. }),
        ) => (fa.clone(), fb.clone()),
        _ => panic!(
            "expected both prove() calls to return Err(InvalidProveRequest), got:\n  a = {:?}\n  b = {:?}",
            result_a, result_b
        ),
    };
    assert_eq!(
        field_a, field_b,
        "prove() failure field path must be deterministic across calls"
    );

    // Pin the exact field path expected for the canonical fixture.
    // The placeholder anchor is all-zero, which never matches the
    // JWT-derived `x` list, so the selector derivation in `prove()`
    // raises an `InvalidProveRequest { field: "anchor / jwts", .. }`.
    // (See prove.rs ~ "no valid selector — anchor and JWT claim
    // shares inconsistent".)
    assert_eq!(
        field_a, "anchor / jwts",
        "prove() must surface selector-derivation failure with field='anchor / jwts'; \
         drift in the validation order or error mapping shows up here. \
         If you intentionally moved this failure (e.g. into the adapter), \
         update this golden."
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Compile-time guard: `prove`'s signature must remain
/// `fn(&ArtifactSet, &ProveRequest) -> Result<ProveResponse,
/// ApplicationError>`. Mirror of the same guard in `lib.rs`'s module
/// docs (added in Commit 3 as part of Finding 2.1).
#[test]
fn prove_signature_is_stable() {
    let _: fn(
        &ArtifactSet,
        &ProveRequest,
    ) -> Result<zkap_service::ProveResponse, ApplicationError> = prove;
}
