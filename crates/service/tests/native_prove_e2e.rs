//! Service crate integration tests for the post-2026-05 native ar1cs
//! prove flow.
//!
//! These cover the public API contract — `ArtifactSet::load` →
//! `prove(&set, &request)` — at the seam level. A full end-to-end
//! happy-path proof that satisfies every R1CS constraint requires a
//! hand-built JWT + RSA + anchor fixture (~800 lines) and lives in the
//! slower `circuit::tests::groth16_integration` suite; replicating it
//! here would not exercise anything `groth16_integration` does not.
//!
//! What this file pins:
//!
//! * Compile-time: [`prove`] takes only `(&ArtifactSet, &ProveRequest)`
//!   — no `&Manifest`, no path arguments, no `&CircuitConfig`, no rng.
//! * Runtime: `service::setup` → [`SetupOutput::into_artifact_set`] →
//!   `ArtifactSet` round trip exposes `vk` / `cfg` / `pk` / `arcs`
//!   without manifest involvement.
//! * Runtime (regression, IRON RULE per Codex outside-voice): a
//!   placeholder request driven through `prove(&set, &req)` is
//!   rejected with an `Err(_)` — proves that *something downstream of
//!   the public `prove` API* runs and rejects garbage. (Honest limit:
//!   the failure may occur in the adapter's selector derivation
//!   before reaching the witness layer; see follow-up #5 in the plan
//!   for a stronger fixture.)

use std::path::PathBuf;

use zkap_service::{ArtifactSet, CircuitConfig, ProveCredential, ProveRequest, prove, setup};

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

/// Build a shape-valid (but cryptographically meaningless)
/// `ProveRequest` suitable for exercising the wiring of
/// [`prove`]. The JWT / RSA modulus / merkle path values are
/// deliberately bogus — the adapter accepts them long enough to reach
/// the witness layer, and the witness layer (or the R1CS preflight)
/// then rejects them. Useful only for `#[ignore]` smoke tests that
/// confirm the seam is wired up.
fn placeholder_prove_request(cfg: &CircuitConfig) -> ProveRequest {
    let k = cfg.k as usize;
    let anchor_len = (cfg.n - cfg.k + 1) as usize;
    let tree_height = cfg.tree_height as usize;

    let zero_fe = "0x00".to_string();
    // 256-byte RSA modulus (all 0xAA) base64-encoded — satisfies the
    // adapter's length check while remaining cryptographically junk.
    let rsa_mod_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0xAA_u8; 256])
    };

    ProveRequest {
        random: zero_fe.clone(),
        h_sign_user_op: zero_fe.clone(),
        anchor: vec![zero_fe.clone(); anchor_len],
        merkle_root: zero_fe.clone(),
        credentials: (0..k)
            .map(|_| ProveCredential {
                jwt: placeholder_jwt(),
                rsa_modulus_b64: rsa_mod_b64.clone(),
                merkle_path: vec![zero_fe.clone(); tree_height],
                merkle_leaf_idx: 0,
            })
            .collect(),
    }
}

/// `header.payload.signature` where:
/// - header decodes to `{"alg":"RS256","typ":"JWT"}`
/// - payload decodes to a minimal JSON object containing `aud`, `iss`, `sub` as strings
/// - signature decodes to 256 bytes of 0xAA (RSA-2048 length, junk content)
fn placeholder_jwt() -> String {
    use base64::Engine;
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"aud":"a","iss":"i","sub":"s","exp":1700000000}"#);
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xAA_u8; 256]);
    format!("{}.{}.{}", header_b64, payload_b64, sig_b64)
}

fn unique_tmp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("zkap_native_prove_{tag}_{nanos}"));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create scratch dir");
    p
}

/// Compile-time guard: [`prove`] signature carries no `&Manifest`, no
/// path arguments, no `&CircuitConfig`, and no rng — its trust input
/// is the `ArtifactSet` borrow, and proof-side randomness is a
/// crate-internal `OsRng`.
#[test]
fn prove_signature_is_no_manifest_no_paths_no_rng() {
    fn _check(
        set: &ArtifactSet,
        req: &ProveRequest,
    ) -> Result<zkap_service::ProveResponse, zkap_service::error::ApplicationError> {
        prove(set, req)
    }
    let _ = _check;
}

/// Runtime: in-memory `SetupOutput → ArtifactSet` round trip without
/// touching the manifest or the loader. Exercises the seam that
/// production callers reach through `ArtifactSet::load`.
///
/// `#[ignore]` because `service::setup` runs the full Groth16 trusted
/// setup (~4-5s under F1 config).
#[test]
#[ignore = "slow: drives the full Groth16 setup via service::setup (~4-5s F1 config)"]
fn artifact_set_in_memory_round_trip() {
    let cfg = test_config();
    let out_dir = unique_tmp_dir("from_artifact_set");

    let setup_output = setup(&cfg, &out_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");
    let set: ArtifactSet = setup_output.into_artifact_set();

    // Smoke-check the public input count via the bundled verifying key —
    // `ArtifactSet` exposes pub fields, so callers access vk / cfg
    // directly without an intermediate handle.
    assert!(
        !set.vk.gamma_abc_g1.is_empty(),
        "vk.gamma_abc_g1 must include the implicit-1 + public input wires"
    );
    assert_eq!(set.cfg.n, cfg.n);

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Wiring smoke (IRON RULE regression per Codex outside-voice): drive
/// the new free function [`prove`] through
/// `setup → into_artifact_set` and assert it rejects a placeholder
/// request.
///
/// **Limitation (acknowledged):** placeholder JWT + zeroed anchor
/// scalars can fail in
/// `prover::adapter::prove_request_to_internal` (selector derivation
/// at `adapter.rs:196`) BEFORE reaching `build_input` /
/// `into_circuit_input` / `synthesize_full_assignment` /
/// `ar1cs_prove`. This test therefore proves only that *something
/// downstream of the public `prove` API* rejects the request — it
/// does NOT prove that the witness / circuit / ar1cs layers were
/// actually exercised. A stronger "reaches-witness-layer" assertion
/// requires a real anchor + JWT fixture (see plan §8 Follow-up #5).
///
/// Replaces the deleted `prove_from_unverified_paths_for_testing_reaches_witness_layer`
/// which had the same limitation. The intent is regression coverage
/// of the public surface, not a fault-isolation test for the prove
/// stack.
#[test]
#[ignore = "slow: drives the full Groth16 setup via service::setup (~4-5s F1 config)"]
fn prove_rejects_invalid_request() {
    let cfg = test_config();
    let out_dir = unique_tmp_dir("prove_rejects");
    let setup_output = setup(&cfg, &out_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");
    let set: ArtifactSet = setup_output.into_artifact_set();
    let req = placeholder_prove_request(&cfg);
    let result = prove(&set, &req);
    assert!(
        result.is_err(),
        "prove must reject a placeholder request, got Ok"
    );
    let _ = std::fs::remove_dir_all(&out_dir);
}
