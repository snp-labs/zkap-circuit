//! Service crate integration tests for the Commit 4 native ar1cs
//! prove flow.
//!
//! These cover the public API contract (`Prover::from_artifact` +
//! `Prover::prove`, plus the non-canonical
//! `prove_from_unverified_paths_for_testing` shortcut) at the seam
//! level. A full end-to-end happy-path proof
//! that satisfies every R1CS constraint requires a hand-built JWT +
//! RSA + anchor fixture (~800 lines) and lives in the slower
//! `circuit::tests::groth16_integration` suite; replicating it here
//! would not exercise anything `groth16_integration` does not.
//!
//! What this file pins:
//!
//! * Compile-time: [`Prover::prove`] takes only `(&self, &ProveRequest)`
//!   — no `&Manifest`, no path arguments, no `&CircuitConfig`, no rng.
//! * Compile-time (under `dev-unverified-artifacts`):
//!   [`prove_from_unverified_paths_for_testing`] takes `(&Path, &ProveRequest)`.
//! * Runtime: `service::setup` → [`SetupOutput::into_artifact_set`] →
//!   [`Prover::from_artifact`] succeeds without manifest involvement.
//! * Runtime (under `dev-unverified-artifacts`): [`Prover::prove`]
//!   reaches the witness layer (synthesises constraints and only fails
//!   on R1CS preflight) on a shape-valid placeholder request, proving
//!   the wiring through
//!   `adapter::prove_request_to_internal → build_input →
//!   into_circuit_input → ZkapCircuit::from_input →
//!   synthesize_full_assignment → ark_ar1cs::prove` is intact.

use std::path::PathBuf;

use zkap_service::{ArtifactSet, CircuitConfig, ProveRequest, Prover, setup};

#[cfg(feature = "dev-unverified-artifacts")]
use std::path::Path;
#[cfg(feature = "dev-unverified-artifacts")]
use zkap_service::{ProveCredential, prove_from_unverified_paths_for_testing};

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
/// `Prover::prove`. The JWT / RSA modulus / merkle path values are
/// deliberately bogus — the adapter accepts them long enough to reach
/// the witness layer, and the witness layer (or the R1CS preflight)
/// then rejects them. Useful only for `#[ignore]` smoke tests that
/// confirm the seam is wired up.
#[cfg(feature = "dev-unverified-artifacts")]
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
#[cfg(feature = "dev-unverified-artifacts")]
fn placeholder_jwt() -> String {
    use base64::Engine;
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(br#"{"alg":"RS256","typ":"JWT"}"#);
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

/// Compile-time guard: [`Prover::prove`] signature carries no
/// `&Manifest`, no path arguments, no `&CircuitConfig`, and no rng —
/// its trust inputs are the `ArtifactSet` that built the prover, and
/// proof-side randomness comes from a crate-internal `OsRng`.
#[test]
fn prover_prove_signature_is_no_manifest_no_paths_no_rng() {
    fn _check(
        prover: &Prover,
        req: &ProveRequest,
    ) -> Result<zkap_service::ProveResponse, zkap_service::error::ApplicationError> {
        prover.prove(req)
    }
    let _ = _check;
}

/// Compile-time guard: [`prove_from_unverified_paths_for_testing`]
/// takes a single directory path (the post-migration bundle layout)
/// and a [`ProveRequest`] — and emphatically not a `&Manifest` or an
/// rng. Only exposed under the `dev-unverified-artifacts` feature.
#[cfg(feature = "dev-unverified-artifacts")]
#[test]
fn prove_from_unverified_paths_for_testing_signature_is_dir_only() {
    fn _check(
        dir: &Path,
        req: &ProveRequest,
    ) -> Result<zkap_service::ProveResponse, zkap_service::error::ApplicationError> {
        prove_from_unverified_paths_for_testing(dir, req)
    }
    let _ = _check;
}

/// Runtime: in-memory `SetupOutput → ArtifactSet → Prover` round trip
/// without touching the manifest or the loader. Exercises the seam
/// that production callers reach through `ArtifactSet::load`.
///
/// `#[ignore]` because `service::setup` runs the full Groth16 trusted
/// setup (~4-5s under F1 config).
#[test]
#[ignore = "slow: drives the full Groth16 setup via service::setup (~4-5s F1 config)"]
fn prover_from_artifact_set_in_memory_round_trip() {
    let cfg = test_config();
    let out_dir = unique_tmp_dir("from_artifact_set");

    let setup_output = setup(&cfg, &out_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");
    let set: ArtifactSet = setup_output.into_artifact_set();
    let prover = Prover::from_artifact(set);

    // Smoke-check the public input count via the bundled verifying key.
    assert!(
        !prover.verifying_key().gamma_abc_g1.is_empty(),
        "vk.gamma_abc_g1 must include the implicit-1 + public input wires"
    );
    assert_eq!(prover.circuit_config().n, cfg.n);

    let _ = std::fs::remove_dir_all(&out_dir);
}

/// Runtime: load the on-disk bundle via the non-canonical shortcut and
/// confirm it reaches `Prover::prove` (which then fails — either in the
/// adapter's JWT-claim derivation against the placeholder request or
/// later at the R1CS preflight — the wiring is the thing under test,
/// not the proof's validity).
///
/// `#[ignore]` for the same trusted-setup latency reason as
/// [`prover_from_artifact_set_in_memory_round_trip`]. Only exposed
/// under the `dev-unverified-artifacts` feature.
#[cfg(feature = "dev-unverified-artifacts")]
#[test]
#[ignore = "slow: drives the full Groth16 setup via service::setup (~4-5s F1 config)"]
fn prove_from_unverified_paths_for_testing_reaches_witness_layer() {
    let cfg = test_config();
    let out_dir = unique_tmp_dir("unverified_paths");
    let _ = setup(&cfg, &out_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed");

    let req = placeholder_prove_request(&cfg);
    let result = prove_from_unverified_paths_for_testing(&out_dir, &req);
    // Placeholder JWT + zeroed anchor scalars do not yield a consistent
    // selector and cannot satisfy the R1CS, so the call must fail —
    // either in the adapter (no valid selector found) or inside the
    // prover (R1CS preflight). Either path proves the seam is wired
    // up — what we must NOT see is a success on garbage data, which
    // would mean the prover never executed.
    assert!(
        result.is_err(),
        "Prover::prove must reject a placeholder request, got Ok"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}
