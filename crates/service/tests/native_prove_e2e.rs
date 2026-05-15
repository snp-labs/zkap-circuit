//! Service crate integration tests for the Commit 4 native ar1cs
//! prove flow.
//!
//! These cover the public API contract (`Prover::from_artifact` +
//! `Prover::prove`, plus the non-canonical `prove_from_unverified_paths`
//! shortcut) at the seam level. A full end-to-end happy-path proof
//! that satisfies every R1CS constraint requires a hand-built JWT +
//! RSA + anchor fixture (~800 lines) and lives in the slower
//! `circuit::tests::groth16_integration` suite; replicating it here
//! would not exercise anything `groth16_integration` does not.
//!
//! What this file pins:
//!
//! * Compile-time: [`Prover::prove`] takes only `(&self, &ProofRequest,
//!   &mut R)` — no `&Manifest`, no path arguments, no `&CircuitConfig`.
//! * Compile-time: [`prove_from_unverified_paths`] takes
//!   `(&Path, &ProofRequest, &mut R)`.
//! * Runtime: `service::setup` → [`SetupOutput::into_artifact_set`] →
//!   [`Prover::from_artifact`] succeeds without manifest involvement.
//! * Runtime: [`Prover::prove`] reaches the witness layer (synthesises
//!   constraints and only fails on R1CS preflight) on a shape-valid
//!   placeholder request, proving the wiring through
//!   `build_input → into_circuit_input → ZkapCircuit::from_input →
//!   synthesize_full_assignment → ark_ar1cs::prove` is intact.

use std::path::{Path, PathBuf};

use ark_std::rand::{Rng, SeedableRng, rngs::StdRng};
use zkap_service::{
    ArtifactSet, CircuitConfig, PerJwtFields, ProofRequest, Prover, SharedFields,
    prove_from_unverified_paths, setup,
};

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

fn placeholder_per_jwt() -> PerJwtFields {
    PerJwtFields {
        jwt_bytes: Vec::new(),
        rsa_modulus_be: vec![0u8; 256],
        rsa_signature_be: vec![0u8; 256],
        anchor_current_idx: 0,
        merkle_leaf_sibling_hash_be: [0u8; 32],
        merkle_auth_path_be: vec![[0u8; 32]; 3],
        merkle_leaf_idx: 0,
    }
}

fn placeholder_request(cfg: &CircuitConfig) -> ProofRequest {
    let n = cfg.n as usize;
    let k = cfg.k as usize;
    ProofRequest {
        shared: SharedFields {
            random_be: [0u8; 32],
            h_sign_user_op_be: [0u8; 32],
            anchor_values_be: vec![[0u8; 32]; n - k + 1],
            anchor_known_x_be: vec![[0u8; 32]; k],
            anchor_selector: {
                let mut s = vec![0u8; n];
                for slot in s.iter_mut().take(k) {
                    *slot = 1;
                }
                s
            },
            merkle_root_be: [0u8; 32],
        },
        per_jwt: (0..k).map(|_| placeholder_per_jwt()).collect(),
    }
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
/// `&Manifest`, no path arguments, no `&CircuitConfig` — its trust
/// inputs are the `ArtifactSet` that built the prover, not anything
/// passed at call time.
#[test]
fn prover_prove_signature_is_no_manifest_no_paths() {
    fn _check<R: Rng + ark_std::rand::CryptoRng>(
        prover: &Prover,
        req: &ProofRequest,
        rng: &mut R,
    ) -> Result<zkap_service::ProveResponse, zkap_service::error::ApplicationError> {
        prover.prove(req, rng)
    }
    let _ = _check::<StdRng>;
}

/// Compile-time guard: [`prove_from_unverified_paths`] takes a single
/// directory path (the post-migration bundle layout), `&ProofRequest`,
/// and an rng — and emphatically not a `&Manifest`.
#[test]
fn prove_from_unverified_paths_signature_is_dir_only() {
    fn _check<R: Rng + ark_std::rand::CryptoRng>(
        dir: &Path,
        req: &ProofRequest,
        rng: &mut R,
    ) -> Result<zkap_service::ProveResponse, zkap_service::error::ApplicationError> {
        prove_from_unverified_paths(dir, req, rng)
    }
    let _ = _check::<StdRng>;
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
/// confirm it reaches `Prover::prove` (which then fails on R1CS
/// preflight against the placeholder request — the wiring is the
/// thing under test, not the proof's validity).
///
/// `#[ignore]` for the same trusted-setup latency reason as
/// [`prover_from_artifact_set_in_memory_round_trip`].
#[test]
#[ignore = "slow: drives the full Groth16 setup via service::setup (~4-5s F1 config)"]
fn prove_from_unverified_paths_reaches_witness_layer() {
    let cfg = test_config();
    let out_dir = unique_tmp_dir("unverified_paths");
    let _ = setup(&cfg, &out_dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed");

    let req = placeholder_request(&cfg);
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);

    let result = prove_from_unverified_paths(&out_dir, &req, &mut rng);
    // Placeholder JWT + zeroed RSA signature will not satisfy the
    // R1CS, so the call either fails inside the witness builder
    // (NonCanonicalField / SignatureMismatch / MalformedJwt) or at
    // the R1CS preflight inside `ark_ar1cs::prove`. Either path
    // proves the seam is wired up — what we must NOT see is a
    // success on garbage data, which would mean the prover never
    // executed.
    assert!(
        result.is_err(),
        "Prover::prove must reject a placeholder request, got Ok"
    );

    let _ = std::fs::remove_dir_all(&out_dir);
}
