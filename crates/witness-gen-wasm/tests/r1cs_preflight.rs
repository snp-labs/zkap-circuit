//! R1CS preflight test for §2.6 criterion #3.
//!
//! Loads the real `dist/1-of-1-wasm` CRS bundle via
//! [`zkap_service::ArtifactSet::load`], calls
//! [`zkap_witness_gen_wasm::synthesize_witness_bytes`] (the rlib path)
//! against the bundle's `proof_fixture.json` / `config.json`, then
//! `CanonicalDeserialize`s the output as `Vec<WitnessBundle>` and feeds
//! each `bundle.full_assignment` directly to `ark_ar1cs::prove`.
//!
//! A successful `prove` call proves that:
//!  - the wasm-path serialiser emits a wire format that round-trips
//!    through `CanonicalDeserialize`,
//!  - `bundle.full_assignment` satisfies the R1CS constraint system
//!    baked into `circuit.ar1cs`, and
//!  - the length invariant
//!    `full_assignment.len() == num_instance + num_witness` holds
//!    (otherwise `ark_ar1cs::prove` returns
//!    `ProverError::WitnessLengthMismatch`).
//!
//! # Prereqs
//!
//! The test reads from `dist/1-of-1-wasm/` relative to the workspace
//! root.  That bundle must already exist (it ships with the repo).
//! The `proof_fixture.json` inside it must also be present (it is
//! staged by `scripts/build-witness-wasm.sh` and committed in
//! `dist/1-of-1-wasm/`).
//!
//! # Run
//!
//! ```bash
//! cargo test --release -p zkap-witness-gen-wasm --test r1cs_preflight
//! ```
//!
//! `--release` is required: loading `pk.bin` (~363 MiB) and running
//! the Groth16 prover is very slow in debug mode.

use std::path::PathBuf;

use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::OsRng;

use zkap_service::{
    ArtifactSet, CircuitConfig, ProveCredential, ProveRequest, WitnessBundle, manifest::Manifest,
};
use zkap_witness_gen_wasm::synthesize_witness_bytes;

// ── camelCase mirror of `dist/<bundle>/proof_fixture.json` ────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofFixtureFile {
    request: JsProveRequest,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsProveRequest {
    random: String,
    h_sign_user_op: String,
    anchor: Vec<String>,
    merkle_root: String,
    credentials: Vec<JsProveCredential>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsProveCredential {
    jwt: String,
    rsa_modulus_b64: String,
    merkle_path: Vec<String>,
    merkle_leaf_idx: u64,
}

impl From<JsProveRequest> for ProveRequest {
    fn from(v: JsProveRequest) -> Self {
        ProveRequest {
            random: v.random,
            h_sign_user_op: v.h_sign_user_op,
            anchor: v.anchor,
            merkle_root: v.merkle_root,
            credentials: v.credentials.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<JsProveCredential> for ProveCredential {
    fn from(v: JsProveCredential) -> Self {
        ProveCredential {
            jwt: v.jwt,
            rsa_modulus_b64: v.rsa_modulus_b64,
            merkle_path: v.merkle_path,
            merkle_leaf_idx: v.merkle_leaf_idx,
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Resolve the workspace root from CARGO_MANIFEST_DIR
/// (`crates/witness-gen-wasm`) by walking two levels up.
fn workspace_root() -> PathBuf {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/witness-gen-wasm")
        .to_path_buf()
}

/// Load `(manifest, bundle_dir)` for the default `1-of-1-wasm` bundle.
fn load_bundle() -> (Manifest, PathBuf) {
    let bundle_dir = workspace_root().join("dist").join("1-of-1-wasm");
    let manifest_path = bundle_dir.join("manifest.json");
    assert!(
        manifest_path.exists(),
        "manifest.json missing at {} — is the bundle checked in?",
        manifest_path.display()
    );
    let bytes = std::fs::read(&manifest_path).unwrap_or_else(|e| panic!("read manifest.json: {e}"));
    let manifest: Manifest =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse manifest.json: {e}"));
    (manifest, bundle_dir)
}

/// Load `(cfg_bytes, req_bytes)` from the bundle's `config.json` and
/// `proof_fixture.json` — the same pair the `oracle` example stages.
fn load_fixture_json(bundle_dir: &std::path::Path) -> (Vec<u8>, Vec<u8>) {
    let cfg_bytes = std::fs::read(bundle_dir.join("config.json")).expect("read config.json");
    // Validate that cfg_bytes parses as CircuitConfig.
    let _cfg: CircuitConfig =
        serde_json::from_slice(&cfg_bytes).expect("parse config.json as CircuitConfig");

    let fixture_bytes = std::fs::read(bundle_dir.join("proof_fixture.json")).expect(
        "read proof_fixture.json — run \
             `cargo test --release -p zkap-service --test gen_proof_fixture \
             -- --ignored --nocapture` with ZKAP_PROOF_MANIFEST_DIR set \
             if it is missing",
    );
    let fixture: ProofFixtureFile =
        serde_json::from_slice(&fixture_bytes).expect("parse proof_fixture.json (camelCase)");
    let request: ProveRequest = fixture.request.into();
    let req_bytes = serde_json::to_vec(&request).expect("serialize ProveRequest snake_case");
    (cfg_bytes, req_bytes)
}

// ── test ──────────────────────────────────────────────────────────────────────

/// §2.6 criterion #3: the rlib witness bytes, when deserialized as
/// `Vec<WitnessBundle>` and fed to `ark_ar1cs::prove`, produce a valid
/// proof against the matching `pk.bin` + `circuit.ar1cs`.
#[test]
fn r1cs_preflight_1_of_1_wasm() {
    let (manifest, bundle_dir) = load_bundle();
    let (cfg_bytes, req_bytes) = load_fixture_json(&bundle_dir);

    // ── synthesize via rlib path ───────────────────────────────────────
    let output_bytes = synthesize_witness_bytes(&req_bytes, &cfg_bytes)
        .expect("synthesize_witness_bytes must succeed against the bundle's fixture");
    assert!(
        !output_bytes.is_empty(),
        "synthesize_witness_bytes returned empty output"
    );

    // ── deserialize Vec<WitnessBundle> ────────────────────────────────
    let bundles = Vec::<WitnessBundle>::deserialize_uncompressed(&output_bytes[..])
        .expect("CanonicalDeserialize Vec<WitnessBundle> must succeed");
    assert!(
        !bundles.is_empty(),
        "Vec<WitnessBundle> deserialized to empty — expected at least 1 credential"
    );

    // ── load ArtifactSet (trust-gated by manifest sha256 / ar1cs_blake3) ──
    let artifact = ArtifactSet::load(&manifest, &bundle_dir, None)
        .expect("ArtifactSet::load must succeed for the canonical bundle");

    // ── R1CS preflight: prove each bundle ─────────────────────────────
    let mut rng = OsRng;
    for (i, bundle) in bundles.iter().enumerate() {
        // Length invariant: full_assignment.len() == num_instance + num_witness
        let expected_len = (artifact.arcs.header.num_instance_variables
            + artifact.arcs.header.num_witness_variables) as usize;
        assert_eq!(
            bundle.full_assignment.len(),
            expected_len,
            "bundle[{i}]: full_assignment.len()={} but arcs expects {expected_len}",
            bundle.full_assignment.len()
        );
        // F::ONE invariant
        use circuit::types::F;
        assert_eq!(
            bundle.full_assignment[0],
            F::from(1u64),
            "bundle[{i}]: full_assignment[0] must be F::ONE"
        );
        // public_inputs length invariant
        assert_eq!(
            bundle.public_inputs.len(),
            8,
            "bundle[{i}]: public_inputs.len()={} but expected 8",
            bundle.public_inputs.len()
        );

        // Actual R1CS preflight: passes iff all constraints are satisfied.
        ark_ar1cs::prove::<circuit::types::BN254, _>(
            &artifact.pk,
            &artifact.arcs,
            &bundle.full_assignment,
            &mut rng,
        )
        .unwrap_or_else(|e| {
            panic!(
                "ark_ar1cs::prove failed for bundle[{i}]: {e}\n\
                 full_assignment.len()={}, expected={expected_len}",
                bundle.full_assignment.len()
            )
        });
    }

    eprintln!(
        "r1cs_preflight: {} bundle(s) proved successfully against dist/1-of-1-wasm",
        bundles.len()
    );
}
