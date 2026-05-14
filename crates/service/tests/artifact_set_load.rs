//! Trust-boundary tamper tests for [`zkap_service::ArtifactSet::load`]
//! (Commit 6 of the 2026-05 ark-ar1cs boundary migration).
//!
//! These tests pin the contract that **the loader is the trust gate** —
//! every hash claim in the manifest is checked here, and downstream
//! [`Prover::prove`](zkap_service::Prover::prove) trusts whatever the
//! loader returned without re-validating. The test file does this by
//!
//! 1. running `service::setup` once to materialise a real CRS bundle
//!    on disk (cached across all tests in this file via `OnceLock`),
//! 2. computing canonical sha256 / `ar1cs_blake3` values from the
//!    on-disk bytes,
//! 3. assembling a [`Manifest`] in-memory whose hashes match those
//!    bytes, and
//! 4. asserting [`ArtifactSet::load`] succeeds against that manifest,
//!    then per-test cloning the manifest, mutating one hash claim,
//!    and asserting `Err(HashMismatch)` with the right `field` slot.
//!
//! Tampering the **manifest** (the trust input) rather than the on-disk
//! bytes exercises exactly the same code path
//! (`recompute → compare → reject`) and lets every tamper variant share
//! the single `service::setup` invocation. A separate test mutates a
//! file byte to confirm the symmetric direction (good manifest +
//! tampered file → reject) and that
//! [`ArtifactSet::load_unverified`] tolerates the same tampered file
//! (no validation by design).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use ark_ar1cs::format::ArcsFile;
use circuit::types::F;
use zkap_service::manifest::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, SetupProvenance,
};
use zkap_service::{ArtifactError, ArtifactSet, CircuitConfig, setup};

// ──────────────────────────────────────────────────────────────────────────────
// Shared setup fixture (slow: one Groth16 trusted setup per test binary)
// ──────────────────────────────────────────────────────────────────────────────

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

/// Lazily build the F1 CRS bundle once per process; reused by every
/// test in this file. ~5s on the first call, free afterward.
fn shared_bundle_dir() -> &'static Path {
    static CACHE: OnceLock<PathBuf> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "zkap-artifact-set-load-{}-{}",
                std::process::id(),
                nanos
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            setup(&test_config(), &dir, &mut ark_std::rand::rngs::OsRng, None)
                .expect("service::setup must succeed for F1 config");
            dir
        })
        .as_path()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn artifact_entry(dir: &Path, file: &str, kind: &str) -> ArtifactEntry {
    let bytes = std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"));
    ArtifactEntry {
        path: file.into(),
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
        kind: kind.into(),
        schema_owner: None,
        schema_ref: None,
    }
}

fn build_canonical_manifest(dir: &Path) -> Manifest {
    let arcs_bytes = std::fs::read(dir.join("circuit.ar1cs")).expect("read circuit.ar1cs");
    let arcs = ArcsFile::<F>::read(&mut &arcs_bytes[..]).expect("parse circuit.ar1cs after setup");
    let ar1cs_blake3 = hex::encode(arcs.body_blake3());

    ManifestBuilder::new(
        "zkap-trust-boundary-test",
        "zkap-trust-boundary-test__commit6",
    )
    .with_ar1cs_blake3(ar1cs_blake3)
    .with_shape(9, 1, 1)
    .with_public_input_names(vec![
        "hanchor".into(),
        "h_a".into(),
        "root".into(),
        "h_sign_user_op".into(),
        "jwt_exp".into(),
        "partial_rhs".into(),
        "lhs".into(),
        "h_aud_list".into(),
    ])
    .with_artifact(
        ArtifactKey::Ar1cs,
        artifact_entry(dir, "circuit.ar1cs", "core"),
    )
    .with_artifact(ArtifactKey::Pk, artifact_entry(dir, "pk.bin", "core"))
    .with_artifact(ArtifactKey::Vk, artifact_entry(dir, "vk.bin", "core"))
    .with_artifact(ArtifactKey::Pvk, artifact_entry(dir, "pvk.bin", "core"))
    .with_artifact(
        ArtifactKey::EvmVerifier,
        artifact_entry(dir, "Groth16Verifier.sol", "domain-optional"),
    )
    .with_artifact(
        ArtifactKey::CircuitConfig,
        artifact_entry(dir, "config.json", "domain"),
    )
    .with_setup_provenance(SetupProvenance::OsRng)
    .with_build(BuildMetadata {
        circuit_repo: "https://github.com/snp-labs/zkap-circuit".into(),
        circuit_commit: "test".into(),
        ark_ar1cs_rev: "test".into(),
        rustc: "test".into(),
        built_at: "2026-05-14T00:00:00Z".into(),
    })
    .build()
    .expect("manifest builder must accept full payload")
}

fn assert_hash_mismatch_on(field: &str, err: ArtifactError) {
    match err {
        ArtifactError::HashMismatch {
            field: actual_field,
            ..
        } => assert_eq!(
            actual_field, field,
            "expected HashMismatch on field `{field}`, got `{actual_field}`"
        ),
        other => panic!("expected HashMismatch on `{field}`, got {other:?}"),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Acceptance: valid bundle + matching manifest loads cleanly
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn load_accepts_canonical_bundle() {
    let dir = shared_bundle_dir();
    let manifest = build_canonical_manifest(dir);
    ArtifactSet::load(&manifest, dir).expect("canonical manifest + matching bundle must load");
}

// ──────────────────────────────────────────────────────────────────────────────
// Manifest-side tamper tests — every claim in the manifest is rejected
// when it disagrees with the on-disk bytes.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn load_rejects_tampered_ar1cs_blake3() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    manifest.ar1cs_blake3 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered ar1cs_blake3 must reject");
    assert_hash_mismatch_on("ar1cs_blake3", err);
}

#[test]
fn load_rejects_tampered_ar1cs_sha256() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    manifest.artifacts.ar1cs.sha256 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered artifacts.ar1cs.sha256 must reject");
    assert_hash_mismatch_on("artifacts.ar1cs.sha256", err);
}

#[test]
fn load_rejects_tampered_pk_sha256() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    manifest.artifacts.pk.sha256 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered artifacts.pk.sha256 must reject");
    assert_hash_mismatch_on("artifacts.pk.sha256", err);
}

#[test]
fn load_rejects_tampered_vk_sha256() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    manifest.artifacts.vk.sha256 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered artifacts.vk.sha256 must reject");
    assert_hash_mismatch_on("artifacts.vk.sha256", err);
}

#[test]
fn load_rejects_tampered_pvk_sha256() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    manifest.artifacts.pvk.sha256 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered artifacts.pvk.sha256 must reject");
    assert_hash_mismatch_on("artifacts.pvk.sha256", err);
}

#[test]
fn load_rejects_tampered_circuit_config_sha256() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    manifest.artifacts.circuit_config.sha256 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered artifacts.circuit_config.sha256 must reject");
    assert_hash_mismatch_on("artifacts.circuit_config.sha256", err);
}

#[test]
fn load_rejects_tampered_evm_verifier_sha256() {
    let dir = shared_bundle_dir();
    let mut manifest = build_canonical_manifest(dir);
    let entry = manifest
        .artifacts
        .evm_verifier
        .as_mut()
        .expect("canonical manifest carries an evm_verifier entry");
    entry.sha256 = "0".repeat(64);
    let err = ArtifactSet::load(&manifest, dir)
        .err()
        .expect("tampered artifacts.evm_verifier.sha256 must reject");
    assert_hash_mismatch_on("artifacts.evm_verifier.sha256", err);
}

// ──────────────────────────────────────────────────────────────────────────────
// File-side tamper test — symmetric direction: good manifest + tampered
// on-disk file → reject; same tampered file is accepted by the
// non-canonical `load_unverified` shortcut (no validation by design).
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn load_rejects_tampered_pk_file_but_load_unverified_accepts_it() {
    // Use a private bundle so we don't poison `shared_bundle_dir()`.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "zkap-artifact-set-load-tamper-pk-{}-{}",
        std::process::id(),
        nanos
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    setup(&test_config(), &dir, &mut ark_std::rand::rngs::OsRng, None).expect("setup() failed");

    // Build canonical manifest before mutation so the manifest's claims
    // describe the pre-tamper bytes.
    let manifest = build_canonical_manifest(&dir);

    // Flip the last byte of pk.bin — keeps file readable as bytes but
    // breaks both sha256 and CanonicalDeserialize.
    let pk_path = dir.join("pk.bin");
    let mut bytes = std::fs::read(&pk_path).expect("read pk.bin");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&pk_path, &bytes).expect("rewrite pk.bin");

    // Canonical load: must reject (sha256 mismatch surfaces first,
    // before any deserialize attempt).
    let err = ArtifactSet::load(&manifest, &dir)
        .err()
        .expect("ArtifactSet::load must reject a tampered pk.bin");
    assert_hash_mismatch_on("artifacts.pk.sha256", err);

    // Non-canonical shortcut: silent acceptance is the documented
    // contract — load_unverified intentionally skips hash gating.
    // The deserialize step inside load_unverified may still fail (we
    // mutated the byte stream), so we accept either Ok or a
    // Deserialize error — what we MUST NOT see is a HashMismatch
    // (load_unverified does not run the gate).
    match ArtifactSet::load_unverified(&dir) {
        Ok(_) => {}
        Err(ArtifactError::Deserialize { what, .. }) => {
            assert_eq!(
                what, "pk",
                "deserialize failure must name the tampered slot"
            );
        }
        Err(other) => panic!("load_unverified must not surface a HashMismatch; got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
