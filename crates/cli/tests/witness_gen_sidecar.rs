//! Library-level tests for `build_witness_gen_sidecar`.
//!
//! Exercise the sidecar builder against a tiny fake `witness_gen.wasm` and
//! hand-built CRS bundle directories (each a real [`Manifest`] serialized
//! to `manifest.json`). The bin entry point is a thin clap wrapper over
//! this function, so covering the builder covers the gen logic.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use zkap_cli::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, SetupProvenance,
    build_witness_gen_sidecar,
};

const KNOWN_BLAKE3: &str = "f928dbaef3750a67a85f1ab0bc317fb5616cd1626affb2ecc2aa847f64fdd962";

/// A scratch directory under `std::env::temp_dir()` that cleans up on drop.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(test_name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "zkap_cli_sidecar_{}_{}_{}",
            test_name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sample_entry(path: &str, kind: &str) -> ArtifactEntry {
    ArtifactEntry {
        path: path.into(),
        sha256: "ab".repeat(32),
        size: 1024,
        kind: kind.into(),
        schema_owner: None,
        schema_ref: None,
    }
}

/// Build a schema-accurate [`Manifest`] carrying `ar1cs_blake3` via the
/// real [`ManifestBuilder`], so the written `manifest.json` parses exactly
/// as `build_witness_gen_sidecar` expects.
fn sample_manifest(ar1cs_blake3: &str) -> Manifest {
    ManifestBuilder::new("zkap-main-v1", "zkap-main-v1__deadbeef")
        .with_ar1cs_blake3(ar1cs_blake3.to_string())
        .with_shape(9, 896_800, 911_941)
        .with_public_input_names(vec!["hanchor".into(), "h_a".into()])
        .with_artifact(ArtifactKey::Ar1cs, sample_entry("circuit.ar1cs", "core"))
        .with_artifact(ArtifactKey::Pk, sample_entry("pk.bin", "core"))
        .with_artifact(ArtifactKey::Vk, sample_entry("vk.bin", "core"))
        .with_artifact(ArtifactKey::Pvk, sample_entry("pvk.bin", "core"))
        .with_artifact(
            ArtifactKey::CircuitConfig,
            sample_entry("config.json", "domain"),
        )
        .with_setup_provenance(SetupProvenance::OsRng)
        .with_build(BuildMetadata {
            circuit_repo: "https://github.com/snp-labs/zkap-circuit".into(),
            circuit_commit: "deadbeef".into(),
            ark_ar1cs_rev: "0370db0e".into(),
            rustc: "rustc 1.95.0".into(),
            built_at: "2026-06-09T00:00:00Z".into(),
        })
        .build()
        .expect("builder must succeed with full payload")
}

/// Write a CRS bundle directory containing a `manifest.json` whose
/// `ar1cs_blake3` is `ar1cs_blake3`. Returns the directory path.
fn write_bundle(scratch: &ScratchDir, name: &str, ar1cs_blake3: &str) -> PathBuf {
    let dir = scratch.join(name);
    fs::create_dir_all(&dir).expect("create bundle dir");
    let manifest = sample_manifest(ar1cs_blake3);
    let bytes = serde_json::to_vec_pretty(&manifest).expect("serialize manifest");
    fs::write(dir.join("manifest.json"), bytes).expect("write manifest.json");
    dir
}

fn write_fake_wasm(scratch: &ScratchDir) -> (PathBuf, String) {
    let wasm_path = scratch.join("witness_gen.wasm");
    let wasm_bytes = b"\0asm fake witness generator bytes";
    fs::write(&wasm_path, wasm_bytes).expect("write fake wasm");
    let sha = hex::encode(Sha256::digest(wasm_bytes));
    (wasm_path, sha)
}

/// Acceptance: the sidecar's `sha256` matches the fake wasm and
/// `compatible_ar1cs_blake3` is the known blake3 from the bundle manifest.
#[test]
fn builds_sidecar_from_wasm_and_bundle() {
    let scratch = ScratchDir::new("single");
    let (wasm_path, expected_sha) = write_fake_wasm(&scratch);
    let bundle = write_bundle(&scratch, "1-of-1", KNOWN_BLAKE3);

    let sidecar =
        build_witness_gen_sidecar(&wasm_path, "v0.1.1-rc.4".into(), &[bundle], None, None)
            .expect("sidecar must build");

    assert_eq!(sidecar.sha256, expected_sha, "sha256 must match fake wasm");
    assert_eq!(
        sidecar.compatible_ar1cs_blake3,
        vec![KNOWN_BLAKE3.to_string()],
        "compatible list must be the bundle's ar1cs_blake3"
    );
    assert_eq!(sidecar.version, "v0.1.1-rc.4");
    assert!(sidecar.circuit_commit.is_none());
    assert!(sidecar.circuit_id.is_none());
}

/// Acceptance: two bundle dirs with the same `ar1cs_blake3` dedupe to a
/// single compatible entry (first-seen order preserved).
#[test]
fn duplicate_bundle_blake3_dedupes() {
    let scratch = ScratchDir::new("dedupe");
    let (wasm_path, _sha) = write_fake_wasm(&scratch);
    let bundle_a = write_bundle(&scratch, "1-of-1", KNOWN_BLAKE3);
    let bundle_b = write_bundle(&scratch, "1-of-1-copy", KNOWN_BLAKE3);

    let sidecar = build_witness_gen_sidecar(
        &wasm_path,
        "v0.1.1-rc.4".into(),
        &[bundle_a, bundle_b],
        Some("deadbeef".into()),
        Some("zkap-main-v1".into()),
    )
    .expect("sidecar must build");

    assert_eq!(
        sidecar.compatible_ar1cs_blake3,
        vec![KNOWN_BLAKE3.to_string()],
        "identical blake3 across bundles must dedupe to one entry"
    );
    assert_eq!(sidecar.circuit_commit.as_deref(), Some("deadbeef"));
    assert_eq!(sidecar.circuit_id.as_deref(), Some("zkap-main-v1"));
}
