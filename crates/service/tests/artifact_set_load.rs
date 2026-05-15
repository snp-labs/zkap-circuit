//! Trust-boundary tamper tests for [`zkap_service::ArtifactSet::load`]
//! (Commit 6 of the 2026-05 ark-ar1cs boundary migration; rebuilt on a
//! toy-circuit fixture in a CI follow-up).
//!
//! These assertions pin the contract that **the loader is the trust
//! gate** — every hash claim in the manifest is checked here, and
//! downstream [`Prover::prove`](zkap_service::Prover::prove) trusts
//! whatever the loader returned without re-validating.
//!
//! ## Why a toy circuit, not `service::setup`
//!
//! The first iteration of this test ran the F1 `service::setup`
//! (`n=6, k=3, tree_height=4`) once and called `ArtifactSet::load`
//! ten times. Setup is ~45 s on GitHub Actions runners and each
//! `ArtifactSet::load` re-reads the 364 MB `pk.bin` and (for the
//! tamper cases that pass the `pk` sha256 step) re-runs
//! `ProvingKey<BN254>::deserialize_uncompressed` with subgroup checks
//! on millions of affine points — collectively well past the 180 s
//! nextest `terminate-after`.
//!
//! `ArtifactSet::load`'s hash gate is artifact-size-independent: the
//! same `sha256 → compare → reject` (or `body_blake3` for `.ar1cs`)
//! code path runs against KB-scale toy artifacts just as it does
//! against the F1 bundle. The test therefore swaps the F1 setup for
//! a single `Groth16::<Bn254>::setup(ToyCircuit, _)` invocation
//! (~ms) and writes the resulting tiny pk/vk/pvk plus a synthetic
//! `circuit.ar1cs` (built from `ConstraintMatrices::from_cs` over the
//! same toy constraint system). End-to-end test runtime drops from
//! 180+ s to under one second; coverage is identical.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use ark_ar1cs::format::{ArcsFile, ConstraintMatrices, CurveId};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, LinearCombination,
    OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{SeedableRng, rngs::StdRng};

use zkap_service::manifest::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, SetupProvenance,
};
use zkap_service::{ArtifactError, ArtifactSet};

// ──────────────────────────────────────────────────────────────────────────────
// Toy circuit + tiny CRS bundle fixture
// ──────────────────────────────────────────────────────────────────────────────

/// Smallest possible R1CS: `x * y = z`, with `z` public, `x` / `y`
/// witness. Mirrors the standalone helper in
/// `crates/service/tests/pvk_serialization.rs::ToyCircuit`. The
/// matrices are 1 row × 3 columns; the resulting pk / vk / pvk are
/// O(KB) and the resulting `circuit.ar1cs` is tens of bytes.
#[derive(Clone)]
struct ToyCircuit;

impl ConstraintSynthesizer<Fr> for ToyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let z = cs.new_input_variable(|| Ok(Fr::from(15u64)))?;
        let x = cs.new_witness_variable(|| Ok(Fr::from(3u64)))?;
        let y = cs.new_witness_variable(|| Ok(Fr::from(5u64)))?;
        cs.enforce_r1cs_constraint(
            || LinearCombination::from(x),
            || LinearCombination::from(y),
            || LinearCombination::from(z),
        )?;
        Ok(())
    }
}

/// Minimal `CircuitConfig` JSON that satisfies
/// `CircuitConfig::validate` (every field is at its valid floor). The
/// loader will parse this back via `serde_json::from_slice`, so the
/// content shape matters; the values do not — the prover code path
/// is not exercised by this test.
const MINIMAL_CONFIG_JSON: &str = r#"{
  "max_jwt_b64_len": 1,
  "max_payload_b64_len": 1,
  "max_aud_len": 1,
  "max_exp_len": 1,
  "max_iss_len": 1,
  "max_nonce_len": 1,
  "max_sub_len": 1,
  "n": 1,
  "k": 1,
  "tree_height": 1,
  "num_audience_limit": 1,
  "claims": ["aud"],
  "forbidden_string": "x"
}"#;

/// Stand-in for `Groth16Verifier.sol`. The loader sha256-checks it
/// when `manifest.artifacts.evm_verifier` is `Some` and never parses
/// the bytes, so any non-empty payload works as a fixture.
const STUB_EVM_VERIFIER: &str =
    "// stub Groth16Verifier.sol fixture for artifact_set_load tamper tests\n";

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

/// Synthesize a toy `circuit.ar1cs` envelope. Walks the same
/// matrices-extraction path `service::setup` uses, just over the toy
/// constraint system instead of `ZkapCircuit`.
fn build_toy_arcs() -> Vec<u8> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    ToyCircuit
        .generate_constraints(cs.clone())
        .expect("toy circuit synthesis");
    cs.finalize();
    let matrices = ConstraintMatrices::<Fr>::from_cs(&cs).expect("ConstraintMatrices::from_cs");
    let arcs = ArcsFile::<Fr>::from_matrices(CurveId::Bn254, &matrices);
    let mut buf: Vec<u8> = Vec::new();
    arcs.write(&mut buf).expect("ArcsFile::write");
    buf
}

/// Lay down the 7-file bundle in `dir`. All artifacts are KB-scale
/// or smaller, so the read/sha256/deserialize cost the loader pays
/// is microseconds per file.
fn lay_down_toy_bundle(dir: &Path) {
    // Tiny Groth16 setup over the toy circuit (~ms, not seconds).
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let (pk, vk) = Groth16::<Bn254>::setup(ToyCircuit, &mut rng).expect("toy Groth16 setup");
    let pvk = prepare_verifying_key(&vk);

    // pk / vk / pvk — same `serialize_uncompressed` shape `service::setup`
    // emits and `ArtifactSet::load` expects.
    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .expect("pk serialize_uncompressed");
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes)
        .expect("vk serialize_uncompressed");
    let mut pvk_bytes = Vec::new();
    pvk.serialize_uncompressed(&mut pvk_bytes)
        .expect("pvk serialize_uncompressed");

    std::fs::write(dir.join("circuit.ar1cs"), build_toy_arcs()).expect("write circuit.ar1cs");
    std::fs::write(dir.join("pk.bin"), &pk_bytes).expect("write pk.bin");
    std::fs::write(dir.join("vk.bin"), &vk_bytes).expect("write vk.bin");
    std::fs::write(dir.join("pvk.bin"), &pvk_bytes).expect("write pvk.bin");
    std::fs::write(dir.join("Groth16Verifier.sol"), STUB_EVM_VERIFIER)
        .expect("write Groth16Verifier.sol");
    std::fs::write(dir.join("config.json"), MINIMAL_CONFIG_JSON).expect("write config.json");
    // `manifest.json` is built by `build_canonical_manifest` *after* the
    // other six files exist — it carries their sha256s.
}

/// Build a `Manifest` whose `ar1cs_blake3` + every `artifacts.*.sha256`
/// matches the bytes laid down in `dir`. `CircuitConfig` value-set is
/// irrelevant — only the hash check is exercised.
fn build_canonical_manifest(dir: &Path) -> Manifest {
    let arcs_bytes = std::fs::read(dir.join("circuit.ar1cs")).expect("read circuit.ar1cs");
    let arcs = ArcsFile::<Fr>::read(&mut &arcs_bytes[..]).expect("parse circuit.ar1cs");
    let ar1cs_blake3 = hex::encode(arcs.body_blake3());

    ManifestBuilder::new("zkap-trust-boundary-test", "zkap-trust-boundary-test__toy")
        .with_ar1cs_blake3(ar1cs_blake3)
        .with_shape(2, 2, 1)
        .with_public_input_names(vec!["z".into()])
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

fn unique_tmp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "zkap-artifact-set-load-{tag}-{}-{}",
        std::process::id(),
        nanos
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// Single combined test — toy fixture is reused across all stages.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn artifact_set_load_trust_boundary() {
    // ── Stage 1: lay down the toy bundle (≈ ms) ─────────────────────────
    let dir = unique_tmp_dir("trust_boundary");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    lay_down_toy_bundle(&dir);
    let canonical = build_canonical_manifest(&dir);

    // ── Stage 2: acceptance — canonical manifest matches bundle ──────────
    ArtifactSet::load(&canonical, &dir).expect("canonical manifest + matching bundle must load");

    // ── Stage 3: manifest-side tamper cases ──────────────────────────────
    //
    // Each case clones the canonical manifest, mutates exactly one
    // hash claim, and asserts `ArtifactSet::load` returns `HashMismatch`
    // on the matching field. Loads are ms-scale because the toy
    // artifacts are KB-scale, so the loop is cheap even though it
    // re-traverses the full hash gate per iteration.
    type Mutator = Box<dyn FnOnce(&mut Manifest)>;
    let cases: Vec<(&'static str, Mutator)> = vec![
        (
            "ar1cs_blake3",
            Box::new(|m: &mut Manifest| m.ar1cs_blake3 = "0".repeat(64)),
        ),
        (
            "artifacts.ar1cs.sha256",
            Box::new(|m: &mut Manifest| m.artifacts.ar1cs.sha256 = "0".repeat(64)),
        ),
        (
            "artifacts.pk.sha256",
            Box::new(|m: &mut Manifest| m.artifacts.pk.sha256 = "0".repeat(64)),
        ),
        (
            "artifacts.vk.sha256",
            Box::new(|m: &mut Manifest| m.artifacts.vk.sha256 = "0".repeat(64)),
        ),
        (
            "artifacts.pvk.sha256",
            Box::new(|m: &mut Manifest| m.artifacts.pvk.sha256 = "0".repeat(64)),
        ),
        (
            "artifacts.circuit_config.sha256",
            Box::new(|m: &mut Manifest| m.artifacts.circuit_config.sha256 = "0".repeat(64)),
        ),
        (
            "artifacts.evm_verifier.sha256",
            Box::new(|m: &mut Manifest| {
                m.artifacts
                    .evm_verifier
                    .as_mut()
                    .expect("canonical manifest carries an evm_verifier entry")
                    .sha256 = "0".repeat(64);
            }),
        ),
    ];
    for (field, mutate) in cases {
        let mut tampered = canonical.clone();
        mutate(&mut tampered);
        let err = ArtifactSet::load(&tampered, &dir)
            .err()
            .unwrap_or_else(|| panic!("tampered manifest field `{field}` must reject"));
        assert_hash_mismatch_on(field, err);
    }

    // ── Stage 4: file-side tamper ────────────────────────────────────────
    //
    // Tamper `Groth16Verifier.sol` rather than `pk.bin`: the canonical
    // load path sha256-checks the EVM verifier (so a tampered byte
    // surfaces as `artifacts.evm_verifier.sha256` mismatch), while the
    // non-canonical loader (gated behind `dev-unverified-artifacts`)
    // does not touch the file at all (the unverified path only reads
    // `circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`, `config.json`).
    // That keeps the contract crisp: `load` rejects via `HashMismatch`;
    // the unverified loader, when compiled in, is silent — same
    // coverage as the F1-shape original, without risking a
    // `CanonicalDeserialize` failure on a flipped `pk.bin` byte.
    let sol_path = dir.join("Groth16Verifier.sol");
    let mut bytes = std::fs::read(&sol_path).expect("read Groth16Verifier.sol");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&sol_path, &bytes).expect("rewrite Groth16Verifier.sol");

    let err = ArtifactSet::load(&canonical, &dir)
        .err()
        .expect("ArtifactSet::load must reject a tampered Groth16Verifier.sol");
    assert_hash_mismatch_on("artifacts.evm_verifier.sha256", err);

    #[cfg(feature = "dev-unverified-artifacts")]
    ArtifactSet::load_without_manifest_verification_for_testing(&dir).expect(
        "ArtifactSet::load_without_manifest_verification_for_testing must not validate the tampered EVM verifier byte",
    );

    let _ = std::fs::remove_dir_all(&dir);
}
