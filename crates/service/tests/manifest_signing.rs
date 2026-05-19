//! Tests for the F5 manifest signing surface — `sign_manifest` /
//! `verify_manifest` / `ArtifactSet::load` with `verifying_key`.
//!
//! Builds the trust-boundary fixture the same way
//! `artifact_set_load.rs` does (toy Groth16 setup over `x * y = z`),
//! so the per-test runtime stays sub-second. Every signature
//! variant — happy path, wrong key, missing signature, tampered
//! payload, soft-enforce permutations through `ArtifactSet::load` —
//! is exercised against the same in-memory fixture.

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
use ed25519_dalek::{SigningKey, VerifyingKey};

use zkap_service::manifest::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, ManifestError,
    SetupProvenance, sign_manifest, verify_manifest,
};
use zkap_service::{ArtifactError, ArtifactSet};

// ──────────────────────────────────────────────────────────────────────────────
// Toy circuit + fixture — mirrors `artifact_set_load.rs`. The fast
// path (Groth16 over `x*y = z`, KB-scale artifacts) keeps every
// `ArtifactSet::load` invocation in the sub-second band even at
// `cargo test --release`.
// ──────────────────────────────────────────────────────────────────────────────

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

const STUB_EVM_VERIFIER: &str = "// stub Groth16Verifier.sol fixture for manifest_signing tests\n";

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

fn lay_down_toy_bundle(dir: &Path) {
    let mut rng = StdRng::seed_from_u64(0xCAFE_F00D_DEAD_BEEF);
    let (pk, vk) = Groth16::<Bn254>::setup(ToyCircuit, &mut rng).expect("toy Groth16 setup");
    let pvk = prepare_verifying_key(&vk);

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
}

fn build_canonical_manifest(dir: &Path) -> Manifest {
    let arcs_bytes = std::fs::read(dir.join("circuit.ar1cs")).expect("read circuit.ar1cs");
    let arcs = ArcsFile::<Fr>::read(&mut &arcs_bytes[..]).expect("parse circuit.ar1cs");
    let ar1cs_blake3 = hex::encode(arcs.body_blake3());

    ManifestBuilder::new(
        "zkap-manifest-signing-test",
        "zkap-manifest-signing-test__toy",
    )
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
        built_at: "2026-05-19T00:00:00Z".into(),
    })
    .build()
    .expect("manifest builder must accept full payload")
}

fn unique_tmp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "zkap-manifest-signing-{tag}-{}-{}",
        std::process::id(),
        nanos
    ))
}

/// Deterministic key generator — `SigningKey::from_bytes([seed; 32])`
/// so tests reproduce identically across runs without needing to
/// invoke `OsRng`.
fn fresh_signing_key(seed_byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed_byte; 32])
}

fn fresh_verifying_key(signing_key: &SigningKey) -> VerifyingKey {
    signing_key.verifying_key()
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = unique_tmp_dir(tag);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        lay_down_toy_bundle(&dir);
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }

    fn manifest(&self) -> Manifest {
        build_canonical_manifest(self.path())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

/// `sign_manifest` + `verify_manifest` round-trip against the
/// matching public key.
#[test]
fn signed_manifest_verifies_with_correct_key() {
    let scratch = Scratch::new("verify_ok");
    let mut manifest = scratch.manifest();
    let sk = fresh_signing_key(0x11);
    sign_manifest(&mut manifest, &sk).expect("sign");
    let vk = fresh_verifying_key(&sk);
    verify_manifest(&manifest, &vk).expect("verify must accept matching key");
    assert!(
        manifest.signature.is_some(),
        "signed manifest must carry a signature"
    );
}

/// Signing with key A and verifying with key B rejects.
#[test]
fn signed_manifest_rejects_wrong_key() {
    let scratch = Scratch::new("wrong_key");
    let mut manifest = scratch.manifest();
    let sk_a = fresh_signing_key(0x22);
    sign_manifest(&mut manifest, &sk_a).expect("sign");

    let sk_b = fresh_signing_key(0x33);
    let vk_b = fresh_verifying_key(&sk_b);
    let err = verify_manifest(&manifest, &vk_b).expect_err("wrong key must reject");
    assert!(
        matches!(err, ManifestError::SignatureInvalid(_)),
        "expected SignatureInvalid, got {err:?}"
    );
}

/// Mutating a hash field after signing invalidates the signature.
#[test]
fn tampered_signed_manifest_rejected() {
    let scratch = Scratch::new("tampered");
    let mut manifest = scratch.manifest();
    let sk = fresh_signing_key(0x44);
    sign_manifest(&mut manifest, &sk).expect("sign");
    let vk = fresh_verifying_key(&sk);
    // Signature is fine before tampering.
    verify_manifest(&manifest, &vk).expect("baseline verify");

    // Tamper one hex char of an inner sha256 (still hex-shaped, still
    // 64 chars). The signature must reject because the signed payload
    // includes this field.
    let pk_sha = &mut manifest.artifacts.pk.sha256;
    let last = pk_sha.len() - 1;
    let mut chars: Vec<char> = pk_sha.chars().collect();
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    *pk_sha = chars.into_iter().collect();

    let err = verify_manifest(&manifest, &vk).expect_err("tampered manifest must reject");
    assert!(
        matches!(err, ManifestError::SignatureInvalid(_)),
        "expected SignatureInvalid, got {err:?}"
    );
}

/// `verify_manifest` returns `SignatureMissing` when the manifest
/// has `signature: None` but the caller supplied a key.
#[test]
fn unsigned_manifest_with_key_required_rejected() {
    let scratch = Scratch::new("unsigned_with_key");
    let manifest = scratch.manifest();
    assert!(manifest.signature.is_none(), "fixture starts unsigned");

    let sk = fresh_signing_key(0x55);
    let vk = fresh_verifying_key(&sk);
    let err = verify_manifest(&manifest, &vk).expect_err("missing signature must reject");
    assert!(
        matches!(err, ManifestError::SignatureMissing),
        "expected SignatureMissing, got {err:?}"
    );
}

/// **Backward-compat gate**: an unsigned bundle still loads when the
/// caller passes `verifying_key = None` — preserves the pre-F5
/// behaviour.
#[test]
fn unsigned_manifest_with_no_key_loads_ok() {
    let scratch = Scratch::new("unsigned_no_key");
    let manifest = scratch.manifest();
    assert!(manifest.signature.is_none());
    ArtifactSet::load(&manifest, scratch.path(), None)
        .expect("unsigned manifest + no key must still load");
}

/// A signed bundle still loads when the caller passes
/// `verifying_key = None` — explicit caller opt-out of verification
/// is honoured.
#[test]
fn signed_manifest_with_no_key_loads_ok() {
    let scratch = Scratch::new("signed_no_key");
    let mut manifest = scratch.manifest();
    let sk = fresh_signing_key(0x66);
    sign_manifest(&mut manifest, &sk).expect("sign");

    ArtifactSet::load(&manifest, scratch.path(), None)
        .expect("signed manifest with no key must still load (caller opted out)");
}

/// Full happy path: signed bundle + matching key through
/// `ArtifactSet::load`.
#[test]
fn signed_manifest_with_key_loads_ok() {
    let scratch = Scratch::new("signed_with_key");
    let mut manifest = scratch.manifest();
    let sk = fresh_signing_key(0x77);
    sign_manifest(&mut manifest, &sk).expect("sign");
    let vk = fresh_verifying_key(&sk);

    ArtifactSet::load(&manifest, scratch.path(), Some(&vk))
        .expect("signed manifest + correct key must load");
}

/// Wrong-key load surfaces as `ArtifactError::Signature(SignatureInvalid)`.
#[test]
fn signed_manifest_with_wrong_key_load_rejected() {
    let scratch = Scratch::new("wrong_key_load");
    let mut manifest = scratch.manifest();
    let sk_a = fresh_signing_key(0x88);
    sign_manifest(&mut manifest, &sk_a).expect("sign");

    let sk_b = fresh_signing_key(0x99);
    let vk_b = fresh_verifying_key(&sk_b);

    let result = ArtifactSet::load(&manifest, scratch.path(), Some(&vk_b));
    match result {
        Ok(_) => panic!("wrong key must reject load"),
        Err(ArtifactError::Signature(ManifestError::SignatureInvalid(_))) => {}
        Err(other) => panic!("expected Signature(SignatureInvalid), got {other:?}"),
    }
}

/// **Critical invariant**: `canonical_signing_bytes` must produce
/// the same bytes whether `signature = None` or
/// `signature = Some(_)` — anything else breaks the property that
/// signing and verifying agree on the payload.
#[test]
fn canonical_bytes_stable_across_signature_states() {
    let scratch = Scratch::new("canonical_stable");
    let unsigned = scratch.manifest();
    let bytes_unsigned = unsigned
        .canonical_signing_bytes()
        .expect("canonical bytes (unsigned)");

    let mut signed = unsigned.clone();
    let sk = fresh_signing_key(0xAA);
    sign_manifest(&mut signed, &sk).expect("sign");
    assert!(signed.signature.is_some(), "post-sign signature present");

    let bytes_signed = signed
        .canonical_signing_bytes()
        .expect("canonical bytes (signed)");

    assert_eq!(
        bytes_unsigned, bytes_signed,
        "canonical_signing_bytes must ignore the `signature` slot"
    );
}
