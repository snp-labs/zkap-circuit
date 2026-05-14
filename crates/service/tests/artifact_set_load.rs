//! Trust-boundary tamper tests for [`zkap_service::ArtifactSet::load`]
//! (Commit 6 of the 2026-05 ark-ar1cs boundary migration; collapsed
//! into a single `#[test]` in a CI follow-up).
//!
//! These assertions pin the contract that **the loader is the trust
//! gate** — every hash claim in the manifest is checked here, and
//! downstream [`Prover::prove`](zkap_service::Prover::prove) trusts
//! whatever the loader returned without re-validating.
//!
//! All cases run inside a **single** `#[test]` so that the heavy
//! `service::setup` invocation (~5–60 s depending on host) executes
//! exactly once per test binary regardless of runner. The previous
//! split-into-9-tests shape relied on `OnceLock<PathBuf>` for sharing,
//! which works under `cargo test` (single process per binary) but
//! breaks under `cargo nextest` (one process per `#[test]`); the
//! per-test setup multiplied 9× and exceeded the 180 s nextest
//! terminate-after threshold on GitHub Actions runners. Collapsing
//! into one test fixes the multiplication regardless of runner
//! semantics.
//!
//! Coverage is unchanged. Each tamper case still names the failing
//! manifest slot in its assertion message so a regression points at
//! the right field.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use ark_ar1cs::format::ArcsFile;
use circuit::types::F;
use zkap_service::manifest::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, SetupProvenance,
};
use zkap_service::{ArtifactError, ArtifactSet, CircuitConfig, setup};

// ──────────────────────────────────────────────────────────────────────────────
// Fixture helpers (no `OnceLock` — the single test owns the bundle)
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
// Single combined test — runs `service::setup` once, then exercises every
// tamper case in sequence. See module docs for the nextest-vs-cargo-test
// rationale.
// ──────────────────────────────────────────────────────────────────────────────

#[test]
fn artifact_set_load_trust_boundary() {
    // ── Stage 1: build a real CRS bundle on disk (the slow step) ───────────
    let dir = unique_tmp_dir("trust_boundary");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    setup(&test_config(), &dir, &mut ark_std::rand::rngs::OsRng, None)
        .expect("service::setup must succeed for F1 config");
    let canonical = build_canonical_manifest(&dir);

    // ── Stage 2: acceptance — canonical manifest matches the bundle ───────
    ArtifactSet::load(&canonical, &dir).expect("canonical manifest + matching bundle must load");

    // ── Stage 3: manifest-side tamper cases ──────────────────────────────
    //
    // Each case clones the canonical manifest, mutates exactly one hash
    // claim to a known-wrong value, and asserts that `ArtifactSet::load`
    // returns `HashMismatch` on the matching field. The mutator
    // closures keep the cases declarative; the loop body is the same
    // for every slot.
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

    // ── Stage 4: file-side tamper case ───────────────────────────────────
    //
    // Symmetric direction: keep the canonical manifest, mutate one byte
    // of pk.bin, and confirm `ArtifactSet::load` rejects via sha256
    // mismatch on the matching slot. Then call
    // `ArtifactSet::load_unverified` on the same tampered file — it
    // must NOT surface a `HashMismatch` (no validation by design); a
    // `Deserialize` error is acceptable because we mutated the byte
    // stream.
    let pk_path = dir.join("pk.bin");
    let mut bytes = std::fs::read(&pk_path).expect("read pk.bin");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&pk_path, &bytes).expect("rewrite pk.bin");

    let err = ArtifactSet::load(&canonical, &dir)
        .err()
        .expect("ArtifactSet::load must reject a tampered pk.bin");
    assert_hash_mismatch_on("artifacts.pk.sha256", err);

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
