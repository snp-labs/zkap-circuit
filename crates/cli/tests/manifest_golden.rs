// File-scoped unsafe allow: `EpochGuard` mutates `SOURCE_DATE_EPOCH` via
// `std::env::set_var`, which Rust 1.83+ marks `unsafe`. Library code
// stays under the workspace `unsafe_code = "deny"` lint.
#![allow(unsafe_code)]

//! Manifest reproducibility tests for the post-migration v1 schema.
//!
//! Builder-level instead of end-to-end `generate_setup` because Groth16
//! setup is ~2 minutes; the byte-reproducibility property the migration
//! plan asks for is fully exercised at the `ManifestBuilder` boundary.
//!
//! The pre-migration schema had `artifacts.{arzkey, wasm}` entries and
//! a `WasmAbi` block. Those are removed in the 2026-05 ark-ar1cs
//! boundary migration (Commit 2); the post-migration schema covers
//! `artifacts.{ar1cs, pk, vk, pvk, evm_verifier, circuit_config}`.

use zkap_cli::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, SetupProvenance,
    built_at_now,
};

const FIXED_EPOCH: &str = "1700000000";
const SEED_HEX: &str = "0x42424242deadbeef0000000000000000000000000000000000000000000000ff";

/// Single source of truth for the per-test sample manifest. Building it
/// twice from the same inputs must yield byte-equal JSON.
fn build_sample(built_at: String) -> Manifest {
    ManifestBuilder::new("zkap-main-v1", "zkap-main-v1__deadbeef")
        .with_ar1cs_blake3("a".repeat(64))
        .with_shape(9, 896800, 911941)
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
            sample_entry("circuit.ar1cs", "core", 696_083_793, None, None),
        )
        .with_artifact(
            ArtifactKey::Pk,
            sample_entry("pk.bin", "core", 696_000_000, None, None),
        )
        .with_artifact(
            ArtifactKey::Vk,
            sample_entry("vk.bin", "core", 1032, None, None),
        )
        .with_artifact(
            ArtifactKey::Pvk,
            sample_entry("pvk.bin", "core", 5120, None, None),
        )
        .with_artifact(
            ArtifactKey::EvmVerifier,
            sample_entry("Groth16Verifier.sol", "domain-optional", 42, None, None),
        )
        .with_artifact(
            ArtifactKey::CircuitConfig,
            sample_entry(
                "config.json",
                "domain",
                345,
                Some("npm:@baerae/zkap-zkp@^1".into()),
                Some("ZkapCircuitConfigV1".into()),
            ),
        )
        .with_setup_provenance(SetupProvenance::Seed {
            seed: SEED_HEX.to_string(),
        })
        .with_build(BuildMetadata {
            circuit_repo: "https://github.com/snp-labs/zkap-circuit".into(),
            circuit_commit: "deadbeef".into(),
            ark_ar1cs_rev: "0370db0e".into(),
            rustc: "rustc 1.95.0".into(),
            built_at,
        })
        .build()
        .expect("builder must succeed with full payload")
}

fn sample_entry(
    path: &str,
    kind: &str,
    size: u64,
    schema_owner: Option<String>,
    schema_ref: Option<String>,
) -> ArtifactEntry {
    ArtifactEntry {
        path: path.into(),
        sha256: "ab".repeat(32),
        size,
        kind: kind.into(),
        schema_owner,
        schema_ref,
    }
}

/// Acceptance: `Manifest → serde_json → Manifest` preserves every field.
#[test]
fn manifest_round_trip_via_serde() {
    let original = build_sample("2026-05-12T00:00:00Z".into());
    let bytes = serde_json::to_vec(&original).expect("serialize");
    let back: Manifest = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(original, back);
}

/// Acceptance: when `SOURCE_DATE_EPOCH` is fixed and all other builder
/// inputs are identical, two `ManifestBuilder` runs produce byte-equal
/// `serde_json::to_string_pretty` output.
#[test]
fn manifest_pretty_is_byte_reproducible_under_fixed_epoch() {
    let a = {
        let _guard = EpochGuard::set(FIXED_EPOCH);
        let built_at = built_at_now().expect("RFC3339 with fixed epoch");
        let manifest = build_sample(built_at);
        serde_json::to_string_pretty(&manifest).expect("serialize manifest")
    };
    let b = {
        let _guard = EpochGuard::set(FIXED_EPOCH);
        let built_at = built_at_now().expect("RFC3339 with fixed epoch");
        let manifest = build_sample(built_at);
        serde_json::to_string_pretty(&manifest).expect("serialize manifest")
    };
    assert_eq!(a, b, "manifest pretty-print must be byte-reproducible");
}

/// Acceptance: the smoke fields the host SDK keys off are present and
/// shaped correctly.
#[test]
fn manifest_stage1_smoke_fields_present() {
    let manifest = build_sample("2026-05-12T00:00:00Z".into());
    let v: serde_json::Value = serde_json::to_value(&manifest).expect("to_value");

    assert_eq!(v["manifest_version"], "1");
    assert_eq!(v["curve"], "bn254");
    assert_eq!(v["proof_system"], "groth16");
    assert_eq!(v["setup_provenance"]["kind"], "seed");
    assert_eq!(
        v["toxic_waste_disclosure"]["trust_model"],
        "operator must be trusted"
    );
    assert_eq!(
        v["artifacts"]["circuit_config"]["schema_owner"],
        "npm:@baerae/zkap-zkp@^1"
    );
    assert_eq!(
        v["ar1cs_blake3"]
            .as_str()
            .map(|s| s.len())
            .unwrap_or_default(),
        64
    );
}

/// Acceptance: the post-migration schema lists every core artifact under
/// its new path. Catches accidental reintroduction of the legacy
/// `.arzkey` / `.wasm` entries.
#[test]
fn manifest_post_migration_artifact_layout() {
    let manifest = build_sample("2026-05-12T00:00:00Z".into());
    let v: serde_json::Value = serde_json::to_value(&manifest).expect("to_value");
    let artifacts = v["artifacts"].as_object().expect("artifacts object");

    for required in ["ar1cs", "pk", "vk", "pvk", "evm_verifier", "circuit_config"] {
        assert!(
            artifacts.contains_key(required),
            "post-migration manifest must include artifacts.{required}",
        );
    }
    for legacy in ["arzkey", "wasm"] {
        assert!(
            !artifacts.contains_key(legacy),
            "legacy artifacts.{legacy} must NOT appear in post-migration manifest",
        );
    }

    assert_eq!(artifacts["ar1cs"]["path"], "circuit.ar1cs");
    assert_eq!(artifacts["pk"]["path"], "pk.bin");
    assert_eq!(artifacts["vk"]["path"], "vk.bin");
    assert_eq!(artifacts["pvk"]["path"], "pvk.bin");

    for key in ["pk", "vk", "pvk", "circuit_config", "evm_verifier"] {
        assert!(
            artifacts[key].get("abi").is_none(),
            "post-migration manifest must NOT carry a wasm abi on artifacts.{key}",
        );
    }
}

/// Acceptance: `built_at_now()` is RFC3339 UTC and ends with `Z`.
#[test]
fn built_at_now_is_rfc3339_utc() {
    let _guard = EpochGuard::set(FIXED_EPOCH);
    let t = built_at_now().expect("RFC3339");
    assert!(t.ends_with('Z'), "expected UTC suffix, got {t}");
    assert_eq!(t, "2023-11-14T22:13:20Z");
}

/// Acceptance: a non-numeric `SOURCE_DATE_EPOCH` is rejected.
#[test]
fn built_at_now_rejects_invalid_source_date_epoch() {
    let _guard = EpochGuard::set("not-a-number");
    let err = built_at_now().expect_err("invalid SOURCE_DATE_EPOCH must error");
    assert!(
        err.contains("SOURCE_DATE_EPOCH"),
        "error should mention SOURCE_DATE_EPOCH: {err}"
    );
}

/// Restore-on-drop guard around `SOURCE_DATE_EPOCH`.
struct EpochGuard {
    previous: Option<std::ffi::OsString>,
}

impl EpochGuard {
    fn set(value: &str) -> Self {
        let previous = std::env::var_os("SOURCE_DATE_EPOCH");
        // SAFETY: env mutation is only racy across threads; restore-on-drop
        // means the worst observable outcome is a deterministic test
        // failure (caught in CI), not memory unsafety.
        unsafe {
            std::env::set_var("SOURCE_DATE_EPOCH", value);
        }
        Self { previous }
    }
}

impl Drop for EpochGuard {
    fn drop(&mut self) {
        // SAFETY: same justification as in `set`.
        unsafe {
            match self.previous.take() {
                Some(v) => std::env::set_var("SOURCE_DATE_EPOCH", v),
                None => std::env::remove_var("SOURCE_DATE_EPOCH"),
            }
        }
    }
}
