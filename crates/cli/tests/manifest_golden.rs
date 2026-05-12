// File-scoped unsafe allow: `EpochGuard` mutates `SOURCE_DATE_EPOCH` via
// `std::env::set_var`, which Rust 1.83+ marks `unsafe`. Library code
// stays under the workspace `unsafe_code = "deny"` lint.
#![allow(unsafe_code)]

//! Manifest reproducibility tests. Builder-level instead of
//! end-to-end `generate_setup` because Groth16 setup is ~2 minutes;
//! the byte-reproducibility property the plan asks for is fully
//! exercised at the `ManifestBuilder` boundary.

use zkap_cli::{
    ArtifactEntry, ArtifactKey, BuildMetadata, Manifest, ManifestBuilder, REQUIRED_EXPORTS,
    SetupProvenance, WasmAbi, built_at_now,
};

const FIXED_EPOCH: &str = "1700000000";
const SEED_HEX: &str =
    "0x42424242deadbeef0000000000000000000000000000000000000000000000ff";

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
            ArtifactKey::Arzkey,
            sample_entry("circuit.arzkey", "core", 696083793, None, None, None),
        )
        .with_artifact(
            ArtifactKey::Wasm,
            sample_entry(
                "zkap_witness_wasm.opt.wasm",
                "core",
                1072606,
                Some(WasmAbi {
                    version: 1,
                    exports: REQUIRED_EXPORTS.iter().map(|s| s.to_string()).collect(),
                }),
                None,
                None,
            ),
        )
        .with_artifact(
            ArtifactKey::Vk,
            sample_entry("vk.key", "core", 1032, None, None, None),
        )
        .with_artifact(
            ArtifactKey::EvmVerifier,
            sample_entry(
                "Groth16Verifier.sol",
                "domain-optional",
                42,
                None,
                None,
                None,
            ),
        )
        .with_artifact(
            ArtifactKey::CircuitConfig,
            sample_entry(
                "config.json",
                "domain",
                345,
                None,
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
    abi: Option<WasmAbi>,
    schema_owner: Option<String>,
    schema_ref: Option<String>,
) -> ArtifactEntry {
    ArtifactEntry {
        path: path.into(),
        sha256: "ab".repeat(32),
        size,
        kind: kind.into(),
        abi,
        schema_owner,
        schema_ref,
    }
}

/// Acceptance (US-S8): `Manifest → serde_json → Manifest` preserves
/// every field. Catches drift between the struct layout and the serde
/// derives (e.g. a missing `#[serde]` attribute or an enum rename slip).
#[test]
fn manifest_round_trip_via_serde() {
    let original = build_sample("2026-05-12T00:00:00Z".into());
    let bytes = serde_json::to_vec(&original).expect("serialize");
    let back: Manifest = serde_json::from_slice(&bytes).expect("deserialize");
    assert_eq!(original, back);
}

/// Acceptance (US-S7 / US-S8): when `SOURCE_DATE_EPOCH` is fixed and all
/// other builder inputs are identical, two `ManifestBuilder` runs produce
/// byte-equal `serde_json::to_string_pretty` output. This is the
/// reproducibility property the deployment-bundle plan §11 D7 relies on
/// — without it, two CI runs against the same config + seed would
/// diverge in `build.built_at` alone.
#[test]
fn manifest_pretty_is_byte_reproducible_under_fixed_epoch() {
    // Two passes that should be byte-equal.
    let a = {
        // Restore-on-drop guard ensures the env var doesn't leak between tests.
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

/// Acceptance (US-S6 / US-S8): the smoke fields the host SDK keys off
/// are present and shaped correctly. Catches a regression where the
/// SetupProvenance tag rename or the `derive_toxic_waste_disclosure`
/// table drifts.
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
        v["artifacts"]["wasm"]["abi"]["exports"]
            .as_array()
            .map(|a| a.len()),
        Some(REQUIRED_EXPORTS.len())
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

/// Acceptance (US-S7): `built_at_now()` is RFC3339 UTC and ends with `Z`.
#[test]
fn built_at_now_is_rfc3339_utc() {
    let _guard = EpochGuard::set(FIXED_EPOCH);
    let t = built_at_now().expect("RFC3339");
    assert!(t.ends_with('Z'), "expected UTC suffix, got {t}");
    // 1700000000 unix-seconds = 2023-11-14T22:13:20Z.
    assert_eq!(t, "2023-11-14T22:13:20Z");
}

/// Acceptance (US-S7): a non-numeric `SOURCE_DATE_EPOCH` is rejected.
#[test]
fn built_at_now_rejects_invalid_source_date_epoch() {
    let _guard = EpochGuard::set("not-a-number");
    let err = built_at_now().expect_err("invalid SOURCE_DATE_EPOCH must error");
    assert!(
        err.contains("SOURCE_DATE_EPOCH"),
        "error should mention SOURCE_DATE_EPOCH: {err}"
    );
}

/// Restore-on-drop guard around `SOURCE_DATE_EPOCH`. Parallel
/// `cargo test` execution of two env-touching tests can produce an
/// observable test failure (e.g. wrong-epoch built_at), not UB — the
/// guard bounds the leak window to a single test's body.
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
