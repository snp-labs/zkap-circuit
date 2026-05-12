//! `manifest.json` v1 schema + builder for the setup deployment bundle.
//!
//! The schema and the Stage 1 vs Stage 2 contract live in plan
//! `2026-05-12-deployment-bundle-spec.md` §4 / §7. The `Ceremony`
//! provenance variant stays serialisable so Stage 2 output parses
//! against the same schema; Stage 1 never emits it.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Top-level manifest written to `<output>/manifest.json`.
///
/// All hashes are lowercase hex (no `0x` prefix). `manifest_version`
/// is `"1"` for the schema documented in plan §7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version — `"1"` for the Stage 1 layout.
    pub manifest_version: String,
    /// Human-readable circuit identifier (e.g. `"zkap-main-v1"`).
    pub circuit_id: String,
    /// `{circuit_id}__{first_8_hex_of_sha256(cfg_canonical_bytes)}`.
    pub circuit_tag: String,
    /// Curve name (BN254 for the current ZKAP pipeline).
    pub curve: String,
    /// Proof system identifier (`"groth16"` for the current pipeline).
    pub proof_system: String,
    /// 64-char hex of the 32-byte `ar1cs_blake3` constant baked into both
    /// `circuit.arzkey` (header bytes 16..48) and the wasm artifact
    /// (`embedded_ar1cs_blake3` export). The host pair-checks these three
    /// values; they MUST match.
    pub ar1cs_blake3: String,
    /// Circuit shape (`num_instance`, `num_witness`, `num_constraints`).
    pub shape: Shape,
    /// Public-input names in the order the circuit allocates them. MUST
    /// match `zkap_witness_wasm::ZKAP_PUBLIC_INPUT_NAMES`.
    pub public_input_names: Vec<String>,
    /// Per-artifact metadata (path / sha256 / size / kind).
    pub artifacts: Artifacts,
    /// Provenance of the randomness used during `Groth16::setup` —
    /// `"os-rng"` (Stage 1 fallback), `"seed"` (deterministic CI), or
    /// `"ceremony"` (Stage 2, not emitted by Stage 1 binary).
    pub setup_provenance: SetupProvenance,
    /// Trust model disclosure derived from `setup_provenance.kind` —
    /// `"single-host"` / `"operator must be trusted"` for Stage 1, or
    /// `"ceremony-1-of-n"` / `"1-of-N honest"` once ceremony output is wired.
    pub toxic_waste_disclosure: ToxicWasteDisclosure,
    /// Build metadata (repo, commit, rustc, RFC3339 built_at).
    pub build: BuildMetadata,
    /// Optional manifest signature (v2 — Stage 1 always emits `null`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Circuit shape (constraint-system counts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shape {
    /// Number of instance variables (includes the constant-1 wire).
    pub num_instance: u64,
    /// Number of witness variables.
    pub num_witness: u64,
    /// Number of constraints in the synthesized R1CS.
    pub num_constraints: u64,
}

/// Per-artifact metadata block. Core artifacts are required; `evm_verifier`
/// is `Option` because the Solidity output is `--skip-evm-verifier`-able in
/// future PRs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifacts {
    /// `circuit.arzkey` (R1CS matrices + proving key, one file).
    pub arzkey: ArtifactEntry,
    /// `zkap_witness_wasm.opt.wasm` witness generator.
    pub wasm: ArtifactEntry,
    /// `vk.key` (verifying key in uncompressed binary form).
    pub vk: ArtifactEntry,
    /// `Groth16Verifier.sol` (optional — `--skip-evm-verifier` in follow-up PR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_verifier: Option<ArtifactEntry>,
    /// `config.json` (domain-typed circuit hyperparameters).
    pub circuit_config: ArtifactEntry,
}

/// A single artifact entry — path, sha256 hex, size in bytes, kind, and
/// optional wasm ABI / schema metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    /// File name relative to the manifest's directory.
    pub path: String,
    /// SHA-256 of the file as lowercase hex (no `0x` prefix).
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
    /// Classification — `"core"` / `"domain"` / `"domain-optional"`.
    pub kind: String,
    /// Wasm ABI (only set for the wasm artifact).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi: Option<WasmAbi>,
    /// Schema owner pointer (e.g. `"npm:@baerae/zkap-zkp@^1"`) for the
    /// `circuit_config` artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_owner: Option<String>,
    /// Schema reference (e.g. `"ZkapCircuitConfigV1"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
}

/// Wasm ABI metadata — only attached to the wasm artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmAbi {
    /// ABI version — Stage 1 emits `1`.
    pub version: u32,
    /// Required exports. Stage 1 lists `wasm_alloc`, `wasm_free`,
    /// `embedded_ar1cs_blake3`, `witness_generator` (same set verified by
    /// `zkap_cli::verify_wasm_exports`).
    pub exports: Vec<String>,
}

/// Provenance of the randomness used during `Groth16::setup`.
///
/// `kind` discriminator (kebab-case) is emitted as `"os-rng"`,
/// `"seed"`, or `"ceremony"`. The `Ceremony` variant is reserved for
/// Stage 2 ceremony output (`--ptau` + `--phase2-attestations`) and is
/// not emitted by the Stage 1 binary, but the schema accepts it so
/// future deserialisers do not break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SetupProvenance {
    /// OS-supplied randomness (Stage 1 default).
    OsRng,
    /// Deterministic ChaCha20 seed, gated by `--allow-test-only` on the CLI.
    Seed {
        /// Hex-encoded 32-byte seed (e.g. `"0x42…"`).
        seed: String,
    },
    /// Stage 2 ceremony output — Powers-of-Tau + Phase 2 attestations.
    Ceremony {
        /// Powers-of-Tau reference.
        ptau: PtauRef,
        /// Phase 2 contribution chain.
        phase2_attestations: Vec<Phase2Attestation>,
    },
}

/// Powers-of-Tau reference (Stage 2). Records the source URL, integrity
/// hash, max degree, and the post-accumulator hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtauRef {
    /// Source URL or local path the file was fetched from.
    pub source: String,
    /// SHA-256 of the `.ptau` file.
    pub sha256: String,
    /// Maximum supported circuit degree (`2^max_power` constraints).
    pub max_power: u32,
    /// Post-accumulator hash from the ceremony verifier.
    pub accumulator_hash: String,
}

/// A single Phase 2 contribution attestation.
///
/// Maps 1:1 to `ceremony-core-engine` `MPCParameters::contribute()` /
/// `verify_contribution()` output. Stage 1 binary never emits one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase2Attestation {
    /// Free-form contributor identifier (e.g. `"alice"`).
    pub contributor_id: String,
    /// 64-char hex hash returned by `MPCParameters::contribute()`.
    pub contribution_hash: String,
    /// `ContributionPublicKey` payload for verifier replay.
    pub public_key: ContributionPublicKeyJson,
    /// RFC3339 timestamp.
    pub timestamp: String,
    /// Verifier crate identifier (e.g. `"ceremony-phase2 v0.1.0"`).
    pub verifier: String,
}

/// `ContributionPublicKey` payload in JSON form (Stage 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionPublicKeyJson {
    /// `g1_s` group element (hex).
    pub g1_s: String,
    /// `g1_s_alpha` group element (hex).
    pub g1_s_alpha: String,
    /// `g2_alpha` group element (hex).
    pub g2_alpha: String,
    /// Transcript hash up to and including this contribution.
    pub transcript_hash: String,
}

/// Trust-model disclosure block. Derived from [`SetupProvenance`] via
/// [`derive_toxic_waste_disclosure`] so the two stay in lockstep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToxicWasteDisclosure {
    /// `"single-host"` for OS-RNG / seed; `"ceremony-1-of-n"` for ceremony.
    pub kind: String,
    /// Plain-text trust assumption (e.g. `"operator must be trusted"`).
    pub trust_model: String,
    /// Attestation-chain hash (only set for ceremony output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_log: Option<String>,
}

/// Build metadata block. `built_at` is RFC3339 UTC; deterministic when
/// `SOURCE_DATE_EPOCH` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildMetadata {
    /// Setup-binary repo URL (typically `env!("CARGO_PKG_REPOSITORY")`).
    pub circuit_repo: String,
    /// Setup-binary commit (caller supplied via `--build-commit` or
    /// `git rev-parse HEAD`).
    pub circuit_commit: String,
    /// `ark-ar1cs` git rev used by this build (from `[workspace.dependencies]`).
    pub ark_ar1cs_rev: String,
    /// `rustc --version` output.
    pub rustc: String,
    /// RFC3339 UTC timestamp; `SOURCE_DATE_EPOCH` overrides wallclock.
    pub built_at: String,
}

/// Derive the [`ToxicWasteDisclosure`] block from the chosen
/// [`SetupProvenance`].
///
/// Stage 1 (`OsRng` / `Seed`) emits `single-host` / `operator must be
/// trusted`. Stage 2 (`Ceremony`) emits `ceremony-1-of-n` / `1-of-N
/// honest` and hashes the attestation chain into `destroy_log` (the
/// hash is the sha256 of the concatenated `contribution_hash` values,
/// in order — a stable summary the host can pin without re-fetching
/// every attestation).
pub fn derive_toxic_waste_disclosure(p: &SetupProvenance) -> ToxicWasteDisclosure {
    match p {
        SetupProvenance::OsRng | SetupProvenance::Seed { .. } => ToxicWasteDisclosure {
            kind: "single-host".into(),
            trust_model: "operator must be trusted".into(),
            destroy_log: None,
        },
        SetupProvenance::Ceremony {
            phase2_attestations,
            ..
        } => ToxicWasteDisclosure {
            kind: "ceremony-1-of-n".into(),
            trust_model: "1-of-N honest".into(),
            destroy_log: Some(chain_hash(phase2_attestations)),
        },
    }
}

/// SHA-256 of the concatenated lowercase-hex `contribution_hash` bytes of
/// each attestation, in order. Used as the `destroy_log` field on
/// ceremony-derived manifests.
fn chain_hash(chain: &[Phase2Attestation]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for att in chain {
        hasher.update(att.contribution_hash.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Which artifact slot a builder entry targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKey {
    /// `circuit.arzkey`.
    Arzkey,
    /// `zkap_witness_wasm.opt.wasm`.
    Wasm,
    /// `vk.key`.
    Vk,
    /// `Groth16Verifier.sol` (optional).
    EvmVerifier,
    /// `config.json`.
    CircuitConfig,
}

/// Required artifact exports for the wasm bundle. Mirrors
/// `crates/cli/src/bin/generate_setup.rs::REQUIRED_EXPORTS` so a builder
/// using [`ManifestBuilder::with_artifact`] always lists the same set.
pub const REQUIRED_EXPORTS: &[&str] = &[
    "wasm_alloc",
    "wasm_free",
    "embedded_ar1cs_blake3",
    "witness_generator",
];

/// Reason a [`ManifestBuilder::build`] call failed.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// A required field was not supplied to the builder.
    #[error("manifest builder missing required field: {0}")]
    MissingField(&'static str),
    /// A required artifact slot was not populated.
    #[error("manifest builder missing required artifact: {0}")]
    MissingArtifact(&'static str),
}

/// Incremental builder for [`Manifest`].
///
/// Required setters: `with_ar1cs_blake3`, `with_shape`,
/// `with_public_input_names`, `with_artifact` (for each of arzkey / wasm /
/// vk / circuit_config), `with_setup_provenance`, `with_build`. The
/// `evm_verifier` artifact is optional. Missing required pieces cause
/// [`build`](Self::build) to return [`BuilderError`].
#[derive(Debug, Default)]
pub struct ManifestBuilder {
    circuit_id: String,
    circuit_tag: String,
    ar1cs_blake3: Option<String>,
    shape: Option<Shape>,
    public_input_names: Option<Vec<String>>,
    arzkey: Option<ArtifactEntry>,
    wasm: Option<ArtifactEntry>,
    vk: Option<ArtifactEntry>,
    evm_verifier: Option<ArtifactEntry>,
    circuit_config_artifact: Option<ArtifactEntry>,
    setup_provenance: Option<SetupProvenance>,
    build: Option<BuildMetadata>,
}

impl ManifestBuilder {
    /// Start a builder for `circuit_id` / `circuit_tag`.
    pub fn new(circuit_id: impl Into<String>, circuit_tag: impl Into<String>) -> Self {
        Self {
            circuit_id: circuit_id.into(),
            circuit_tag: circuit_tag.into(),
            ..Self::default()
        }
    }

    /// Set `ar1cs_blake3` (64-hex).
    pub fn with_ar1cs_blake3(mut self, hex: impl Into<String>) -> Self {
        self.ar1cs_blake3 = Some(hex.into());
        self
    }

    /// Set the constraint-system shape counts.
    pub fn with_shape(mut self, num_instance: u64, num_witness: u64, num_constraints: u64) -> Self {
        self.shape = Some(Shape {
            num_instance,
            num_witness,
            num_constraints,
        });
        self
    }

    /// Set `public_input_names` (caller supplies the wasm export list).
    pub fn with_public_input_names(mut self, names: Vec<String>) -> Self {
        self.public_input_names = Some(names);
        self
    }

    /// Place `entry` into the slot identified by `key`.
    pub fn with_artifact(mut self, key: ArtifactKey, entry: ArtifactEntry) -> Self {
        match key {
            ArtifactKey::Arzkey => self.arzkey = Some(entry),
            ArtifactKey::Wasm => self.wasm = Some(entry),
            ArtifactKey::Vk => self.vk = Some(entry),
            ArtifactKey::EvmVerifier => self.evm_verifier = Some(entry),
            ArtifactKey::CircuitConfig => self.circuit_config_artifact = Some(entry),
        }
        self
    }

    /// Set `setup_provenance`. `toxic_waste_disclosure` is derived in
    /// [`build`](Self::build).
    pub fn with_setup_provenance(mut self, p: SetupProvenance) -> Self {
        self.setup_provenance = Some(p);
        self
    }

    /// Set the `build` metadata block.
    pub fn with_build(mut self, build: BuildMetadata) -> Self {
        self.build = Some(build);
        self
    }

    /// Consume the builder and produce a [`Manifest`].
    ///
    /// Fails with [`BuilderError`] when a required field is missing.
    pub fn build(self) -> Result<Manifest, BuilderError> {
        let setup_provenance = self
            .setup_provenance
            .ok_or(BuilderError::MissingField("setup_provenance"))?;
        let toxic_waste_disclosure = derive_toxic_waste_disclosure(&setup_provenance);

        Ok(Manifest {
            manifest_version: "1".into(),
            circuit_id: self.circuit_id,
            circuit_tag: self.circuit_tag,
            curve: "bn254".into(),
            proof_system: "groth16".into(),
            ar1cs_blake3: self
                .ar1cs_blake3
                .ok_or(BuilderError::MissingField("ar1cs_blake3"))?,
            shape: self.shape.ok_or(BuilderError::MissingField("shape"))?,
            public_input_names: self
                .public_input_names
                .ok_or(BuilderError::MissingField("public_input_names"))?,
            artifacts: Artifacts {
                arzkey: self
                    .arzkey
                    .ok_or(BuilderError::MissingArtifact("arzkey"))?,
                wasm: self.wasm.ok_or(BuilderError::MissingArtifact("wasm"))?,
                vk: self.vk.ok_or(BuilderError::MissingArtifact("vk"))?,
                evm_verifier: self.evm_verifier,
                circuit_config: self
                    .circuit_config_artifact
                    .ok_or(BuilderError::MissingArtifact("circuit_config"))?,
            },
            setup_provenance,
            toxic_waste_disclosure,
            build: self.build.ok_or(BuilderError::MissingField("build"))?,
            signature: None,
        })
    }
}

/// Read bytes 16..48 of an `.arzkey` header and return them as a 64-char
/// lowercase hex string.
///
/// Thin wrapper over [`crate::read_arzkey_blake3`] that converts the
/// `[u8; 32]` output to a `String` (the form [`Manifest::ar1cs_blake3`]
/// uses).
pub fn read_arzkey_blake3_hex(path: &Path) -> String {
    hex::encode(crate::read_arzkey_blake3(path))
}

/// `{circuit_id}__{first_8_hex_of_sha256(cfg_canonical_bytes)}`.
///
/// Used for both the dist subdirectory name (PR #2 follow-up) and the
/// `manifest.circuit_tag` field. The tag pins a hyperparam variant: two
/// configs with different `CircuitConfig` produce different tags.
pub fn compute_circuit_tag(circuit_id: &str, cfg_canonical_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(cfg_canonical_bytes);
    let short = hex::encode(&hash[..4]);
    format!("{circuit_id}__{short}")
}

/// Serialise a `serde_json::Value` with keys sorted ascending at every
/// depth — i.e. emit canonical JSON bytes that hash deterministically.
///
/// `serde_json::Value::Object` is already backed by a `BTreeMap` when the
/// `preserve_order` feature is off (the default workspace setting), so a
/// plain `serde_json::to_vec` is already key-sorted. This helper exists
/// so callers can build a `Value` from an arbitrary `Serialize` and get
/// the same guarantee without reaching into serde internals.
pub fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serde_json::Value always serialises")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_artifact(path: &str, kind: &str) -> ArtifactEntry {
        ArtifactEntry {
            path: path.into(),
            sha256: "ab".repeat(32),
            size: 1024,
            kind: kind.into(),
            abi: None,
            schema_owner: None,
            schema_ref: None,
        }
    }

    fn sample_build() -> BuildMetadata {
        BuildMetadata {
            circuit_repo: "https://github.com/snp-labs/zkap-circuit".into(),
            circuit_commit: "deadbeef".into(),
            ark_ar1cs_rev: "0370db0e".into(),
            rustc: "rustc 1.95.0".into(),
            built_at: "2026-05-12T00:00:00Z".into(),
        }
    }

    fn sample_manifest() -> Manifest {
        ManifestBuilder::new("zkap-main-v1", "zkap-main-v1__deadbeef")
            .with_ar1cs_blake3("ab".repeat(32))
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
            .with_artifact(ArtifactKey::Arzkey, sample_artifact("circuit.arzkey", "core"))
            .with_artifact(
                ArtifactKey::Wasm,
                ArtifactEntry {
                    abi: Some(WasmAbi {
                        version: 1,
                        exports: REQUIRED_EXPORTS.iter().map(|s| s.to_string()).collect(),
                    }),
                    ..sample_artifact("zkap_witness_wasm.opt.wasm", "core")
                },
            )
            .with_artifact(ArtifactKey::Vk, sample_artifact("vk.key", "core"))
            .with_artifact(
                ArtifactKey::EvmVerifier,
                sample_artifact("Groth16Verifier.sol", "domain-optional"),
            )
            .with_artifact(
                ArtifactKey::CircuitConfig,
                ArtifactEntry {
                    schema_owner: Some("npm:@baerae/zkap-zkp@^1".into()),
                    schema_ref: Some("ZkapCircuitConfigV1".into()),
                    ..sample_artifact("config.json", "domain")
                },
            )
            .with_setup_provenance(SetupProvenance::OsRng)
            .with_build(sample_build())
            .build()
            .expect("builder must succeed with full payload")
    }

    /// Acceptance (US-S1): `Manifest → serde_json bytes → Manifest`
    /// preserves every field. Catches drift between the struct layout
    /// and the serde derives.
    #[test]
    fn manifest_round_trip_via_serde() {
        let original = sample_manifest();
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let back: Manifest = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(original, back);
    }

    /// Acceptance (US-S1): the `kind` discriminator is kebab-case, not the
    /// Rust variant name. The host-side SDK keys off `"os-rng"` /
    /// `"seed"` / `"ceremony"`, so the rename is load-bearing.
    #[test]
    fn setup_provenance_kind_is_kebab_case() {
        let v = serde_json::to_value(SetupProvenance::OsRng).unwrap();
        assert_eq!(v["kind"], "os-rng");
        let v = serde_json::to_value(SetupProvenance::Seed {
            seed: "0x42".into(),
        })
        .unwrap();
        assert_eq!(v["kind"], "seed");
    }

    /// Acceptance (US-S5): builder fails with `MissingField` /
    /// `MissingArtifact` when a required input is absent.
    #[test]
    fn builder_rejects_incomplete_payload() {
        let err = ManifestBuilder::new("x", "y").build().unwrap_err();
        assert!(matches!(err, BuilderError::MissingField(_)));
    }

    /// Acceptance (US-S5): `derive_toxic_waste_disclosure` returns the
    /// Stage 1 single-host disclosure for `OsRng` and `Seed`, and the
    /// ceremony-1-of-n disclosure for `Ceremony`.
    #[test]
    fn toxic_waste_disclosure_follows_provenance() {
        let d = derive_toxic_waste_disclosure(&SetupProvenance::OsRng);
        assert_eq!(d.kind, "single-host");
        assert_eq!(d.trust_model, "operator must be trusted");
        assert!(d.destroy_log.is_none());

        let d = derive_toxic_waste_disclosure(&SetupProvenance::Seed {
            seed: "0xabcd".into(),
        });
        assert_eq!(d.kind, "single-host");

        let d = derive_toxic_waste_disclosure(&SetupProvenance::Ceremony {
            ptau: PtauRef {
                source: "x".into(),
                sha256: "y".into(),
                max_power: 22,
                accumulator_hash: "z".into(),
            },
            phase2_attestations: vec![],
        });
        assert_eq!(d.kind, "ceremony-1-of-n");
        assert_eq!(d.trust_model, "1-of-N honest");
        assert!(d.destroy_log.is_some());
    }

    /// Acceptance (US-S4): `compute_circuit_tag` is stable and tracks the
    /// canonical bytes of the config — different bytes give different tags.
    #[test]
    fn compute_circuit_tag_is_deterministic() {
        let a = compute_circuit_tag("zkap-main-v1", b"{}");
        let b = compute_circuit_tag("zkap-main-v1", b"{}");
        assert_eq!(a, b);
        let c = compute_circuit_tag("zkap-main-v1", b"{\"x\":1}");
        assert_ne!(a, c);
        // Tag layout: `{id}__{8hex}`.
        let suffix = a.strip_prefix("zkap-main-v1__").expect("prefix");
        assert_eq!(suffix.len(), 8);
    }
}
