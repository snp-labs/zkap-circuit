//! `manifest.json` v1 schema + builder for the post-migration CRS bundle.
//!
//! Reshaped against the 2026-05 ark-ar1cs boundary migration target.
//! The schema lists `artifacts.{ar1cs, pk, vk, pvk, evm_verifier,
//! circuit_config}` — every other slot the manifest used to carry has
//! been removed.
//!
//! The Stage 1 vs Stage 2 trust contract carries over verbatim:
//! `Phase2Attestation` / `PtauRef` stay serialisable so Stage 2 output
//! parses against the same schema, but the Stage 1 binary never emits
//! the `Ceremony` provenance variant.
//!
//! This module is intentionally **proof-feature-independent** so hosts
//! that consume the manifest without pulling Groth16 (e.g. lightweight
//! binding builds) can depend on it cheaply.

use serde::{Deserialize, Serialize};

/// Top-level manifest written to `<output>/manifest.json`.
///
/// All hashes are lowercase hex (no `0x` prefix). `manifest_version`
/// is `"1"` for the schema documented in the migration cheatsheet
/// (`docs/migration-2026-05.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version — `"1"` for the post-migration layout.
    pub manifest_version: String,
    /// Human-readable circuit identifier (e.g. `"zkap-main-v1"`).
    pub circuit_id: String,
    /// `{circuit_id}__{first_8_hex_of_sha256(cfg_canonical_bytes)}`.
    pub circuit_tag: String,
    /// Curve name (BN254 for the current ZKAP pipeline).
    pub curve: String,
    /// Proof system identifier (`"groth16"` for the current pipeline).
    pub proof_system: String,
    /// 64-char hex of the 32-byte `body_blake3` of `circuit.ar1cs`. Callers
    /// must compare against `arcs.body_blake3()` of the loaded artifact
    /// before invoking the prover (see
    /// `zkap_service::artifact::ArtifactSet::load`).
    pub ar1cs_blake3: String,
    /// Circuit shape (`num_instance`, `num_witness`, `num_constraints`).
    pub shape: Shape,
    /// Public-input names in the order the circuit allocates them.
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

/// Per-artifact metadata block.
///
/// Required artifacts are the four core files (`ar1cs`, `pk`, `vk`,
/// `pvk`) plus the `circuit_config`. `evm_verifier` and `witness_gen`
/// stay `Option` so hosts that drop those outputs still parse the
/// manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifacts {
    /// `circuit.ar1cs` — R1CS matrices in ark-ar1cs canonical envelope.
    pub ar1cs: ArtifactEntry,
    /// `pk.bin` — proving key (arkworks `CanonicalSerialize` uncompressed).
    pub pk: ArtifactEntry,
    /// `vk.bin` — verifying key (arkworks `CanonicalSerialize` uncompressed).
    pub vk: ArtifactEntry,
    /// `pvk.bin` — prepared verifying key (arkworks `CanonicalSerialize`
    /// uncompressed). Round-trip locked by the
    /// `pvk_serialization::prepared_verifying_key_round_trips_uncompressed`
    /// test.
    pub pvk: ArtifactEntry,
    /// `Groth16Verifier.sol` (optional; skipped by future
    /// `--skip-evm-verifier` flag).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_verifier: Option<ArtifactEntry>,
    /// `config.json` (domain-typed circuit hyperparameters).
    pub circuit_config: ArtifactEntry,
    /// `witness_gen.wasm` (optional) — circuit-dependent witness
    /// generator built from `crates/witness-gen-wasm`. Lets
    /// downstream circuit-agnostic prover packages call
    /// `zkap_service::synthesize_witnesses` behind a wasm runtime
    /// without recompiling when the circuit changes; skipped when
    /// the CLI is invoked without `--witness-gen-wasm`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_gen: Option<ArtifactEntry>,
}

/// A single artifact entry — relative path, sha256 hex, size in bytes,
/// kind, and optional schema metadata.
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
    /// Schema owner pointer (e.g. `"npm:@baerae/zkap-zkp@^1"`) for the
    /// `circuit_config` artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_owner: Option<String>,
    /// Schema reference (e.g. `"ZkapCircuitConfigV1"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
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
    /// `circuit.ar1cs`.
    Ar1cs,
    /// `pk.bin`.
    Pk,
    /// `vk.bin`.
    Vk,
    /// `pvk.bin`.
    Pvk,
    /// `Groth16Verifier.sol` (optional).
    EvmVerifier,
    /// `config.json`.
    CircuitConfig,
    /// `witness_gen.wasm` (optional).
    WitnessGen,
}

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
/// `with_public_input_names`, `with_artifact` (for each of `ar1cs`,
/// `pk`, `vk`, `pvk`, `circuit_config`), `with_setup_provenance`,
/// `with_build`. The `evm_verifier` artifact is optional.
#[derive(Debug, Default)]
pub struct ManifestBuilder {
    circuit_id: String,
    circuit_tag: String,
    ar1cs_blake3: Option<String>,
    shape: Option<Shape>,
    public_input_names: Option<Vec<String>>,
    ar1cs: Option<ArtifactEntry>,
    pk: Option<ArtifactEntry>,
    vk: Option<ArtifactEntry>,
    pvk: Option<ArtifactEntry>,
    evm_verifier: Option<ArtifactEntry>,
    circuit_config_artifact: Option<ArtifactEntry>,
    witness_gen: Option<ArtifactEntry>,
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

    /// Set `public_input_names` (caller supplies the wire-protocol export list).
    pub fn with_public_input_names(mut self, names: Vec<String>) -> Self {
        self.public_input_names = Some(names);
        self
    }

    /// Place `entry` into the slot identified by `key`.
    pub fn with_artifact(mut self, key: ArtifactKey, entry: ArtifactEntry) -> Self {
        match key {
            ArtifactKey::Ar1cs => self.ar1cs = Some(entry),
            ArtifactKey::Pk => self.pk = Some(entry),
            ArtifactKey::Vk => self.vk = Some(entry),
            ArtifactKey::Pvk => self.pvk = Some(entry),
            ArtifactKey::EvmVerifier => self.evm_verifier = Some(entry),
            ArtifactKey::CircuitConfig => self.circuit_config_artifact = Some(entry),
            ArtifactKey::WitnessGen => self.witness_gen = Some(entry),
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
                ar1cs: self.ar1cs.ok_or(BuilderError::MissingArtifact("ar1cs"))?,
                pk: self.pk.ok_or(BuilderError::MissingArtifact("pk"))?,
                vk: self.vk.ok_or(BuilderError::MissingArtifact("vk"))?,
                pvk: self.pvk.ok_or(BuilderError::MissingArtifact("pvk"))?,
                evm_verifier: self.evm_verifier,
                circuit_config: self
                    .circuit_config_artifact
                    .ok_or(BuilderError::MissingArtifact("circuit_config"))?,
                witness_gen: self.witness_gen,
            },
            setup_provenance,
            toxic_waste_disclosure,
            build: self.build.ok_or(BuilderError::MissingField("build"))?,
            signature: None,
        })
    }
}

/// `{circuit_id}__{first_8_hex_of_sha256(cfg_canonical_bytes)}`.
///
/// Used for both the dist subdirectory name and the
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
pub fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serde_json::Value always serialises")
}

#[cfg(test)]
mod tests {
    use super::*;

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
            .with_artifact(ArtifactKey::Ar1cs, sample_entry("circuit.ar1cs", "core"))
            .with_artifact(ArtifactKey::Pk, sample_entry("pk.bin", "core"))
            .with_artifact(ArtifactKey::Vk, sample_entry("vk.bin", "core"))
            .with_artifact(ArtifactKey::Pvk, sample_entry("pvk.bin", "core"))
            .with_artifact(
                ArtifactKey::EvmVerifier,
                sample_entry("Groth16Verifier.sol", "domain-optional"),
            )
            .with_artifact(
                ArtifactKey::CircuitConfig,
                ArtifactEntry {
                    schema_owner: Some("npm:@baerae/zkap-zkp@^1".into()),
                    schema_ref: Some("ZkapCircuitConfigV1".into()),
                    ..sample_entry("config.json", "domain")
                },
            )
            .with_setup_provenance(SetupProvenance::OsRng)
            .with_build(sample_build())
            .build()
            .expect("builder must succeed with full payload")
    }

    /// Acceptance: `Manifest → serde_json bytes → Manifest` preserves every
    /// field. Catches drift between the struct layout and the serde derives.
    #[test]
    fn manifest_round_trip_via_serde() {
        let original = sample_manifest();
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let back: Manifest = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(original, back);
    }

    /// Acceptance: the `kind` discriminator is kebab-case.
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

    /// Acceptance: builder fails with a clear error when a required input
    /// is absent.
    #[test]
    fn builder_rejects_incomplete_payload() {
        let err = ManifestBuilder::new("x", "y").build().unwrap_err();
        assert!(matches!(err, BuilderError::MissingField(_)));
    }

    /// Acceptance: `derive_toxic_waste_disclosure` returns the Stage 1
    /// single-host disclosure for `OsRng` and `Seed`, and the
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

    /// Acceptance: `compute_circuit_tag` is stable and tracks the canonical
    /// bytes of the config.
    #[test]
    fn compute_circuit_tag_is_deterministic() {
        let a = compute_circuit_tag("zkap-main-v1", b"{}");
        let b = compute_circuit_tag("zkap-main-v1", b"{}");
        assert_eq!(a, b);
        let c = compute_circuit_tag("zkap-main-v1", b"{\"x\":1}");
        assert_ne!(a, c);
        let suffix = a.strip_prefix("zkap-main-v1__").expect("prefix");
        assert_eq!(suffix.len(), 8);
    }

    /// Acceptance: the post-migration schema lists every required
    /// artifact slot. The schema is statically typed
    /// ([`Artifacts`]) so absence of retired slots is structural;
    /// only the positive presence check is asserted here.
    #[test]
    fn schema_lists_every_required_artifact_slot() {
        let v = serde_json::to_value(sample_manifest()).unwrap();
        let artifacts = v["artifacts"].as_object().expect("artifacts object");
        for required in ["ar1cs", "pk", "vk", "pvk", "circuit_config"] {
            assert!(
                artifacts.contains_key(required),
                "artifacts.{required} must be present in the new schema"
            );
        }
    }

    /// Acceptance: an absent `witness_gen` slot is skipped during
    /// serialization (matching `evm_verifier`'s optional shape), so
    /// hosts on older bundles keep parsing the manifest.
    #[test]
    fn schema_skips_absent_witness_gen() {
        let v = serde_json::to_value(sample_manifest()).unwrap();
        let artifacts = v["artifacts"].as_object().expect("artifacts object");
        assert!(
            !artifacts.contains_key("witness_gen"),
            "witness_gen must be omitted when not attached"
        );
    }

    /// Acceptance: when `witness_gen` is attached, the entry round
    /// trips through serde with the same path/sha256/size/kind as
    /// the in-memory `ArtifactEntry`.
    #[test]
    fn schema_round_trips_witness_gen_entry() {
        let manifest = ManifestBuilder::new("zkap-main-v1", "zkap-main-v1__deadbeef")
            .with_ar1cs_blake3("ab".repeat(32))
            .with_shape(9, 896800, 911941)
            .with_public_input_names(vec!["hanchor".into()])
            .with_artifact(ArtifactKey::Ar1cs, sample_entry("circuit.ar1cs", "core"))
            .with_artifact(ArtifactKey::Pk, sample_entry("pk.bin", "core"))
            .with_artifact(ArtifactKey::Vk, sample_entry("vk.bin", "core"))
            .with_artifact(ArtifactKey::Pvk, sample_entry("pvk.bin", "core"))
            .with_artifact(
                ArtifactKey::CircuitConfig,
                sample_entry("config.json", "domain"),
            )
            .with_artifact(
                ArtifactKey::WitnessGen,
                sample_entry("witness_gen.wasm", "domain-optional"),
            )
            .with_setup_provenance(SetupProvenance::OsRng)
            .with_build(sample_build())
            .build()
            .expect("builder must succeed");

        let bytes = serde_json::to_vec(&manifest).expect("serialize");
        let back: Manifest = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(
            back.artifacts
                .witness_gen
                .as_ref()
                .map(|e| e.path.as_str()),
            Some("witness_gen.wasm")
        );
        assert_eq!(manifest, back);
    }
}
