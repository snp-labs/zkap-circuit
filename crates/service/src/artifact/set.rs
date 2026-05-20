//! [`ArtifactSet`] — the in-memory bundle of `(pk, vk, pvk, arcs, cfg)`
//! and the two caller-facing loaders.

use std::path::Path;

use ark_ar1cs::format::ArcsFile;
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey as Groth16VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use circuit::types::{BN254, CircuitConfig, F};
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::error::ArtifactError;
use crate::manifest::{ArtifactEntry, Manifest, verify_manifest};

/// In-memory bundle of every CRS artifact a `Prover` needs.
///
/// Populated by [`ArtifactSet::load_signed`] — the single
/// manifest-validated trust gate for the prove flow.
pub struct ArtifactSet {
    /// Groth16 proving key — loaded from `pk.bin`.
    pub pk: ProvingKey<BN254>,
    /// Groth16 verifying key — loaded from `vk.bin`.
    pub vk: Groth16VerifyingKey<BN254>,
    /// Prepared verifying key — loaded from `pvk.bin`.
    pub pvk: PreparedVerifyingKey<BN254>,
    /// `.ar1cs` body — loaded from `circuit.ar1cs`.
    pub arcs: ArcsFile<F>,
    /// Circuit configuration — loaded from `config.json`.
    pub cfg: CircuitConfig,
    /// Optional `witness_gen.wasm` bytes — loaded from the
    /// `witness_gen` manifest entry when present.
    ///
    /// Set to `Some(bytes)` iff `manifest.artifacts.witness_gen` is
    /// populated and the on-disk file matches the recorded sha256.
    /// Downstream circuit-agnostic prover packages instantiate this
    /// wasm via a runtime (wasmtime, browser native, …) and call
    /// `synthesize_witness` over the ABI documented in the
    /// `zkap-witness-gen-wasm` crate.
    pub witness_gen_wasm: Option<Vec<u8>>,
}

impl ArtifactSet {
    /// Load every artifact named in `manifest` from `dir`, verify the
    /// ed25519 signature against `verifying_key`, **and** check all sha256
    /// / `ar1cs_blake3` integrity claims before returning.
    ///
    /// This is the **primary production entry point** for environments
    /// that issue signed bundles. The signature gate fires first so a
    /// tampered hash is caught by the signature before the recomputed-sha256
    /// gate runs. The hash gates remain in place as defence-in-depth.
    ///
    /// # Contract
    ///
    /// * `manifest.signature` must be `Some(_)` — if it is `None` the load
    ///   is rejected with [`ArtifactError::Signature`] (`SignatureMissing`).
    /// * The signature must verify against `verifying_key`; any mismatch
    ///   returns [`ArtifactError::Signature`].
    /// * All sha256 / `ar1cs_blake3` claims must match the on-disk files.
    ///
    /// For loading unsigned bundles (e.g. CI test fixtures, pre-F5 legacy
    /// bundles) use [`ArtifactSet::load_unsigned`] — it is explicit about
    /// skipping signature authenticity.
    pub fn load_signed(
        manifest: &Manifest,
        dir: &Path,
        verifying_key: &VerifyingKey,
    ) -> Result<Self, ArtifactError> {
        verify_manifest(manifest, verifying_key)?;
        Self::load_artifacts(manifest, dir)
    }

    /// Load every artifact named in `manifest` from `dir` and verify the
    /// sha256 / `ar1cs_blake3` integrity claims before returning.
    ///
    /// # Security
    ///
    /// **Signature authenticity is NOT checked.** The manifest's `signature`
    /// field — and therefore the authenticity of all embedded sha256 hashes —
    /// is trusted without cryptographic verification. The sha256 / blake3
    /// gates still protect against accidental corruption or filesystem-level
    /// tampering after the manifest was written, but they cannot protect
    /// against an attacker who controls the manifest file itself.
    ///
    /// Use this constructor only when:
    /// * The bundle was produced without a signing key (unsigned CI fixtures,
    ///   pre-F5 legacy bundles), **or**
    /// * The caller has authenticated the manifest through an out-of-band
    ///   channel and explicitly opts out of the in-process signature check.
    ///
    /// For production environments that issue signed bundles, prefer
    /// [`ArtifactSet::load_signed`].
    pub fn load_unsigned(manifest: &Manifest, dir: &Path) -> Result<Self, ArtifactError> {
        Self::load_artifacts(manifest, dir)
    }

    // ── Shared loading logic ──────────────────────────────────────────────

    fn load_artifacts(manifest: &Manifest, dir: &Path) -> Result<Self, ArtifactError> {
        let arcs = load_arcs(dir, &manifest.artifacts.ar1cs, &manifest.ar1cs_blake3)?;
        let pk = load_canonical::<ProvingKey<BN254>>(dir, &manifest.artifacts.pk, "pk")?;
        let vk = load_canonical::<Groth16VerifyingKey<BN254>>(dir, &manifest.artifacts.vk, "vk")?;
        let pvk =
            load_canonical::<PreparedVerifyingKey<BN254>>(dir, &manifest.artifacts.pvk, "pvk")?;
        let cfg = load_circuit_config(dir, &manifest.artifacts.circuit_config)?;
        if let Some(entry) = manifest.artifacts.evm_verifier.as_ref() {
            verify_sha256(dir, entry, "artifacts.evm_verifier.sha256")?;
        }
        let witness_gen_wasm = manifest
            .artifacts
            .witness_gen
            .as_ref()
            .map(|entry| load_bytes_with_sha(dir, entry, "artifacts.witness_gen.sha256"))
            .transpose()?;
        Ok(Self {
            pk,
            vk,
            pvk,
            arcs,
            cfg,
            witness_gen_wasm,
        })
    }
}

fn load_circuit_config(dir: &Path, entry: &ArtifactEntry) -> Result<CircuitConfig, ArtifactError> {
    let path = dir.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;
    let sha_hex = sha256_hex(&bytes);
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field: "artifacts.circuit_config.sha256",
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }
    parse_circuit_config(&bytes)
}

fn parse_circuit_config(bytes: &[u8]) -> Result<CircuitConfig, ArtifactError> {
    serde_json::from_slice::<CircuitConfig>(bytes).map_err(|e| ArtifactError::Deserialize {
        what: "circuit_config",
        message: format!("{e}"),
    })
}

fn load_arcs(
    dir: &Path,
    entry: &ArtifactEntry,
    expected_body_blake3_hex: &str,
) -> Result<ArcsFile<F>, ArtifactError> {
    let path = dir.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;

    // sha256 of the on-disk file vs manifest.
    let sha_hex = sha256_hex(&bytes);
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field: "artifacts.ar1cs.sha256",
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }

    // Parse, then verify the body_blake3 claim.
    let arcs = ArcsFile::<F>::read(&mut &bytes[..])
        .map_err(|e| ArtifactError::ArcsFormat(format!("{e}")))?;
    let body_blake3_hex = hex::encode(arcs.body_blake3());
    if body_blake3_hex != expected_body_blake3_hex {
        return Err(ArtifactError::HashMismatch {
            field: "ar1cs_blake3",
            expected: expected_body_blake3_hex.to_string(),
            got: body_blake3_hex,
        });
    }
    Ok(arcs)
}

fn load_canonical<T: CanonicalDeserialize>(
    dir: &Path,
    entry: &ArtifactEntry,
    what: &'static str,
) -> Result<T, ArtifactError> {
    let path = dir.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;

    let sha_hex = sha256_hex(&bytes);
    if sha_hex != entry.sha256 {
        let field: &'static str = match what {
            "pk" => "artifacts.pk.sha256",
            "vk" => "artifacts.vk.sha256",
            "pvk" => "artifacts.pvk.sha256",
            _ => "artifacts.unknown.sha256",
        };
        return Err(ArtifactError::HashMismatch {
            field,
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }

    T::deserialize_uncompressed(&bytes[..]).map_err(|e| ArtifactError::Deserialize {
        what,
        message: format!("{e}"),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Read `dir/entry.path` and assert `sha256(bytes) == entry.sha256`.
///
/// Used for artifact entries that need only an integrity check (no
/// `CanonicalDeserialize` follow-up), e.g. the optional
/// `Groth16Verifier.sol`. The `field` argument is the manifest path
/// reported in [`ArtifactError::HashMismatch`] so the error message
/// names the failing slot.
fn verify_sha256(
    dir: &Path,
    entry: &ArtifactEntry,
    field: &'static str,
) -> Result<(), ArtifactError> {
    let path = dir.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;
    let sha_hex = sha256_hex(&bytes);
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field,
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }
    Ok(())
}

/// Read `dir/entry.path`, assert `sha256(bytes) == entry.sha256`,
/// and return the bytes.
///
/// Same hash-check contract as [`verify_sha256`], but the file's
/// contents flow out instead of being discarded. Used for opaque
/// artifacts that downstream consumers need to hold in memory (e.g.
/// `witness_gen.wasm` instantiated through a wasm runtime).
fn load_bytes_with_sha(
    dir: &Path,
    entry: &ArtifactEntry,
    field: &'static str,
) -> Result<Vec<u8>, ArtifactError> {
    let path = dir.join(&entry.path);
    let bytes = std::fs::read(&path).map_err(|e| ArtifactError::Io {
        path: path.clone(),
        source: e,
    })?;
    let sha_hex = sha256_hex(&bytes);
    if sha_hex != entry.sha256 {
        return Err(ArtifactError::HashMismatch {
            field,
            expected: entry.sha256.clone(),
            got: sha_hex,
        });
    }
    Ok(bytes)
}
