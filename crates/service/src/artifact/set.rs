//! [`ArtifactSet`] — the in-memory bundle of `(pk, vk, pvk, arcs, cfg)`
//! and the two caller-facing loaders.

use std::path::Path;

use ark_ar1cs::format::ArcsFile;
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use circuit::types::{BN254, CircuitConfig, F};
use sha2::{Digest, Sha256};

use super::error::ArtifactError;
use crate::manifest::{ArtifactEntry, Manifest};

/// In-memory bundle of every CRS artifact a `Prover` needs.
///
/// Populated either by [`ArtifactSet::load`] (manifest-validated,
/// canonical) or [`ArtifactSet::load_unverified`] (non-canonical, tests
/// only).
pub struct ArtifactSet {
    /// Groth16 proving key — loaded from `pk.bin`.
    pub pk: ProvingKey<BN254>,
    /// Groth16 verifying key — loaded from `vk.bin`.
    pub vk: VerifyingKey<BN254>,
    /// Prepared verifying key — loaded from `pvk.bin`.
    pub pvk: PreparedVerifyingKey<BN254>,
    /// `.ar1cs` body — loaded from `circuit.ar1cs`.
    pub arcs: ArcsFile<F>,
    /// Circuit configuration — loaded from `config.json`.
    pub cfg: CircuitConfig,
}

impl ArtifactSet {
    /// Load every artifact named in `manifest` from `dir` and verify the
    /// integrity claims (sha256 + `ar1cs_blake3`) before returning.
    ///
    /// This is the **canonical production entry point**: the manifest is
    /// the trust boundary, and every artifact the prover sees has been
    /// hash-checked here.
    pub fn load(manifest: &Manifest, dir: &Path) -> Result<Self, ArtifactError> {
        let arcs = load_arcs(dir, &manifest.artifacts.ar1cs, &manifest.ar1cs_blake3)?;
        let pk = load_canonical::<ProvingKey<BN254>>(dir, &manifest.artifacts.pk, "pk")?;
        let vk = load_canonical::<VerifyingKey<BN254>>(dir, &manifest.artifacts.vk, "vk")?;
        let pvk =
            load_canonical::<PreparedVerifyingKey<BN254>>(dir, &manifest.artifacts.pvk, "pvk")?;
        let cfg = load_circuit_config(dir, &manifest.artifacts.circuit_config)?;
        Ok(Self {
            pk,
            vk,
            pvk,
            arcs,
            cfg,
        })
    }

    /// Load every artifact from the hard-coded post-migration layout
    /// **without** consulting a manifest.
    ///
    /// **non-canonical: bypasses manifest hash validation; production
    /// callers MUST use [`ArtifactSet::load`].** This entry point exists
    /// for tests, dev tools, and caller-trusted environments where
    /// integrity has been established out of band. Calls in production
    /// code are policy violations and are detectable by the
    /// `scripts/check-removed-api.sh` rule set.
    pub fn load_unverified(dir: &Path) -> Result<Self, ArtifactError> {
        let arcs_path = dir.join("circuit.ar1cs");
        let arcs_bytes = std::fs::read(&arcs_path).map_err(|e| ArtifactError::Io {
            path: arcs_path.clone(),
            source: e,
        })?;
        let arcs = ArcsFile::<F>::read(&mut &arcs_bytes[..])
            .map_err(|e| ArtifactError::ArcsFormat(format!("{e}")))?;

        let pk = load_canonical_raw::<ProvingKey<BN254>>(&dir.join("pk.bin"), "pk")?;
        let vk = load_canonical_raw::<VerifyingKey<BN254>>(&dir.join("vk.bin"), "vk")?;
        let pvk = load_canonical_raw::<PreparedVerifyingKey<BN254>>(&dir.join("pvk.bin"), "pvk")?;
        let cfg = load_circuit_config_raw(&dir.join("config.json"))?;

        Ok(Self {
            pk,
            vk,
            pvk,
            arcs,
            cfg,
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

fn load_circuit_config_raw(path: &Path) -> Result<CircuitConfig, ArtifactError> {
    let bytes = std::fs::read(path).map_err(|e| ArtifactError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
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

fn load_canonical_raw<T: CanonicalDeserialize>(
    path: &Path,
    what: &'static str,
) -> Result<T, ArtifactError> {
    let bytes = std::fs::read(path).map_err(|e| ArtifactError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
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
