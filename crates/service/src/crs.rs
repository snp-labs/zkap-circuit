//! CRS persistence — serialise a [`SetupOutput`] to disk and produce a `manifest.json`.
//!
//! # Overview
//!
//! [`persist_crs`] writes five files into a target directory:
//!
//! | File | Content |
//! |------|---------|
//! | `pk.key` | Proving key (uncompressed binary) |
//! | `vk.key` | Verifying key (uncompressed binary) |
//! | `pvk.key` | Prepared verifying key (uncompressed binary) |
//! | `Groth16Verifier.sol` | Solidity on-chain verifier contract |
//! | `manifest.json` | Metadata: version, profile, circuit params, SHA-256 file hashes |
//!
//! The `manifest.json` format is compatible with [`crate::manifest::validate_crs_manifest`],
//! so any CRS produced by this module can be verified before proving.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use ark_serialize::CanonicalSerialize;
use ark_utils::evm::groth16_verifier_solidity::SolidityContractGenerator;
use circuit::constants::CircuitConfig;
use sha2::{Digest, Sha256};

use crate::error::ApplicationError;
use crate::proof::SetupOutput;

// ── Public types ─────────────────────────────────────────────────────────────

/// Filesystem paths of the five files produced by [`persist_crs`].
pub struct CrsPaths {
    pub pk: PathBuf,
    pub vk: PathBuf,
    pub pvk: PathBuf,
    pub solidity: PathBuf,
    pub manifest: PathBuf,
}

/// Configuration for CRS file persistence.
pub struct CrsPersistConfig {
    /// Directory where all CRS files will be written.
    pub output_dir: PathBuf,
    /// Profile label recorded in `manifest.json` (e.g. `"dev"`, `"prod"`).
    pub profile: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Persist a [`SetupOutput`] to disk.
///
/// Creates `persist.output_dir` if it does not already exist, then writes five
/// files (see module-level table).  Returns the paths of all written files.
///
/// # Errors
///
/// Returns [`ApplicationError::Other`] on any I/O or serialisation failure.
pub fn persist_crs(
    setup: &SetupOutput,
    config: &CircuitConfig,
    persist: &CrsPersistConfig,
) -> Result<CrsPaths, ApplicationError> {
    let dir = &persist.output_dir;

    std::fs::create_dir_all(dir).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to create output directory '{}': {}",
            dir.display(),
            e
        ))
    })?;

    let pk_path = dir.join("pk.key");
    let vk_path = dir.join("vk.key");
    let pvk_path = dir.join("pvk.key");
    let sol_path = dir.join("Groth16Verifier.sol");
    let manifest_path = dir.join("manifest.json");

    write_key_file(&setup.pk, &pk_path)?;
    write_key_file(&setup.vk, &vk_path)?;
    write_key_file(&setup.pvk, &pvk_path)?;

    setup.vk.generate_solidity(&sol_path);

    let paths = CrsPaths {
        pk: pk_path,
        vk: vk_path,
        pvk: pvk_path,
        solidity: sol_path,
        manifest: manifest_path,
    };

    write_manifest_file(&paths, config, persist)?;

    Ok(paths)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn write_key_file<T: CanonicalSerialize>(value: &T, path: &Path) -> Result<(), ApplicationError> {
    let mut cursor = Cursor::new(Vec::new());
    value.serialize_uncompressed(&mut cursor).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to serialize key to '{}': {}",
            path.display(),
            e
        ))
    })?;
    std::fs::write(path, cursor.get_ref()).map_err(|e| {
        ApplicationError::Other(format!("Failed to write '{}': {}", path.display(), e))
    })
}

fn sha256_file(path: &Path) -> Result<String, ApplicationError> {
    let bytes = std::fs::read(path).map_err(|e| {
        ApplicationError::Other(format!("Failed to read '{}': {}", path.display(), e))
    })?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn write_manifest_file(
    paths: &CrsPaths,
    config: &CircuitConfig,
    persist: &CrsPersistConfig,
) -> Result<(), ApplicationError> {
    let file_entries = [
        (&paths.pk, "pk.key"),
        (&paths.vk, "vk.key"),
        (&paths.pvk, "pvk.key"),
        (&paths.solidity, "Groth16Verifier.sol"),
    ];

    let mut file_hashes: HashMap<&str, String> = HashMap::new();
    for (path, name) in &file_entries {
        file_hashes.insert(name, sha256_file(path)?);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let manifest = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "profile": persist.profile,
        "generated_at": timestamp,
        "params": {
            "MAX_JWT_B64_LEN":    config.max_jwt_b64_len,
            "MAX_PAYLOAD_B64_LEN": config.max_payload_b64_len,
            "MAX_AUD_LEN":        config.max_aud_len,
            "MAX_EXP_LEN":        config.max_exp_len,
            "MAX_ISS_LEN":        config.max_iss_len,
            "MAX_NONCE_LEN":      config.max_nonce_len,
            "MAX_SUB_LEN":        config.max_sub_len,
            "N":                  config.n,
            "K":                  config.k,
            "TREE_HEIGHT":        config.tree_height,
            "NUM_AUDIENCE_LIMIT": config.num_audience_limit,
        },
        "files": file_hashes,
    });

    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| ApplicationError::Other(format!("Failed to serialize manifest: {}", e)))?;

    std::fs::write(&paths.manifest, &json).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to write '{}': {}",
            paths.manifest.display(),
            e
        ))
    })?;

    Ok(())
}
