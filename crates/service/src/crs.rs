//! CRS persistence — serialise a [`SetupOutput`] to disk under the
//! post-migration bundle layout.
//!
//! # Bundle layout (Commit 2 of the 2026-05 ark-ar1cs boundary migration)
//!
//! [`persist_setup_output`] writes six files into a target directory:
//!
//! | File                  | Content                                                          |
//! |-----------------------|------------------------------------------------------------------|
//! | `circuit.ar1cs`       | R1CS body in ark-ar1cs canonical envelope (`ArcsFile::write`)    |
//! | `pk.bin`              | Proving key (arkworks `CanonicalSerialize` uncompressed)         |
//! | `vk.bin`              | Verifying key (arkworks `CanonicalSerialize` uncompressed)       |
//! | `pvk.bin`             | Prepared verifying key (arkworks `CanonicalSerialize`)           |
//! | `Groth16Verifier.sol` | Solidity on-chain verifier contract                              |
//! | `config.json`         | Circuit configuration in `CircuitConfig` JSON                    |
//!
//! `manifest.json` is the seventh bundle file but is produced by the CLI
//! (`generate_setup`) — it carries build/commit metadata that the
//! service does not own.
//!
//! Earlier filenames and the wasm witness substrate that pre-dated the
//! 2026-05 ark-ar1cs boundary migration are no longer written; the
//! seven entries above are the entire bundle contract enforced by
//! `scripts/check-bundle-layout.sh`.

use std::io::Cursor;
use std::path::Path;

use ark_ar1cs::format::ArcsFile;
use ark_serialize::CanonicalSerialize;
use circuit::types::{CircuitConfig, F};
use zkap_evm_verifier::SolidityContractGenerator;

use crate::error::ApplicationError;
use crate::proof::SetupOutput;

// ── Internal API (called by setup()) ─────────────────────────────────────────

/// Persist a [`SetupOutput`] and the originating [`CircuitConfig`] to
/// `output_dir` under the post-migration bundle layout.
///
/// Creates `output_dir` if it does not already exist, then writes six
/// files (see module-level table). Called internally by
/// [`crate::proof::setup`].
pub(crate) fn persist_setup_output(
    setup: &SetupOutput,
    config: &CircuitConfig,
    output_dir: &Path,
    arcs: &ArcsFile<F>,
) -> Result<(), ApplicationError> {
    std::fs::create_dir_all(output_dir)?;

    write_canonical_uncompressed(&setup.pk, &output_dir.join("pk.bin"), "pk.bin")?;
    write_canonical_uncompressed(&setup.vk, &output_dir.join("vk.bin"), "vk.bin")?;
    write_canonical_uncompressed(&setup.pvk, &output_dir.join("pvk.bin"), "pvk.bin")?;

    write_arcs(arcs, &output_dir.join("circuit.ar1cs"))?;

    setup
        .vk
        .generate_solidity(output_dir.join("Groth16Verifier.sol"))
        .map_err(|e| {
            ApplicationError::Other(format!("Failed to write Groth16Verifier.sol: {}", e))
        })?;

    write_config_json(config, &output_dir.join("config.json"))?;

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn write_canonical_uncompressed<T: CanonicalSerialize>(
    value: &T,
    path: &Path,
    label: &str,
) -> Result<(), ApplicationError> {
    let mut cursor = Cursor::new(Vec::new());
    value.serialize_uncompressed(&mut cursor).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to serialize {label} to '{}': {}",
            path.display(),
            e
        ))
    })?;
    std::fs::write(path, cursor.get_ref())?;
    Ok(())
}

fn write_arcs(arcs: &ArcsFile<F>, path: &Path) -> Result<(), ApplicationError> {
    let mut file = std::fs::File::create(path).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to create circuit.ar1cs at '{}': {}",
            path.display(),
            e
        ))
    })?;
    arcs.write(&mut file).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to write circuit.ar1cs to '{}': {}",
            path.display(),
            e
        ))
    })?;
    Ok(())
}

fn write_config_json(config: &CircuitConfig, path: &Path) -> Result<(), ApplicationError> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| ApplicationError::Other(format!("Failed to serialize config.json: {}", e)))?;
    std::fs::write(path, json)?;
    Ok(())
}
