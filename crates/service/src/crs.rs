//! CRS persistence — serialise a [`SetupOutput`] to disk.
//!
//! # Overview
//!
//! [`persist_setup_output`] writes five files into a target directory:
//!
//! | File | Content |
//! |------|---------|
//! | `pk.key` | Proving key (uncompressed binary) |
//! | `vk.key` | Verifying key (uncompressed binary) |
//! | `pvk.key` | Prepared verifying key (uncompressed binary) |
//! | `Groth16Verifier.sol` | Solidity on-chain verifier contract |
//! | `config.json` | Circuit configuration in JSON (RawCircuitConfig format) |

use std::io::Cursor;
use std::path::Path;

use crate::evm::groth16_verifier_solidity::SolidityContractGenerator;
use ark_ar1cs_format::ArcsFile;
use ark_ar1cs_zkey::ArzkeyFile;
use ark_serialize::CanonicalSerialize;
use circuit::constants::{CircuitConfig, F, RawCircuitConfig};

use crate::error::ApplicationError;
use crate::proof::SetupOutput;

// ── Internal API (called by setup()) ─────────────────────────────────────────

/// Persist a [`SetupOutput`] and the originating [`CircuitConfig`] to `output_dir`.
///
/// Creates `output_dir` if it does not already exist, then writes five
/// files (see module-level table). Called internally by [`crate::proof::setup`].
pub(crate) fn persist_setup_output(
    setup: &SetupOutput,
    config: &CircuitConfig,
    output_dir: &Path,
    arcs: ArcsFile<F>,
) -> Result<(), ApplicationError> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to create output directory '{}': {}",
            output_dir.display(),
            e
        ))
    })?;

    write_key_file(&setup.pk, &output_dir.join("pk.key"))?;
    write_key_file(&setup.vk, &output_dir.join("vk.key"))?;
    write_key_file(&setup.pvk, &output_dir.join("pvk.key"))?;

    // Write the .arzkey file (proving key + R1CS matrices in ark-ar1cs format).
    // pk_path in RawProofRequest should now point to this file instead of pk.key.
    let arzkey = ArzkeyFile::from_setup_output(arcs, setup.pk.clone());
    let arzkey_path = output_dir.join("pk.arzkey");
    let mut arzkey_file = std::fs::File::create(&arzkey_path).map_err(|e| {
        ApplicationError::Other(format!(
            "Failed to create '{}': {}",
            arzkey_path.display(),
            e
        ))
    })?;
    arzkey.write(&mut arzkey_file).map_err(|e| {
        ApplicationError::Other(format!("Failed to write pk.arzkey: {}", e))
    })?;

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

fn write_config_json(config: &CircuitConfig, path: &Path) -> Result<(), ApplicationError> {
    let raw = config_to_raw(config);
    let json = serde_json::to_string_pretty(&raw)
        .map_err(|e| ApplicationError::Other(format!("Failed to serialize config.json: {}", e)))?;
    std::fs::write(path, json)
        .map_err(|e| ApplicationError::Other(format!("Failed to write config.json: {}", e)))
}

fn config_to_raw(config: &CircuitConfig) -> RawCircuitConfig {
    RawCircuitConfig {
        max_jwt_b64_len: config.max_jwt_b64_len,
        max_payload_b64_len: config.max_payload_b64_len,
        max_aud_len: config.max_aud_len,
        max_exp_len: config.max_exp_len,
        max_iss_len: config.max_iss_len,
        max_nonce_len: config.max_nonce_len,
        max_sub_len: config.max_sub_len,
        n: config.n,
        k: config.k,
        tree_height: config.tree_height,
        num_audience_limit: config.num_audience_limit,
        claims: config
            .claims
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect(),
        forbidden_string: String::from_utf8_lossy(&config.forbidden_string).into_owned(),
    }
}
