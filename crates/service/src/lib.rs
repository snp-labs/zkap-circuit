//! zkap-service — high-level API for ZKAP proof generation and verification.
//!
//! # Public API
//!
//! **Always available:**
//! - [`generate_hash`], [`generate_aud_hash`], [`generate_leaf_hash`] — Poseidon hashing
//! - [`generate_anchor`] — threshold anchor generation
//! - [`load_circuit_config`] — load [`CircuitConfig`] from JSON
//!
//! **`proof` feature (default):**
//! - [`setup`] — trusted setup: generates proving/verifying keys and writes them to disk
//! - [`prove`] — generate Groth16 zero-knowledge proofs
//! - [`verify`] — verify Groth16 proofs

pub(crate) mod anchor;
pub(crate) mod dto;
pub mod error;
pub(crate) mod hash;

#[cfg(feature = "proof")]
pub(crate) mod crs;
#[cfg(feature = "proof")]
pub mod evm;
#[cfg(feature = "proof")]
pub mod jwt;
#[cfg(feature = "proof")]
pub mod proof;

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use circuit::constants::F;
use std::sync::OnceLock;

// Field-codec re-export — single source of truth lives in
// `ark-utils::field_codec` (PR4 / Step 7 of the DTO consolidation plan).
pub(crate) use ark_utils::field_codec::field_to_hex;

/// Cached Poseidon parameters — constructed once, shared across all modules.
pub(crate) fn poseidon_params() -> &'static PoseidonConfig<F> {
    static PARAMS: OnceLock<PoseidonConfig<F>> = OnceLock::new();
    PARAMS.get_or_init(gadget::hashes::poseidon::get_poseidon_params::<F>)
}

/// Extract forbidden_string as &str from CircuitConfig.
pub(crate) fn forbidden_str(params: &CircuitConfig) -> Result<&str, error::ApplicationError> {
    Ok(params.forbidden_string.as_str())
}

/// Load a [`CircuitConfig`] from a JSON config file.
///
/// Accepts both `config.json` produced by [`setup`] and stand-alone config files
/// in the same [`CircuitConfig`] JSON format.
pub fn load_circuit_config(
    path: &std::path::Path,
) -> Result<CircuitConfig, error::ApplicationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        error::ApplicationError::InvalidFormat(format!("Failed to read config: {}", e))
    })?;
    let config: circuit::constants::CircuitConfig =
        serde_json::from_str(&content).map_err(|e| {
            error::ApplicationError::InvalidFormat(format!("Failed to parse config: {}", e))
        })?;
    config
        .validate()
        .map_err(error::ApplicationError::InvalidFormat)?;
    Ok(config)
}

pub use circuit::constants;

// Public API (always available)
pub use anchor::poseidon::generate_anchor;
pub use anchor::types::Secret;
pub use circuit::constants::CircuitConfig;
pub use dto::AudHashResult;
pub use hash::{generate_aud_hash, generate_hash, generate_leaf_hash};

// Public API (proof feature only)
#[cfg(feature = "proof")]
pub use dto::{PerProofPublicInputs, ProofComponents, SharedPublicInputs, ZkapProofResult};
#[cfg(feature = "proof")]
pub use proof::{RawProofRequest, SetupOutput, VerifyingContext, ZkapPerJwtFields, ZkapSharedFields};
#[cfg(feature = "proof")]
pub use proof::{prove, setup, verify};
