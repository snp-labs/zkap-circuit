//! zkap-service — high-level API for ZKAP proof generation and verification.
//!
//! This crate exposes the seven core public functions (`groth16_setup`, `prove`, `verify`,
//! `generate_anchor`, `generate_hash`, `generate_aud_hash`, `generate_leaf_hash`) plus the
//! supporting types (`Secret`, `RawProofRequest`, `CircuitConfig`) that callers need to produce
//! and verify Groth16 zero-knowledge proofs for the ZKAP protocol.

pub(crate) mod anchor;
pub(crate) mod dto;
pub mod error;
pub(crate) mod hash;

#[cfg(feature = "proof")]
pub mod crs;
#[cfg(feature = "proof")]
pub mod jwt;
#[cfg(feature = "proof")]
pub mod manifest;
#[cfg(feature = "proof")]
pub mod evm;
#[cfg(feature = "proof")]
pub mod proof;

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use circuit::constants::F;
use std::sync::OnceLock;

/// Serialize a field element as a 0x-prefixed big-endian hex string.
pub(crate) fn field_to_hex<F: PrimeField>(f: F) -> String {
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

/// Cached Poseidon parameters — constructed once, shared across all modules.
pub(crate) fn poseidon_params() -> &'static PoseidonConfig<F> {
    static PARAMS: OnceLock<PoseidonConfig<F>> = OnceLock::new();
    PARAMS.get_or_init(gadget::hashes::poseidon::get_poseidon_params::<F>)
}

/// Extract forbidden_string as &str from CircuitConfig.
pub(crate) fn forbidden_str(params: &CircuitConfig) -> Result<&str, error::ApplicationError> {
    std::str::from_utf8(&params.forbidden_string).map_err(|e| {
        error::ApplicationError::InvalidFormat(format!("Invalid forbidden_string: {}", e))
    })
}

/// Load a [`CircuitConfig`] from a JSON config file.
pub fn load_circuit_config(path: &std::path::Path) -> Result<CircuitConfig, error::ApplicationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        error::ApplicationError::InvalidFormat(format!("Failed to read config: {}", e))
    })?;
    let raw: circuit::constants::RawCircuitConfig = serde_json::from_str(&content).map_err(|e| {
        error::ApplicationError::InvalidFormat(format!("Failed to parse config: {}", e))
    })?;
    let config = CircuitConfig::from(raw);
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
pub use dto::{AudHashResult, GenerateAnchorResCore};
pub use hash::{generate_aud_hash, generate_hash, generate_leaf_hash};

// Public API (proof feature only)
#[cfg(feature = "proof")]
pub use crs::{CrsPaths, CrsPersistConfig, persist_crs};
#[cfg(feature = "proof")]
pub use dto::{ProofComponents, ZkapProofResult};
#[cfg(feature = "proof")]
pub use proof::{RawProofRequest, VerifyingContext};
#[cfg(feature = "proof")]
pub use proof::{groth16_setup, groth16_setup_and_save, prove, verify};
