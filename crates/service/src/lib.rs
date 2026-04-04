pub mod anchor;
pub mod dto;
pub mod error;
pub mod hash;
pub mod jwt;
pub mod manifest;
pub mod proof;

use std::sync::OnceLock;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use circuit::constants::F;

/// Cached Poseidon parameters — constructed once, shared across all modules.
pub(crate) fn poseidon_params() -> &'static PoseidonConfig<F> {
    static PARAMS: OnceLock<PoseidonConfig<F>> = OnceLock::new();
    PARAMS.get_or_init(gadget::hashes::poseidon::get_poseidon_params::<F>)
}

/// Extract forbidden_string as &str from CircuitConfig.
pub(crate) fn forbidden_str(params: &CircuitConfig) -> Result<&str, error::ApplicationError> {
    std::str::from_utf8(&params.forbidden_string)
        .map_err(|e| error::ApplicationError::InvalidFormat(format!("Invalid forbidden_string: {}", e)))
}

pub use circuit::constants;
pub use ark_utils::evm;
pub use ark_utils::io;

// Public API (7 functions)
pub use proof::{groth16_setup, prove, verify};
pub use anchor::poseidon::generate_anchor;
pub use hash::{generate_hash, generate_aud_hash, generate_leaf_hash};

// Public types
pub use anchor::types::Secret;
pub use proof::RawProofRequest;
pub use circuit::constants::{CircuitConfig, PAD_CHAR};
