pub mod anchor;
pub mod dto;
pub mod error;
pub mod hash;
pub mod jwt;
pub mod manifest;
pub mod proof;

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
