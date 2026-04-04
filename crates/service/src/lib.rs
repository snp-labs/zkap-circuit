pub mod api;
mod app;
pub mod dto;
pub mod error;
pub mod manifest;

pub use circuit::constants;
pub use ark_utils::evm;
pub use ark_utils::io;

pub use api::setup::groth16_setup;
pub use api::snark::{prove, verify};
pub use api::anchor::generate_anchor;
pub use api::hash::{generate_hash, generate_aud_hash, generate_leaf_hash};
pub use app::anchor::types::Secret;
pub use app::snark::RawProofRequest;
pub use circuit::constants::{CircuitConfig, PAD_CHAR};
