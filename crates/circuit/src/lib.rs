//! zkap-circuit — the Groth16 R1CS circuit definition for the ZKAP protocol.
//!
//! Provides [`ZkapCircuit`](crate::zkap::ZkapCircuit), the main constraint
//! synthesizer, along with all witness types ([`ZkapCircuitInput`],
//! [`CircuitPublicInputs`], witness structs) and the shared
//! [`CircuitConfig`](crate::types::CircuitConfig) parameter type.
//! This crate is a dependency of `zkap-service` and is not usually
//! consumed directly by application code.

// Workspace lint gate — see docs/LOCKS.md.
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::invalid_html_tags)]

#[cfg(feature = "constraints")]
use ark_ff::Field;

#[cfg(feature = "constraints")]
mod audience;
#[cfg(feature = "constraints")]
mod output_binding;

#[cfg(feature = "constraints")]
pub mod token;
#[cfg(feature = "constraints")]
pub mod witness;
#[cfg(feature = "constraints")]
pub mod zkap;

pub mod types;

// Re-export circuit witness types
#[cfg(feature = "constraints")]
pub use witness::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};

/// Adapter for objects that can be reduced to the Groth16 public-input
/// vector accepted by `ark_groth16::Groth16::verify_proof`. Implemented
/// for [`ZkapCircuit`](crate::zkap::ZkapCircuit) and used by
/// `zkap-service::proof::verify` to assemble the verifier input from a
/// completed prover side.
#[cfg(feature = "constraints")]
pub trait ExposesPublicInputs<F: Field> {
    /// Return the ordered public inputs for this circuit instance.
    /// The element order must match
    /// [`CircuitPublicInputs::to_vec`](crate::CircuitPublicInputs::to_vec).
    fn public_inputs(&self) -> Vec<F>;
}
