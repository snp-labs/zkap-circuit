//! zkap-circuit — the Groth16 R1CS circuit definition for the ZKAP protocol.
//!
//! Provides [`ZkapCircuit`], the main constraint synthesizer, along with all witness types
//! ([`ZkapCircuitInput`], [`CircuitPublicInputs`], witness structs) and the shared
//! [`CircuitConfig`](crate::types::CircuitConfig) parameter type (re-exported from
//! `ark-utils::wire`).  This crate is a dependency of `zkap-service` and is not usually
//! consumed directly by application code.

use ark_ff::Field;

pub mod token;
pub mod witness;
pub mod zkap;

pub mod types;

// Re-export circuit witness types
pub use witness::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
