//! zkap-circuit — the Groth16 R1CS circuit definition for the ZKAP protocol.
//!
//! Provides [`ZkapCircuit`], the main constraint synthesizer, along with all input types
//! ([`ZkapCircuitInput`], [`CircuitPublicInputs`], witness structs) and the shared
//! [`CircuitConfig`] / [`RawCircuitConfig`] parameter types.  This crate is a dependency of
//! `zkap-service` and is not usually consumed directly by application code.

use ark_ff::Field;

pub mod input;
pub mod token;
pub mod zkap;

pub mod constants;

// Re-export circuit input types
pub use input::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
