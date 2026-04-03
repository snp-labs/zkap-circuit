use ark_ff::Field;

pub mod baerae;
pub mod token;

pub mod constants;
pub mod field_parser;
pub mod error;
pub mod io;
pub mod evm;
pub mod text;

// Re-export circuit input types
pub use baerae::input::{
    AnchorWitness, AudienceWitness, BaeraeCircuitInput, CircuitConstants,
    CircuitPublicInputs, JwtWitness, MerkleWitness, MiscWitness,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
