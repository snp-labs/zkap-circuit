use ark_ff::Field;

pub mod input;
pub mod token;
pub mod zkap;

pub mod constants;

// Re-export circuit input types
pub use input::{
    AnchorWitness, AudienceWitness, ZkapCircuitInput, CircuitConstants,
    CircuitPublicInputs, JwtWitness, MerkleWitness, MiscWitness,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
