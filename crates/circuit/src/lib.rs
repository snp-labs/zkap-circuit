use ark_ff::Field;

pub mod baerae;
pub mod token;

pub mod constants;

// Re-export circuit input types
pub use baerae::input::{
    AnchorWitness, AudienceWitness, BaeraeCircuitInput, CircuitConstants,
    CircuitPublicInputs, JwtWitness, MerkleWitness, MiscWitness,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
