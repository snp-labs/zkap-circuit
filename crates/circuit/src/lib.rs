use ark_ff::Field;

// pub mod zkpasskey;
pub mod baerae;
pub mod token;

// Re-export circuit input types
pub use baerae::input::{
    AnchorWitnessData, AudienceWitnessData, BaeraeCircuitInput, CircuitConstants,
    CircuitPublicInputs, JwtWitnessData, MerkleWitnessData, MiscWitnessData,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
