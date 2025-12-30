use ark_ff::Field;

// pub mod zkpasskey;
pub mod baerae;
pub mod to_solidity;
pub mod token;

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
