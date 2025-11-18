use ark_ff::Field;

pub mod base;
// pub mod light_weight;
// pub mod opt_hash;

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
