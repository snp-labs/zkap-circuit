// This file was adapted from: https://github.com/arkworks-rs/r1cs-tutorial/blob/main/simple-payments/src/random_oracle/blake2s/constraints.rs

use crate::hashes::blake2s256::Blake2s256;
use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

#[derive(Clone)]
pub struct ParametersVar;

#[derive(Clone)]
pub struct Blake2s256Gadget;

impl<ConstraintF: PrimeField> CRHSchemeGadget<Blake2s256, ConstraintF> for Blake2s256Gadget {
    type InputVar = [UInt8<ConstraintF>];
    type OutputVar = DigestVar<ConstraintF>;
    type ParametersVar = ParametersVar;

    fn evaluate(
        _: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut input_bits = Vec::with_capacity(512);
        for byte in input.iter() {
            input_bits.extend_from_slice(&byte.to_bits_le()?);
        }
        let mut result = Vec::new();
        for int in evaluate_blake2s(&input_bits)?.into_iter() {
            let chunk = int.to_bytes_le()?;
            result.extend_from_slice(&chunk);
        }
        Ok(DigestVar(result))
    }
}

impl<ConstraintF: Field> AllocVar<(), ConstraintF> for ParametersVar {
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(ParametersVar)
    }
}

#[cfg(test)]
mod test {
    use crate::hashes::blake2s256::Blake2s256;
    use crate::hashes::blake2s256::constraints::Blake2s256Gadget;
    use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
    use ark_ed_on_bn254::Fq as Fr;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn blake2s_gadget_test() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let input = [1u8; 32];

        type TestRO = Blake2s256;
        type TestROGadget = Blake2s256Gadget;

        let parameters = ();
        let primitive_result = Blake2s256::evaluate(&parameters, input).unwrap();

        let mut input_var = vec![];
        for byte in &input {
            input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
        }

        let parameters_var =
            <TestROGadget as CRHSchemeGadget<TestRO, Fr>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "gadget_parameters"),
                || Ok(&parameters),
            )
            .unwrap();
        let result_var =
            <TestROGadget as CRHSchemeGadget<TestRO, Fr>>::evaluate(&parameters_var, &input_var)
                .unwrap();

        for i in 0..32 {
            assert_eq!(primitive_result[i], result_var.0[i].value().unwrap());
        }
        assert!(cs.is_satisfied().unwrap());
    }
}
