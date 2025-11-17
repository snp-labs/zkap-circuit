use std::{iter, marker::PhantomData};

use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::ToBytesGadget, uint8::UInt8, uint32::UInt32};

use crate::hashes::{
    Parameter,
    constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
    error::HashError,
};

use super::{DigestVar, H, SHA256, SHA256Gadget};

impl<F: PrimeField, P: Parameter<F>> Default for SHA256Gadget<F, P> {
    fn default() -> Self {
        Self {
            state: H.iter().cloned().map(UInt32::constant).collect(),
            completed_data_blocks: 0,
            pending: iter::repeat(0u8).take(64).map(UInt8::constant).collect(),
            num_pending: 0,
            _params: PhantomData,
        }
    }
}

impl<F, P> CRHSchemeGadget<SHA256<F, P>, F> for SHA256Gadget<F, P>
where
    F: PrimeField,
    P: Parameter<F>,
{
    type InputVar = [UInt8<F>];
    type OutputVar = DigestVar<F>;

    fn evaluate(input: &Self::InputVar) -> Result<Self::OutputVar, HashError> {
        Self::digest(input).map_err(HashError::SynthesisError)
    }
}

impl<F, P> TwoToOneCRHSchemeGadget<SHA256<F, P>, F> for SHA256Gadget<F, P>
where
    F: PrimeField,
    P: Parameter<F>,
{
    type InputVar = [UInt8<F>];
    type OutputVar = DigestVar<F>;

    fn evaluate(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, HashError> {
        let mut h = Self::default();
        h.update(left_input)?;
        h.update(right_input)?;
        h.finalize().map_err(HashError::SynthesisError)
    }

    fn compress(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, HashError> {
        // Convert output to bytes
        let left_input = left_input.to_bytes_le()?;
        let right_input = right_input.to_bytes_le()?;
        <Self as TwoToOneCRHSchemeGadget<SHA256<F, P>, F>>::evaluate(&left_input, &right_input)
    }
}
