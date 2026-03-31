use core::iter;

use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::Boolean, prelude::ToBitsGadget, uint8::UInt8, uint32::UInt32};
use ark_relations::r1cs::SynthesisError;

pub trait UInt32Ext<F: PrimeField>: Sized {
    fn shr(&self, by: usize) -> Self;
    fn not(&self) -> Self;
    fn bitand(&self, other: &Self) -> Result<Self, SynthesisError>;
    fn from_bytes_be(bytes: &[UInt8<F>]) -> Result<Self, SynthesisError>;
}

impl<F: PrimeField> UInt32Ext<F> for UInt32<F> {
    fn shr(&self, by: usize) -> Self {
        assert!(by < 32);

        let zeros = iter::repeat(Boolean::constant(false)).take(by);
        let new_bits: Vec<_> = self
            .to_bits_le()
            .unwrap()
            .into_iter()
            .skip(by)
            .chain(zeros)
            .collect();
        UInt32::from_bits_le(&new_bits)
    }

    fn not(&self) -> Self {
        let new_bits: Vec<_> = self.to_bits_le().unwrap().iter().map(|bit| !bit).collect();

        UInt32::from_bits_le(&new_bits)
    }

    fn bitand(&self, rhs: &Self) -> Result<Self, SynthesisError> {
        let new_bits: Vec<_> = self
            .to_bits_le()?
            .into_iter()
            .zip(rhs.to_bits_le()?)
            .map(|(a, b)| a & b)
            .collect();
        Ok(UInt32::from_bits_le(&new_bits))
    }

    fn from_bytes_be(bytes: &[UInt8<F>]) -> Result<Self, SynthesisError> {
        assert_eq!(bytes.len(), 4);

        let mut bits: Vec<Boolean<F>> = Vec::new();
        for byte in bytes.iter().rev() {
            let b: Vec<Boolean<F>> = byte.to_bits_le()?;
            bits.extend(b);
        }
        Ok(UInt32::from_bits_le(&bits))
    }
}
