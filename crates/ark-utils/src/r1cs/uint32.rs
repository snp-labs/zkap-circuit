//! R1CS extension trait for 32-bit unsigned integers.
//!
//! Exports: [`UInt32Ext`].  Adds bitwise operations (`shr`, `not`, `bitand`)
//! and big-endian byte construction (`from_bytes_be`) to the arkworks
//! `UInt32` type.  Requires the `r1cs` feature (default-on).

use core::iter;

use ark_ff::PrimeField;
use ark_r1cs_std::{prelude::Boolean, prelude::ToBitsGadget, uint8::UInt8, uint32::UInt32};
use ark_relations::gr1cs::SynthesisError;

/// Bitwise / byte-construction helpers missing from the upstream
/// [`UInt32`] gadget. Implemented for `UInt32<F>` below.
pub trait UInt32Ext<F: PrimeField>: Sized {
    /// Logical right shift by `by` positions (`by < 32`).
    fn shr(&self, by: usize) -> Self;
    /// Bitwise NOT (one's complement).
    fn not(&self) -> Self;
    /// Bitwise AND with `other`. Both operands keep their existing R1CS
    /// allocations; only the resulting bits are newly allocated.
    fn bitand(&self, other: &Self) -> Result<Self, SynthesisError>;
    /// Reconstruct a 32-bit value from exactly four big-endian
    /// [`UInt8`] bytes (`bytes[0]` is the most significant byte).
    fn from_bytes_be(bytes: &[UInt8<F>]) -> Result<Self, SynthesisError>;
}

impl<F: PrimeField> UInt32Ext<F> for UInt32<F> {
    fn shr(&self, by: usize) -> Self {
        assert!(by < 32);

        let zeros = iter::repeat_n(Boolean::constant(false), by);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{GR1CSVar, uint8::UInt8, uint32::UInt32};
    use ark_relations::gr1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

    #[test]
    fn test_uint32_shr_basic() {
        let _cs = ConstraintSystem::<F>::new_ref();
        let val = UInt32::<F>::constant(0xFF00u32);
        let shifted = val.shr(8);
        assert_eq!(shifted.value().unwrap(), 0xFFu32);
    }

    #[test]
    fn test_uint32_shr_by_zero() {
        let _cs = ConstraintSystem::<F>::new_ref();
        let val = UInt32::<F>::constant(12345u32);
        let shifted = val.shr(0);
        assert_eq!(shifted.value().unwrap(), 12345u32);
    }

    #[test]
    fn test_uint32_shr_by_31() {
        let _cs = ConstraintSystem::<F>::new_ref();
        let val = UInt32::<F>::constant(0x80000000u32);
        let shifted = val.shr(31);
        assert_eq!(shifted.value().unwrap(), 1u32);
    }

    #[test]
    fn test_uint32_not_basic() {
        let _cs = ConstraintSystem::<F>::new_ref();
        let val = UInt32::<F>::constant(0u32);
        let notted = val.not();
        assert_eq!(notted.value().unwrap(), 0xFFFFFFFFu32);

        let val2 = UInt32::<F>::constant(0xFFFFFFFFu32);
        let notted2 = val2.not();
        assert_eq!(notted2.value().unwrap(), 0u32);
    }

    #[test]
    fn test_uint32_bitand_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let a = UInt32::<F>::constant(0xFF00u32);
        let b = UInt32::<F>::constant(0x0FF0u32);
        let result = a.bitand(&b).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), 0x0F00u32);
    }

    #[test]
    fn test_uint32_from_bytes_be_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let bytes = vec![
            UInt8::<F>::constant(0x01),
            UInt8::<F>::constant(0x02),
            UInt8::<F>::constant(0x03),
            UInt8::<F>::constant(0x04),
        ];
        let result = UInt32::<F>::from_bytes_be(&bytes).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), 0x01020304u32);
    }

    #[test]
    fn test_uint32_from_bytes_be_endianness() {
        let cs = ConstraintSystem::<F>::new_ref();
        let bytes = vec![
            UInt8::<F>::constant(0x00),
            UInt8::<F>::constant(0x00),
            UInt8::<F>::constant(0x00),
            UInt8::<F>::constant(0x01),
        ];
        let result = UInt32::<F>::from_bytes_be(&bytes).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), 1u32);
    }

    #[test]
    #[should_panic]
    fn test_uint32_from_bytes_be_wrong_len_panics() {
        let bytes = vec![
            UInt8::<F>::constant(0x01),
            UInt8::<F>::constant(0x02),
            UInt8::<F>::constant(0x03),
        ];
        let _ = UInt32::<F>::from_bytes_be(&bytes);
    }
}
