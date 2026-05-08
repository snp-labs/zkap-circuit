//! `DigestVar` — the canonical R1CS type for a 32-byte SHA-256 output.
//!
//! [`DigestVar`] wraps a `[UInt8<F>; 32]` array and implements `AllocVar`, `R1CSVar`,
//! `EqGadget`, `ToBytesGadget`, and `CondSelectGadget` so it can be used as a
//! standard constraint variable. It is the output type of [`crate::hashes::sha256::constraints::SHA256Gadget`]
//! and is re-exported from [`crate::hashes::sha256`] as the primary import path.

use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    prelude::{Boolean, ToBytesGadget},
    select::CondSelectGadget,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

#[derive(Clone, Debug)]
pub struct DigestVar<F: PrimeField>(pub Vec<UInt8<F>>);

impl<ConstraintF> EqGadget<ConstraintF> for DigestVar<ConstraintF>
where
    ConstraintF: PrimeField,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0.is_eq(&other.0)
    }
}

impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for DigestVar<ConstraintF> {
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<ConstraintF: PrimeField> CondSelectGadget<ConstraintF> for DigestVar<ConstraintF>
where
    Self: Sized,
    Self: Clone,
{
    fn conditionally_select(
        cond: &Boolean<ConstraintF>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let bytes: Result<Vec<_>, _> = true_value
            .0
            .iter()
            .zip(false_value.0.iter())
            .map(|(t, f)| UInt8::conditionally_select(cond, t, f))
            .collect();
        bytes.map(DigestVar)
    }
}

impl<ConstraintF: PrimeField> AllocVar<Vec<u8>, ConstraintF> for DigestVar<ConstraintF> {
    // Allocates 32 UInt8s
    fn new_variable<T: Borrow<Vec<u8>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let native_bytes = f();

        if native_bytes
            .as_ref()
            .map(|b| b.borrow().len())
            .unwrap_or(32)
            != 32
        {
            panic!("DigestVar must be allocated with precisely 32 bytes");
        }

        // For each i, allocate the i-th byte
        let var_bytes: Result<Vec<_>, _> = (0..32)
            .map(|i| {
                UInt8::new_variable(
                    cs.clone(),
                    || native_bytes.as_ref().map(|v| v.borrow()[i]).map_err(|e| *e),
                    mode,
                )
            })
            .collect();

        var_bytes.map(DigestVar)
    }
}

impl<ConstraintF: PrimeField> R1CSVar<ConstraintF> for DigestVar<ConstraintF> {
    type Value = [u8; 32];

    fn cs(&self) -> ConstraintSystemRef<ConstraintF> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut buf = [0u8; 32];
        for (b, var) in buf.iter_mut().zip(self.0.iter()) {
            *b = var.value()?;
        }

        Ok(buf)
    }
}
