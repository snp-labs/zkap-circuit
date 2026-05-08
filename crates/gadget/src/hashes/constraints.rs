//! R1CS gadget traits for hash schemes.
//!
//! [`CRHSchemeGadget`] and [`TwoToOneCRHSchemeGadget`] are the circuit-level counterparts
//! of [`crate::hashes::CRHScheme`] and [`crate::hashes::TwoToOneCRHScheme`]. Their
//! associated `OutputVar` must satisfy the standard arkworks R1CS variable bounds
//! (`EqGadget`, `ToBytesGadget`, `CondSelectGadget`, `AllocVar`, `R1CSVar`).

use ark_ff::Field;

use core::fmt::Debug;

use ark_r1cs_std::prelude::*;

use crate::hashes::{CRHScheme, TwoToOneCRHScheme};

use super::error::HashError;

pub trait CRHSchemeGadget<H: CRHScheme, ConstraintF: Field>: Sized {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    fn evaluate(input: &Self::InputVar) -> Result<Self::OutputVar, HashError>;
}

pub trait TwoToOneCRHSchemeGadget<H: TwoToOneCRHScheme, ConstraintF: Field>: Sized {
    type InputVar: ?Sized;
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    fn evaluate(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, HashError>;

    fn compress(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, HashError>;
}
