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

/// R1CS gadget trait for a single-input CRH; circuit-level counterpart of
/// [`crate::hashes::CRHScheme`].
///
/// `OutputVar` must satisfy the standard arkworks R1CS variable bounds so it can
/// be embedded in Merkle tree path variables and equality constraints.
pub trait CRHSchemeGadget<H: CRHScheme, ConstraintF: Field>: Sized {
    /// In-circuit input type; `?Sized` allows slice-based inputs like `[FpVar<F>]`.
    type InputVar: ?Sized;
    /// In-circuit output type; must support equality testing, byte extraction,
    /// conditional selection, and allocation from the native output type.
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    /// Evaluates the hash gadget on `input`, adding R1CS constraints to the current system.
    fn evaluate(input: &Self::InputVar) -> Result<Self::OutputVar, HashError>;
}

/// R1CS gadget trait for a two-to-one compression function; circuit-level counterpart of
/// [`crate::hashes::TwoToOneCRHScheme`].
///
/// Used inside Merkle tree path gadgets to combine two child digest variables into one parent.
pub trait TwoToOneCRHSchemeGadget<H: TwoToOneCRHScheme, ConstraintF: Field>: Sized {
    /// In-circuit input type for left and right operands.
    type InputVar: ?Sized;
    /// In-circuit output type; must satisfy the same trait bounds as `CRHSchemeGadget::OutputVar`.
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + CondSelectGadget<ConstraintF>
        + AllocVar<H::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    /// In-circuit evaluation of `H(left_input || right_input)`.
    fn evaluate(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, HashError>;

    /// In-circuit compression step; for Poseidon delegates to `evaluate`.
    fn compress(
        left_input: &Self::InputVar,
        right_input: &Self::InputVar,
    ) -> Result<Self::OutputVar, HashError>;
}
