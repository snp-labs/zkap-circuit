//! R1CS gadget trait for the threshold anchor scheme.
//!
//! [`AnchorSchemeGadget`] mirrors [`crate::anchor::AnchorScheme`] at the constraint level.
//! Implementors must provide `verify_b_consistency` (that `b = a · A` holds in-circuit)
//! and `verify_binding` (that the inner products match the public anchor). The Poseidon
//! instantiation lives in [`crate::anchor::poseidon::constraints`].

use ark_ff::Field;
use ark_r1cs_std::{alloc::AllocVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;

use crate::anchor::AnchorScheme;

pub trait AnchorSchemeGadget<A: AnchorScheme, ConstraintF: Field> {
    type PublicKeyVar: AllocVar<A::PublicKey, ConstraintF>;
    type AnchorVar: AllocVar<A::Anchor, ConstraintF>;
    type WitnessVar: AllocVar<A::Witness, ConstraintF>;
    type MatrixVar: AllocVar<A::Matrix, ConstraintF>;

    /// Verify: b = a * A
    fn verify_b_consistency(
        witness: &Self::WitnessVar,
        matrix: &Self::MatrixVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;

    /// Verify: <a, anchor> = <b, h_known>
    fn verify_binding(
        pk: &Self::PublicKeyVar,
        anchor: &Self::AnchorVar,
        witness: &Self::WitnessVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}
