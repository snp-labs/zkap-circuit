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
