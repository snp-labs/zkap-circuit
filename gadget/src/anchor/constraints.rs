use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::SynthesisError;

use crate::anchor::AnchorScheme;

pub trait AnchorSchemeGadget<A: AnchorScheme, ConstraintF: Field> {
    type PublicKeyVar: AllocVar<A::PublicKey, ConstraintF>;
    type AnchorVar: AllocVar<A::Anchor, ConstraintF>;
    type WitnessVar: AllocVar<A::Witness, ConstraintF>;

    fn verify(
        pk: &Self::PublicKeyVar,
        anchor: &Self::AnchorVar,
        witness: &Self::WitnessVar,
    ) -> Result<(), SynthesisError>;
}
