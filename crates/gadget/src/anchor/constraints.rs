//! R1CS gadget trait for the threshold anchor scheme.
//!
//! [`AnchorSchemeGadget`] mirrors [`crate::anchor::AnchorScheme`] at the constraint level.
//! Implementors must provide `verify_b_consistency` (that `b = a · A` holds in-circuit)
//! and `verify_binding` (that the inner products match the public anchor). The Poseidon
//! instantiation lives in [`crate::anchor::poseidon::constraints`].

use ark_ff::Field;
use ark_r1cs_std::{alloc::AllocVar, prelude::Boolean};
use ark_relations::gr1cs::SynthesisError;

use crate::anchor::AnchorScheme;

/// R1CS gadget trait that mirrors [`AnchorScheme`] at the constraint level.
///
/// Implementors enforce the two key equations in-circuit:
/// `b = a · A` (`verify_b_consistency`) and `⟨a, anchor⟩ = ⟨b, h_known⟩`
/// (`verify_binding`). The Poseidon instantiation is in
/// [`crate::anchor::poseidon::constraints::PoseidonAnchorSchemeGadget`].
pub trait AnchorSchemeGadget<A: AnchorScheme, ConstraintF: Field> {
    /// In-circuit representation of the public key (Poseidon parameters).
    type PublicKeyVar: AllocVar<A::PublicKey, ConstraintF>;
    /// In-circuit representation of the committed anchor vector (length m).
    type AnchorVar: AllocVar<A::Anchor, ConstraintF>;
    /// In-circuit representation of the witness `(a, b, h_known)`.
    type WitnessVar: AllocVar<A::Witness, ConstraintF>;
    /// In-circuit representation of the Vandermonde matrix.
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
