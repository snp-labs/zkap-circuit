//! R1CS gadget trait for signature verification inside ZKP circuits.
//!
//! [`SigVerifyGadget`] abstracts over the circuit-level signature verification for any
//! [`crate::signature::SignatureScheme`]. Implementors supply associated types for
//! parameter, public-key, and signature variables, plus a `verify` method that returns
//! a `Boolean` constraint indicating whether the signature is valid in-circuit. The
//! RSA-2048 PKCS#1 v1.5 instantiation is in [`crate::signature::rsa::constraints`].

use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use crate::signature::SignatureScheme;

/// R1CS gadget for signature verification inside ZKP circuits.
pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    type SignatureVar: ToBytesGadget<ConstraintF> + AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}
