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
///
/// Mirrors [`crate::signature::SignatureScheme`] at the circuit level. Call [`verify`](Self::verify)
/// inside a constraint system to obtain a `Boolean` that is `true` iff the PKCS#1 v1.5
/// signature check passes; enforce it with `Boolean::enforce_equal(&Boolean::TRUE)`.
pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    /// In-circuit representation of the scheme's public parameters.
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    /// In-circuit representation of the public key; must support byte serialisation
    /// so that it can be hashed or compared inside other gadgets.
    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    /// In-circuit representation of the signature; must support byte serialisation
    /// for the modular exponentiation step in RSA verification.
    type SignatureVar: ToBytesGadget<ConstraintF> + AllocVar<S::Signature, ConstraintF> + Clone;

    /// Enforces that `signature` on `message` verifies under `public_key`.
    ///
    /// Returns a `Boolean` constraint (not a panic); callers must enforce it equal to
    /// `Boolean::TRUE` to make the circuit unsatisfiable on an invalid signature.
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}
