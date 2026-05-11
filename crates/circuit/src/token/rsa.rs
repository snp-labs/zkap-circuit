//! RSA-2048 PKCS#1 signature verification gadget.
//!
//! [`RSA2048VerifyGadget`] provides two verification paths:
//!
//! - [`RSA2048VerifyGadget::verify_opt`] — canonical circuit path; computes `sig^65537 mod n`
//!   via 16 squarings + 1 multiply (65537 = 2^16 + 1).  This is the only path invoked by
//!   [`crate::zkap::ZkapCircuit`].
//!
//! - [`RSA2048VerifyGadget::verify`] — deprecated general path using `pow_mod` with a full
//!   17-bit exponent loop.  Retained for reference; do not call in production circuits.

use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    prelude::Boolean,
    uint8::UInt8,
};
use ark_relations::gr1cs::SynthesisError;
use gadget::{
    bigint::constraints::{BigNatCircuitParams, BigNatVar},
    signature::rsa::constraints::{PublicKeyVar, SignatureVar, output_with_prefix},
};

/// Zero-state marker carrying the RSA-2048 PKCS#1 verification gadgets
/// as associated functions. See [`RSA2048VerifyGadget::verify_opt`] for
/// the canonical circuit path.
pub struct RSA2048VerifyGadget;

impl RSA2048VerifyGadget {
    /// General RSA-2048 verification using `pow_mod` with a full 17-bit exponent loop.
    ///
    /// # Deprecated
    ///
    /// Use [`RSA2048VerifyGadget::verify_opt`] instead.  This path applies the generic
    /// square-and-multiply algorithm which is non-canonical for e = 65537 and substantially
    /// more expensive in constraints.  It is retained only as a reference implementation.
    ///
    /// The circuit calls only `verify_opt`; if you call this function by mistake, the proof
    /// will still be sound but will produce a different (non-optimised) R1CS and break the
    /// `ar1cs_blake3` gate.
    #[deprecated(
        note = "use verify_opt — 65537-specific square-and-multiply, the non-opt path is non-canonical"
    )]
    pub fn verify<F: PrimeField, BNP: BigNatCircuitParams>(
        message: &mut [UInt8<F>],
        sig: &SignatureVar<F, BNP>,
        pk: &PublicKeyVar<F, BNP>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let num_exp_bits: usize = 17;

        message.reverse();

        let output = output_with_prefix(message);
        let output_fp = output.to_constraint_field()?;

        let result = sig.sig.pow_mod(&pk.e, &pk.n, num_exp_bits)?.to_bytes_le()?;

        let result_fp = result.to_constraint_field()?;

        let is_valid = result_fp.is_eq(&output_fp)?;

        Ok(is_valid)
    }

    /// 65537-specific RSA-2048 verification (canonical circuit path).
    ///
    /// Computes `sig^65537 mod n` using 16 squarings followed by one multiply, then
    /// compares the result with the PKCS#1-prefixed message digest.  This is the only
    /// path called by [`crate::zkap::ZkapCircuit`].
    ///
    /// Do **not** generalise this to arbitrary exponents without a new trusted setup —
    /// the optimisation is valid only because 65537 = 2^16 + 1.
    pub fn verify_opt<F: PrimeField, BNP: BigNatCircuitParams>(
        message: &mut [UInt8<F>],
        sig: &SignatureVar<F, BNP>,
        pk: &PublicKeyVar<F, BNP>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let cs = pk.n.cs().or(sig.sig.cs());

        sig.sig.enforce_limb_range_via_bits()?;
        pk.n.enforce_limb_range_via_bits()?;

        BigNatVar::<F, BNP>::enforce_lt_strict_borrow_chain(cs.clone(), &sig.sig, &pk.n)?;

        message.reverse();

        let output = output_with_prefix(message);
        let output_fp = output.to_constraint_field()?;

        let mut acc = sig.sig.clone();

        // acc = sig^(2^16) mod n  (16 squarings)
        for _ in 0..16 {
            acc = acc.square_mod_unchecked(&pk.n)?;
        }

        // acc = sig^(2^16) * sig = sig^(65537) mod n
        let result = acc.mult_mod_unchecked(&sig.sig, &pk.n)?.to_bytes_le()?;

        let result_fp = result.to_constraint_field()?;
        let is_valid = result_fp.is_eq(&output_fp)?;

        Ok(is_valid)
    }
}
