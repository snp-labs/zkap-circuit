use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    prelude::Boolean,
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use gadget::{
    bigint::constraints::{BigNatCircuitParams, BigNatVar},
    signature::rsa::constraints::{PublicKeyVar, SignatureVar, output_with_prifix},
};

use crate::token::ClaimIndices;

#[derive(Clone)]
pub struct ClaimIndicesVar<F: PrimeField> {
    pub offset: UInt16<F>,    // Claim start position
    pub claim_len: UInt16<F>, // Total claim length
    pub colon_idx: UInt16<F>, // Position of ':' separator
    pub value_idx: UInt16<F>, // Value start position
    pub value_len: UInt16<F>, // Value length
}

pub struct RSA2048VerifyGadget;

impl RSA2048VerifyGadget {
    pub fn verify<F: PrimeField, BNP: BigNatCircuitParams>(
        message: &mut [UInt8<F>],
        sig: &SignatureVar<F, BNP>,
        pk: &PublicKeyVar<F, BNP>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let num_exp_bits: usize = 17;

        message.reverse();

        let output = output_with_prifix(message);
        let output_fp = output.to_constraint_field()?;

        let result = sig.sig.pow_mod(&pk.e, &pk.n, num_exp_bits)?.to_bytes_le()?;

        let result_fp = result.to_constraint_field()?;

        let is_valid = result_fp.is_eq(&output_fp)?;

        Ok(is_valid)
    }

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

        let output = output_with_prifix(message);
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

impl<F> AllocVar<ClaimIndices, F> for ClaimIndicesVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<ClaimIndices>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        let claim_indices = f()?.borrow().clone();

        let offset = UInt16::new_variable(cs.clone(), || Ok(claim_indices.offset as u16), mode)?;
        let claim_len =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.claim_len as u16), mode)?;
        let colon_idx =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.colon_idx as u16), mode)?;

        let value_idx =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.value_idx as u16), mode)?;
        let value_len =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.value_len as u16), mode)?;

        Ok(Self {
            offset,
            claim_len,
            colon_idx,
            value_idx,
            value_len,
        })
    }
}
