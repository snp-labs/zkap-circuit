use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    convert::ToConstraintFieldGadget,
    eq::EqGadget,
    prelude::{Boolean, ToBytesGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::{
    bigint::constraints::BigNatCircuitParams,
    signature::rsa::gadget::{PublicKeyVar, SignatureVar},
    token::signature::TokenSig,
};

#[cfg(feature = "r1cs-debug")]
use crate::debug::log_r1cs_eq;

#[derive(Clone)]
pub struct TokenSigVar<F: PrimeField, BNP: BigNatCircuitParams> {
    pub sig: SignatureVar<F, BNP>,
    pub pk: PublicKeyVar<F, BNP>,
}

impl<F: PrimeField, BNP: BigNatCircuitParams> TokenSigVar<F, BNP> {
    pub fn verify_signature(&self, message: &mut [UInt8<F>]) -> Result<(), SynthesisError> {
        let num_exp_bits: usize = 17;

        message.reverse();

        let output = output_with_prifix(&message.to_vec());
        let output_fp = output.to_constraint_field()?;

        let result = self
            .sig
            .sig
            .pow_mod(&self.pk.e, &self.pk.n, num_exp_bits)?
            .to_bytes_le()?;

        let result_fp = result.to_constraint_field()?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq(
            "Token Signature Validity",
            &result_fp.clone(),
            &output_fp.clone(),
        );

        result_fp.enforce_equal(&output_fp)?;

        Ok(())
    }
}

pub fn output_with_prifix<F: PrimeField>(hashed: &[UInt8<F>]) -> Vec<UInt8<F>> {
    let mut output = Vec::new();
    let prifix1 = UInt8::<F>::constant_vec(&[32, 4, 0, 5, 1, 2, 4, 3]);
    let prifix2 = UInt8::<F>::constant_vec(&[101, 1, 72, 134, 96, 9, 6, 13]);
    let prifix3 = UInt8::<F>::constant_vec(&[48, 49, 48, 0, 255, 255, 255, 255]);
    let prifix4 = UInt8::<F>::constant_vec(&[255, 255, 255, 255, 255, 255, 1, 0]);
    let prifix5 = UInt8::<F>::constant_vec(&[255, 255, 255, 255, 255, 255, 255, 255]);
    output.extend_from_slice(hashed);
    output.extend_from_slice(&prifix1);
    output.extend_from_slice(&prifix2);
    output.extend_from_slice(&prifix3);

    for _ in 0..24 {
        output.extend_from_slice(&prifix5);
    }

    output.extend_from_slice(&prifix4);

    output
}

impl<F, BNP> AllocVar<TokenSig, F> for TokenSigVar<F, BNP>
where
    F: PrimeField,
    BNP: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<TokenSig>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let sig =
                SignatureVar::new_variable(cs.clone(), || Ok(val.borrow().sig.clone()), mode)?;
            let pk = PublicKeyVar::new_variable(cs.clone(), || Ok(val.borrow().pk.clone()), mode)?;
            Ok(TokenSigVar { sig, pk })
        })
    }
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
}
