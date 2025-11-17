use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::{
    bigint::constraints::BigNatCircuitParams,
    jwt::{token2::Token, types::ClaimIndices},
    signature::rsa::gadget::{PublicKeyVar, SignatureVar},
};

/// Circuit variable representing claim indices in decoded payload.
#[derive(Clone)]
pub struct ClaimIndicesVar<F: PrimeField> {
    pub offset: UInt16<F>,    // Claim start position
    pub len: UInt16<F>,       // Total claim length
    pub colon_idx: UInt16<F>, // Position of ':' separator
    pub value_idx: UInt16<F>, // Value start position
    pub value_len: UInt16<F>, // Value length
}

#[derive(Clone)]
pub struct TokenVar<F: PrimeField> {
    pub pay_offset_b64: UInt16<F>,
    pub pay_len_b64: UInt16<F>,
    pub claims: Vec<ClaimIndicesVar<F>>,
    pub sha_pad_payload_b64: Vec<UInt8<F>>,
    pub bit_witness: Vec<[Boolean<F>; 6]>,
}

impl<F: PrimeField> TokenVar<F> {
    pub fn verify_rsa_signature<BNP: BigNatCircuitParams>(
        &self,
        pk: &PublicKeyVar<F, BNP>,
        sig: &SignatureVar<F, BNP>,
    ) {
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
        let len = UInt16::new_variable(cs.clone(), || Ok(claim_indices.len as u16), mode)?;
        let colon_idx =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.colon_idx as u16), mode)?;

        let value_idx =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.value_idx as u16), mode)?;
        let value_len =
            UInt16::new_variable(cs.clone(), || Ok(claim_indices.value_len as u16), mode)?;

        Ok(Self {
            offset,
            len,
            colon_idx,
            value_idx,
            value_len,
        })
    }
}

impl<F> AllocVar<Token, F> for TokenVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<Token>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let pay_offset_b64 =
                UInt16::new_variable(cs.clone(), || Ok(val.borrow().pay_offset_b64 as u16), mode)?;
            let pay_len_b64 =
                UInt16::new_variable(cs.clone(), || Ok(val.borrow().pay_len_b64 as u16), mode)?;
            let claims = val
                .borrow()
                .claims
                .iter()
                .map(|claim| {
                    ClaimIndicesVar::new_variable(cs.clone(), || Ok(claim.indices.clone()), mode)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let sha_pad_payload_b64 = val
                .borrow()
                .sha_pad_payload_b64
                .iter()
                .map(|byte| UInt8::new_variable(cs.clone(), || Ok(byte), mode))
                .collect::<Result<Vec<_>, _>>()?;
            let bit_witness = val
                .borrow()
                .bit_witness
                .chunks(6)
                .map(|chunk| {
                    let arr: [Boolean<F>; 6] = std::array::from_fn(|i| {
                        Boolean::new_variable(cs.clone(), || Ok(chunk[i]), mode).unwrap()
                    });
                    arr
                })
                .collect::<Vec<_>>();

            Ok(Self {
                pay_offset_b64,
                pay_len_b64,
                claims,
                sha_pad_payload_b64,
                bit_witness,
            })
        })
    }
}
