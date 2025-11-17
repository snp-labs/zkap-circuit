use std::borrow::Borrow;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::{
    base64::{Base64TableVar, base64_decoder},
    bigint::constraints::BigNatCircuitParams,
    hashes::sha256::constraints::SHA256Gadget,
    jwt::{token_no_opt::TokenNoOpt, token_opt::TokenOpt, types::ClaimIndices},
    signature::rsa::gadget::{PublicKeyVar, SignatureVar, new_rsa_verify_with_state},
    utils::slice,
};

#[derive(Clone)]
pub struct ClaimIndicesVar<F: PrimeField> {
    pub offset: UInt16<F>,
    pub len: UInt16<F>,
    pub colon_idx: UInt16<F>,
    pub value_idx: UInt16<F>,
    pub value_len: UInt16<F>,
}

#[derive(Clone)]
pub struct TokenOptVar<F: PrimeField, BNP: BigNatCircuitParams> {
    pub pay_offset_b64: UInt16<F>,
    pub pay_len_b64: UInt16<F>,
    pub claims: Vec<ClaimIndicesVar<F>>,
    pub shapad_payload_b64: Vec<UInt8<F>>,
    pub sig: SignatureVar<F, BNP>,
    pub pk: PublicKeyVar<F, BNP>,
    pub bit_witness: Vec<[Boolean<F>; 6]>,
    pub overlap: Vec<FpVar<F>>,
    pub overlap_len: FpVar<F>,
    pub sha256_gadget: SHA256Gadget<F>,
    pub num_blocks: FpVar<F>,
}

impl<F: PrimeField, BNP: BigNatCircuitParams> TokenOptVar<F, BNP> {
    pub fn verify_rsa_with_state<C>(&mut self) -> Result<(), SynthesisError>
    where
        C: CurveGroup<BaseField = F>,
    {
        // RSA verification with state

        let pk = self.pk.clone();
        let sig = self.sig.clone();
        let msg = self.shapad_payload_b64.clone();
        let nblk = self.num_blocks.clone();

        new_rsa_verify_with_state::<C, BNP>(&pk, &sig, &msg, &nblk, &mut self.sha256_gadget)
    }

    pub fn decode_base64_payload(
        &self,
        cs: ConstraintSystemRef<F>,
        base64_table: &Base64TableVar<F>,
        max_payload_len: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pad_char = FpVar::<F>::Constant(F::from(b'A'));
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        let shapad_pad_payload_b64_to_fp = self
            .shapad_payload_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<Result<Vec<_>, _>>()?;

        let mut payload = slice(
            &shapad_pad_payload_b64_to_fp,
            &self.pay_offset_b64,
            &self.pay_len_b64,
            max_payload_b64_len,
            &pad_char,
        )?;

        payload.resize(max_payload_b64_len + 4, pad_char.clone());

        let dec = base64_decoder(&base64_table.table, &payload, &self.bit_witness)?;

        Ok(dec)
    }
}

#[derive(Clone)]
pub struct TokenNoOptVar<F: PrimeField, BNP: BigNatCircuitParams> {
    pub pay_offset_b64: UInt16<F>,
    pub pay_len_b64: UInt16<F>,
    pub claims: Vec<ClaimIndicesVar<F>>,
    pub shapad_payload_b64: Vec<UInt8<F>>,
    pub sig: SignatureVar<F, BNP>,
    pub pk: PublicKeyVar<F, BNP>,
    pub bit_witness: Vec<[Boolean<F>; 6]>,
    pub sha256_gadget: SHA256Gadget<F>,
    pub num_blocks: FpVar<F>,
}

impl<F, BNP> TokenNoOptVar<F, BNP>
where
    F: PrimeField,
    BNP: BigNatCircuitParams,
{
    pub fn verify_rsa_with_state<C>(&mut self) -> Result<(), SynthesisError>
    where
        C: CurveGroup<BaseField = F>,
    {
        // RSA verification with state

        let pk = self.pk.clone();
        let sig = self.sig.clone();
        let msg = self.shapad_payload_b64.clone();
        let nblk = self.num_blocks.clone();

        new_rsa_verify_with_state::<C, BNP>(&pk, &sig, &msg, &nblk, &mut self.sha256_gadget)
    }

    pub fn decode_base64_payload(
        &self,
        cs: ConstraintSystemRef<F>,
        base64_table: &Base64TableVar<F>,
        max_payload_len: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pad_char = FpVar::<F>::Constant(F::from(b'A'));
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        let shapad_pad_payload_b64_to_fp = &self
            .shapad_payload_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<Result<Vec<_>, _>>()?;

        let payload = slice(
            shapad_pad_payload_b64_to_fp,
            &self.pay_offset_b64,
            &self.pay_len_b64,
            max_payload_b64_len,
            &pad_char,
        )?;

        let dec = base64_decoder(&base64_table.table, &payload, &self.bit_witness)?;

        Ok(dec)
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

impl<F, BNP> AllocVar<TokenOpt, F> for TokenOptVar<F, BNP>
where
    F: PrimeField,
    BNP: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<TokenOpt>>(
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
            let shapad_payload_b64 = val
                .borrow()
                .shapad_payload_b64
                .iter()
                .map(|byte| UInt8::new_variable(cs.clone(), || Ok(byte), mode))
                .collect::<Result<Vec<_>, _>>()?;
            let sig =
                SignatureVar::new_variable(cs.clone(), || Ok(val.borrow().sig.clone()), mode)?;
            let pk = PublicKeyVar::new_variable(cs.clone(), || Ok(val.borrow().pk.clone()), mode)?;
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
            let overlap = val
                .borrow()
                .overlap
                .iter()
                .map(|elem| FpVar::new_variable(cs.clone(), || Ok(F::from(*elem as u64)), mode))
                .collect::<Result<Vec<_>, _>>()?;
            let overlap_len = FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(val.borrow().overlap_len as u64)),
                mode,
            )?;

            let sha256_gadget = SHA256Gadget::<F>::new_variable(
                cs.clone(),
                || Ok(val.borrow().state.clone()),
                mode,
            )?;
            let num_blocks = FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(val.borrow().num_blocks as u64)),
                mode,
            )?;

            Ok(TokenOptVar {
                pay_offset_b64,
                pay_len_b64,
                claims,
                shapad_payload_b64,
                sig,
                pk,
                bit_witness,
                overlap,
                overlap_len,
                sha256_gadget,
                num_blocks,
            })
        })
    }
}

impl<F, BNP> AllocVar<TokenNoOpt, F> for TokenNoOptVar<F, BNP>
where
    F: PrimeField,
    BNP: BigNatCircuitParams,
{
    fn new_variable<T: Borrow<TokenNoOpt>>(
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
            let shapad_payload_b64 = val
                .borrow()
                .shapad_payload_b64
                .iter()
                .map(|byte| UInt8::new_variable(cs.clone(), || Ok(byte), mode))
                .collect::<Result<Vec<_>, _>>()?;
            let sig =
                SignatureVar::new_variable(cs.clone(), || Ok(val.borrow().sig.clone()), mode)?;
            let pk = PublicKeyVar::new_variable(cs.clone(), || Ok(val.borrow().pk.clone()), mode)?;
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
            let sha256_gadget = SHA256Gadget::<F>::default();
            let num_blocks = FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(val.borrow().num_blocks as u64)),
                mode,
            )?;

            Ok(TokenNoOptVar {
                pay_offset_b64,
                pay_len_b64,
                claims,
                shapad_payload_b64,
                sig,
                pk,
                bit_witness,
                sha256_gadget,
                num_blocks,
            })
        })
    }
}
