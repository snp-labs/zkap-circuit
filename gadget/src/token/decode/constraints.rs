use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::{base64::Base64TableVar, token::decode::TokenPayloadB64, utils::slice};

#[derive(Clone)]
pub struct TokenPayloadB64Var<F: PrimeField> {
    /// Base64 payload 시작 offset (문자 단위)
    pub pay_offset_b64: UInt16<F>,
    /// Base64 payload 길이 (문자 단위)
    pub pay_len_b64: UInt16<F>,
    /// 전체 토큰(sharded+ padded)에서 payload를 포함하는 Base64 문자열 바이트들
    pub sha_pad_payload_b64: Vec<UInt8<F>>,
    /// base64_decoder용 6비트 witness
    pub bit_witness: Vec<[Boolean<F>; 6]>,
}

impl<F: PrimeField> TokenPayloadB64Var<F> {
    #[inline]
    pub fn as_b64_bytes(&self) -> &[UInt8<F>] {
        &self.sha_pad_payload_b64
    }

    pub fn decode_to_bytes(
        &self,
        table: &Base64TableVar<F>,
        max_payload_len: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pad_char = FpVar::<F>::Constant(F::from(b'A'));
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        let sha_pad_payload_b64_to_fp = self
            .sha_pad_payload_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<Result<Vec<_>, _>>()?;

        let mut payload = slice(
            &sha_pad_payload_b64_to_fp,
            &self.pay_offset_b64,
            &self.pay_len_b64,
            max_payload_b64_len,
            &pad_char,
        )?;

        payload.resize(max_payload_b64_len + 4, pad_char.clone());

        let dec = table.decode(&payload, &self.bit_witness)?;

        Ok(dec)
    }
}

impl<F> AllocVar<TokenPayloadB64, F> for TokenPayloadB64Var<F>
where
    F: PrimeField,
{
    fn new_variable<T: Borrow<TokenPayloadB64>>(
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

            Ok(TokenPayloadB64Var {
                pay_offset_b64,
                pay_len_b64,
                sha_pad_payload_b64,
                bit_witness,
            })
        })
    }
}
