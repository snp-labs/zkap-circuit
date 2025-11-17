use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, eq::EqGadget, fields::{FieldVar, fp::FpVar}, prelude::{Boolean, ToBitsGadget}, uint16::UInt16
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::{token::claim::ClaimIndices, utils::{
    a_lt_b, hadamard_product, indexing::IndexingGadget, single_multiplexer, slice::slice,
    slice_from_start,
}};

#[cfg(feature = "r1cs-debug")]
use crate::debug::log_r1cs_eq;

/// Circuit variable representing claim indices in decoded payload.
#[derive(Clone)]
pub struct ClaimIndicesVar<F: PrimeField> {
    pub offset: UInt16<F>,    // Claim start position
    pub claim_len: UInt16<F>, // Total claim length
    pub colon_idx: UInt16<F>, // Position of ':' separator
    pub value_idx: UInt16<F>, // Value start position
    pub value_len: UInt16<F>, // Value length
}

impl<F> ClaimIndicesVar<F>
where
    F: PrimeField,
{
    pub fn claim_extractor(
        &self,
        key: &str,
        payload: &[FpVar<F>],
        max_claim_len: usize,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pad_char = FpVar::<F>::Constant(F::from(b'0'));
        let key = key
            .bytes()
            .map(|byte| FpVar::<F>::Constant(F::from(byte)))
            .collect::<Vec<_>>();
        let key_len = UInt16::constant(key.len() as u16);

        let claim = slice(
            payload,
            &self.offset,
            &self.claim_len,
            max_claim_len,
            &pad_char,
        )?;

        let result_name = slice_from_start(&claim, &key_len.to_fp()?, key.len(), &pad_char)?;

        let result_value = slice(
            &claim,
            &self.value_idx,
            &self.value_len,
            max_claim_len,
            &pad_char,
        )?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("Claim key", &result_name.clone(), &key.clone());

        result_name.enforce_equal(&key)?;

        self.claim_format_verifier(&claim, &key_len, max_claim_len)?;

        Ok(result_value)
    }
    fn claim_format_verifier(
        &self,
        claim: &[FpVar<F>],
        name_len: &UInt16<F>,
        max_claim_len: usize,
    ) -> Result<(), SynthesisError> {
        // check1: 이름 길이는 콜론 인덱스보다 작거나 같아야한다.
        // name_len.enforce_cmp(&colon_idx, Ordering::Less, true)?;
        // r1cs-std "0.5.0" 버전에서 enforce_cmp의 버그로 인해 다음과 같이 변경합니다.
        let name_len_boolean = name_len.to_bits_le()?;
        let colon_idx_boolean = self.colon_idx.to_bits_le()?;
        let result =
            a_lt_b(&name_len_boolean, &colon_idx_boolean)? | name_len.is_eq(&self.colon_idx)?;
        
        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("Name length <= Colon index", &[result.clone()], &[Boolean::TRUE]);

        result.enforce_equal(&Boolean::TRUE)?;

        // check2: 콜론 인덱스는 값 인덱스보다 작아야 한다.
        // colon_idx.enforce_cmp(&value_idx, Ordering::Less, true)?;
        // r1cs-std "0.5.0" 버전에서 enforce_cmp의 버그로 인해 다음과 같이 변경합니다.
        let value_idx_boolean = self.value_idx.to_bits_le()?;
        let result = a_lt_b(&colon_idx_boolean, &value_idx_boolean)?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("Colon index < Value index", &[result.clone()], &[Boolean::TRUE]);

        result.enforce_equal(&Boolean::TRUE)?;

        // '공백이 아니면 1, 공백이면 0'인 플래그를 계산합니다.
        let is_not_whitespace_flags = claim
            .iter()
            .map(|byte| Ok(FpVar::from(!is_whitespace(byte)?)))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let name_len = name_len.to_fp()?;
        let colon_idx = self.colon_idx.to_fp()?;
        let value_idx = self.value_idx.to_fp()?;
        let claim_len = self.claim_len.to_fp()?;
        let value_len = self.value_len.to_fp()?;

        // check3: key와 colon 사이에 ws를 제외한 문자는 없어야한다. (name_len-1 < i < colon_idx)
        enforce_range_is_whitespace(
            &(name_len - F::ONE),
            &colon_idx,
            &is_not_whitespace_flags,
            max_claim_len,
        )?;

        // check4: colon_idx와 value_idx 사이에 ws를 제외한 문자는 없어야한다. (colon_idx < i < value_idx)
        enforce_range_is_whitespace(
            &colon_idx,
            &value_idx,
            &is_not_whitespace_flags,
            max_claim_len,
        )?;

        // check5: value의 끝과 claim의 끝 사이에 ws를 제외한 문자는 없어야한다.
        let value_end_idx = value_idx + value_len; // 값의 마지막 인덱스 + 1
        let claim_end_idx = claim_len.clone() - F::ONE; // 클레임의 마지막 문자 인덱스
        enforce_range_is_whitespace(
            &value_end_idx,
            &claim_end_idx,
            &is_not_whitespace_flags,
            max_claim_len,
        )?;

        // check6: colon이 colon_idx 위치에 있는지 확인한다.
        let colon_var = single_multiplexer(claim, &colon_idx)?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("Colon character check", &[colon_var.clone()], &[FpVar::Constant(F::from(b':'))]);

        colon_var.enforce_equal(&FpVar::<F>::Constant(F::from(b':')))?;

        // check7: 마지막 문자가 콤마 혹은 닫는 중괄호인지 확인한다.
        let last_char_var = single_multiplexer(claim, &(claim_len - F::ONE))?;
        let is_closing_brace = last_char_var.is_eq(&FpVar::constant(F::from(b'}')))?;
        let is_comma = last_char_var.is_eq(&FpVar::constant(F::from(b',')))?;

        #[cfg(feature = "r1cs-debug")]
        log_r1cs_eq("Last character check", &[is_closing_brace.clone() | is_comma.clone()], &[Boolean::TRUE]);

        (is_closing_brace | is_comma).enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

fn is_whitespace<F: PrimeField>(byte: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let is_tab = byte.is_eq(&FpVar::constant(F::from(0x09u8)))?;
    let is_newline = byte.is_eq(&FpVar::constant(F::from(0x0Au8)))?;
    let is_carriage_return = byte.is_eq(&FpVar::constant(F::from(0x0Du8)))?;
    let is_space = byte.is_eq(&FpVar::constant(F::from(0x20u8)))?;

    Ok(is_tab | is_newline | is_carriage_return | is_space)
}

fn enforce_range_is_whitespace<F: PrimeField>(
    start_idx: &FpVar<F>,
    end_idx: &FpVar<F>,
    is_not_whitespace_flags: &[FpVar<F>],
    max_len: usize,
) -> Result<(), SynthesisError> {
    let is_gt_start = start_idx.to_gt_vector(max_len)?;
    let is_lt_end = end_idx.to_lt_vector(max_len)?;
    let selection_mask = hadamard_product(&is_gt_start, &is_lt_end);

    let non_whitespace_sum: FpVar<F> = hadamard_product(&selection_mask, is_not_whitespace_flags)
        .iter()
        .sum();

    #[cfg(feature = "r1cs-debug")]
    log_r1cs_eq("Non-whitespace sum in range", &[non_whitespace_sum.clone()], &[FpVar::zero()]);

    non_whitespace_sum.enforce_equal(&FpVar::zero())?;

    Ok(())
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
        let claim_len = UInt16::new_variable(cs.clone(), || Ok(claim_indices.claim_len as u16), mode)?;
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
