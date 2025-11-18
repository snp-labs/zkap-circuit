use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::{
    jwt::constraints::ClaimIndicesVar,
    utils::{
        a_lt_b, gt_bit_vector, hadamard_product, lt_bit_vector, single_multiplexer, slice::slice,
        slice_from_start,
    },
};

pub fn claim_extractor<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    key: &str,
    payload: &[FpVar<F>],
    pos: &ClaimIndicesVar<F>,
    max_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let pad_char = FpVar::<F>::Constant(F::from(b'0'));
    let key = key
        .bytes()
        .map(|byte| FpVar::<F>::Constant(F::from(byte)))
        .collect::<Vec<_>>();
    let key_len = UInt16::constant(key.len() as u16);

    let claim = slice(payload, &pos.offset, &pos.len, max_len, &pad_char)?;

    let result_name = slice_from_start(&claim, &key_len.to_fp()?, key.len(), &pad_char)?;

    let result_value = slice(&claim, &pos.value_idx, &pos.value_len, max_len, &pad_char)?;

    result_name.enforce_equal(&key)?;

    claim_format_verifier(
        cs.clone(),
        &claim,
        &pos.len,
        &key_len,
        &pos.colon_idx,
        &pos.value_idx,
        &pos.value_len,
        max_len,
    )?;

    // let result_value = vec![FpVar::zero()];

    Ok(result_value)
}

fn claim_format_verifier<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    claim: &[FpVar<F>],
    claim_len: &UInt16<F>,
    name_len: &UInt16<F>,
    colon_idx: &UInt16<F>,
    value_idx: &UInt16<F>,
    value_len: &UInt16<F>,
    max_claim_len: usize,
) -> Result<(), SynthesisError> {
    let value_len = Boolean::le_bits_to_fp(&value_len.to_bits_le()?)?;
    let claim_len = Boolean::le_bits_to_fp(&claim_len.to_bits_le()?)?;

    // check1: 이름 길이는 콜론 인덱스보다 작거나 같아야한다.
    // name_len.enforce_cmp(&colon_idx, Ordering::Less, true)?;
    // r1cs-std "0.5.0" 버전에서 enforce_cmp의 버그로 인해 다음과 같이 변경합니다.
    let name_len_boolean = name_len.to_bits_le()?;
    let colon_idx_boolean = colon_idx.to_bits_le()?;
    let result = a_lt_b(&name_len_boolean, &colon_idx_boolean)? | name_len.is_eq(&colon_idx)?;
    result.enforce_equal(&Boolean::TRUE)?;

    // check2: 콜론 인덱스는 값 인덱스보다 작아야 한다.
    // colon_idx.enforce_cmp(&value_idx, Ordering::Less, true)?;
    // r1cs-std "0.5.0" 버전에서 enforce_cmp의 버그로 인해 다음과 같이 변경합니다.
    let value_idx_boolean = value_idx.to_bits_le()?;
    let result = a_lt_b(&colon_idx_boolean, &value_idx_boolean)?;
    result.enforce_equal(&Boolean::TRUE)?;

    // '공백이 아니면 1, 공백이면 0'인 플래그를 한 번만 계산합니다.
    let is_not_whitespace_flags = claim
        .iter()
        .map(|byte| Ok(FpVar::from(!is_whitespace(byte)?)))
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    let name_len = name_len.to_fp()?;
    let colon_idx = colon_idx.to_fp()?;
    let value_idx = value_idx.to_fp()?;

    // check3: key와 colon 사이에 ws를 제외한 문자는 없어야한다. (name_len-1 < i < colon_idx)
    enforce_range_is_whitespace(
        cs.clone(),
        &(name_len - F::ONE),
        &colon_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check4: colon_idx와 value_idx 사이에 ws를 제외한 문자는 없어야한다. (colon_idx < i < value_idx)
    enforce_range_is_whitespace(
        cs.clone(),
        &colon_idx,
        &value_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;

    // check5: value의 끝과 claim의 끝 사이에 ws를 제외한 문자는 없어야한다.
    let value_end_idx = value_idx + value_len; // 값의 마지막 인덱스 + 1
    let claim_end_idx = claim_len.clone() - F::ONE; // 클레임의 마지막 문자 인덱스
    enforce_range_is_whitespace(
        cs.clone(),
        &value_end_idx,
        &claim_end_idx,
        &is_not_whitespace_flags,
        max_claim_len,
    )?;
    // 참고: check5의 기존 로직 `&(value_idx + value_len + F::ONE)`은 범위가 한 칸 더 뒤에서 시작하는 것으로 보입니다.
    // 의도된 로직에 맞게 `value_end_idx`를 `value_idx + value_len` 또는 `value_idx + value_len + F::ONE`으로 조절하여 사용하시면 됩니다.

    // check6: colon이 colon_idx 위치에 있는지 확인한다.
    let colon_var = single_multiplexer(claim, &colon_idx)?;
    colon_var.enforce_equal(&FpVar::<F>::Constant(F::from(b':')))?;

    // check7: 마지막 문자가 콤마 혹은 닫는 중괄호인지 확인한다.
    let last_char_var = single_multiplexer(claim, &(claim_len - F::ONE))?;
    let is_closing_brace = last_char_var.is_eq(&FpVar::constant(F::from(b'}')))?;
    let is_comma = last_char_var.is_eq(&FpVar::constant(F::from(b',')))?;
    (is_closing_brace | is_comma).enforce_equal(&Boolean::TRUE)?;
    // 기존 mul_equals 로직보다 or를 사용하는 것이 더 명확할 수 있습니다.

    Ok(())
}

fn enforce_range_is_whitespace<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    start_idx: &FpVar<F>,
    end_idx: &FpVar<F>,
    is_not_whitespace_flags: &[FpVar<F>],
    max_len: usize,
) -> Result<(), SynthesisError> {
    let is_gt_start = gt_bit_vector(start_idx, max_len)?;
    let is_lt_end = lt_bit_vector(end_idx, max_len)?;
    let selection_mask = hadamard_product(&is_gt_start, &is_lt_end);

    let non_whitespace_sum: FpVar<F> = hadamard_product(&selection_mask, is_not_whitespace_flags)
        .iter()
        .sum();

    non_whitespace_sum.enforce_equal(&FpVar::zero())?;

    Ok(())
}

fn is_whitespace<F: PrimeField>(byte: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
    let is_tab = byte.is_eq(&FpVar::constant(F::from(0x09u8)))?;
    let is_newline = byte.is_eq(&FpVar::constant(F::from(0x0Au8)))?;
    let is_carriage_return = byte.is_eq(&FpVar::constant(F::from(0x0Du8)))?;
    let is_space = byte.is_eq(&FpVar::constant(F::from(0x20u8)))?;

    Ok(is_tab | is_newline | is_carriage_return | is_space)
}
