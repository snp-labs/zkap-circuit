use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    select::CondSelectGadget,
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    is_less_than, lt_bit_vector, select_array_element,
};

pub fn slice_in_binary_tree<F: PrimeField>(
    input: &[FpVar<F>],
    offset: &UInt16<F>,
    len: &FpVar<F>,
    output_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let input_len = input.len();

    let zero = FpVar::<F>::Constant(F::from(b'A'));

    // input 배열 패딩
    let input_padded = pad_input(input);

    let select_bit_len = input_padded.len().next_power_of_two().trailing_zeros() as usize;
    let comp_bit_len = select_bit_len + 1;

    let input_len_bits = (0..comp_bit_len)
        .map(|k| Boolean::<F>::constant(((input_len >> k) & 1) == 1))
        .collect::<Vec<_>>();

    // length의 비트 표현
    let mut length_bits = len.to_bits_le()?;
    length_bits = length_bits[..comp_bit_len].to_vec();

    let mut output = Vec::new();
    for i in 0..output_len {
        let i_fp = UInt16::<F>::constant(i as u16);

        let idx = offset.wrapping_add(&i_fp);

        // idx의 비트 표현
        let mut idx_bits = idx.to_bits_le()?;
        idx_bits = idx_bits[..comp_bit_len].to_vec();

        // i를 비트로 표현
        let mut i_bits = i_fp.to_bits_le()?;
        i_bits = i_bits[..comp_bit_len].to_vec();

        // i < length인지 확인
        let i_lt_length = is_less_than(&i_bits, &length_bits)?;

        // idx < input_len인지 확인
        let idx_lt_input_len = is_less_than(&idx_bits, &input_len_bits)?;

        let mut idx_bits_sel = idx.to_bits_le()?;
        idx_bits_sel = idx_bits_sel[..select_bit_len].to_vec();

        // 유효한 인덱스인지 확인
        let valid = &i_lt_length & &idx_lt_input_len;

        // input[idx] 선택
        let input_elem = select_array_element(&input_padded, &idx_bits_sel)?;

        // valid에 따라 값 선택
        let output_elem = FpVar::conditionally_select(&valid, &input_elem, &zero)?;

        output.push(output_elem);
    }
    Ok(output)
}

/// 나눗셈의 올림 연산을 수행합니다.
/// ceil(n / q)를 계산합니다.
pub fn ceil(n: u64, q: u64) -> u64 {
    assert!(q != 0, "Divisor q cannot be zero");

    let quotient = n / q;
    let remainder = n % q;

    if remainder == 0 {
        quotient
    } else {
        quotient + 1
    }
}

/// 입력 벡터의 앞에서부터 `length` 개 원소를 반환하고 나머지를 `pad_char`로 채웁니다.
///
/// ## Arguments
/// * `in_vec` - 입력 벡터
/// * `length` - 슬라이스 길이 (회로 내 변수)
/// * `out_len` - 출력 벡터의 고정 길이
/// * `pad_char` - 패딩 문자
pub fn slice_from_start<F: PrimeField>(
    in_vec: &[FpVar<F>],
    length: &FpVar<F>,
    out_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let in_len = in_vec.len();

    assert!(out_len > 0, "출력 길이(out_len)는 0보다 커야 합니다.");
    assert!(
        out_len <= in_len,
        "출력 길이(out_len)는 입력 길이(in_len = {})보다 작거나 같아야 합니다.",
        in_len
    );

    let mask_vec: Vec<FpVar<F>> = lt_bit_vector(length, out_len)?;

    let out_vec: Vec<FpVar<F>> = in_vec
        .iter()
        .take(out_len)
        .zip(mask_vec.iter())
        .map(|(inp_val, mask_val)| {
            mask_val * (inp_val * mask_val) + (FpVar::Constant(F::from(1u8)) - mask_val) * pad_char
        })
        .collect();

    Ok(out_vec)
}

fn pad_input<F: PrimeField>(input: &[FpVar<F>]) -> Vec<FpVar<F>> {
    let mut input_padded = input.to_vec();
    let next_power_of_two = input.len().next_power_of_two();
    let zero = FpVar::<F>::zero();
    input_padded.resize(next_power_of_two, zero);
    input_padded
}
