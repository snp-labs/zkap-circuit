use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    select::CondSelectGadget,
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::log2;
use core::ops::BitXor;

use crate::{
    a_lt_b, divide_mod_power_of_2_circuit, lt_bit_vector, multi_mux, pack_byte_fps_to_fp,
    select_array_element, unpack_fp_to_byte_fps,
};

/// Optimized slice function using binary tree and packed representation
pub fn slice<F: PrimeField>(
    data: &[FpVar<F>], // FpVar<F> 하나 당 1byte를 나타냄
    start_var: &UInt16<F>,
    len_var: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let data_len = data.len();

    // --- 경계 검사 (Bounds Checking) ---
    // 1. start_var <= data_len
    Boolean::enforce_smaller_or_equal_than_le(&start_var.to_bits_le()?, [data_len as u64])?;

    // 2. len_var <= max_len
    Boolean::enforce_smaller_or_equal_than_le(&len_var.to_bits_le()?, [max_len as u64])?;

    // 3. start_var + len_var <= data_len
    let end_exclusive_var = start_var.wrapping_add(len_var);
    Boolean::enforce_smaller_or_equal_than_le(&end_exclusive_var.to_bits_le()?, [data_len as u64])?;

    let num_bytes_expected = 16;
    let packed_input: Vec<FpVar<F>> = data
        .chunks(num_bytes_expected)
        .map(|chunk| {
            let mut chunk_vec = chunk.to_vec();

            // 부족한 부분은 constant 0으로 패딩 (witness 아님!)
            while chunk_vec.len() < num_bytes_expected {
                chunk_vec.push(FpVar::<F>::constant(F::from(0u8)));
            }

            pack_byte_fps_to_fp(&chunk_vec, num_bytes_expected)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    slice_packed(&packed_input, start_var, len_var, max_len, pad_char)
}

/// Unoptimized slice function using simple loop and conditional selection
/// This version doesn't use binary tree or packing optimization
pub fn slice_unopt<F: PrimeField>(
    data: &[FpVar<F>],
    start_var: &UInt16<F>,
    len_var: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let data_len = data.len();

    // --- 경계 검사 (Bounds Checking) ---
    // 1. start_var <= data_len
    Boolean::enforce_smaller_or_equal_than_le(&start_var.to_bits_le()?, [data_len as u64])?;

    // 2. len_var <= max_len
    Boolean::enforce_smaller_or_equal_than_le(&len_var.to_bits_le()?, [max_len as u64])?;

    // 3. start_var + len_var <= data_len
    let end_exclusive_var = start_var.wrapping_add(len_var);
    Boolean::enforce_smaller_or_equal_than_le(&end_exclusive_var.to_bits_le()?, [data_len as u64])?;

    let mut result = Vec::with_capacity(max_len);

    // For each output position
    for i in 0..max_len {
        let i_const = UInt16::<F>::constant(i as u16);

        // Calculate the source index: start_var + i
        let src_idx = start_var.wrapping_add(&i_const);

        // Check if i < len_var (within the slice length)
        let i_lt_len = is_less_than(&i_const, len_var)?;

        // Select the element from data at src_idx position
        // We need to check all possible positions in data
        let mut selected = pad_char.clone();
        for (j, data_elem) in data.iter().enumerate() {
            let j_const = UInt16::<F>::constant(j as u16);
            let is_match = src_idx.is_eq(&j_const)?;

            // If src_idx == j, then select data[j]
            selected = FpVar::conditionally_select(&is_match, data_elem, &selected)?;
        }

        // If i < len_var, use selected value, otherwise use pad_char
        let final_val = FpVar::conditionally_select(&i_lt_len, &selected, pad_char)?;
        result.push(final_val);
    }

    Ok(result)
}

/// Helper function to check if a < b for UInt16
fn is_less_than<F: PrimeField>(a: &UInt16<F>, b: &UInt16<F>) -> Result<Boolean<F>, SynthesisError> {
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;
    a_lt_b(&a_bits, &b_bits)
}

pub fn slice_packed<F: PrimeField>(
    data: &[FpVar<F>], // 이미 big-endian으로 16개씩 grouped 된 입력임.
    start_var: &UInt16<F>,
    len_var: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // let output = Vec::new();
    let nums_per_group: usize = 16;
    let p = log2(nums_per_group);
    // --- 경계 검사 (Bounds Checking) ---
    // 1. start_var <= input_len
    Boolean::enforce_smaller_or_equal_than_le(
        &start_var.to_bits_le()?,
        [(data.len() * 16) as u64],
    )?;

    // 2. len_var <= max_len
    Boolean::enforce_smaller_or_equal_than_le(&len_var.to_bits_le()?, [max_len as u64])?;

    // 3. start_var + length_var <= input_len 강제
    // let end_exclusive_var = UInt16::<F>::addmany(&[start_var.clone(), len_var.clone()]).unwrap();
    let end_exclusive_var = start_var.wrapping_add(len_var);
    Boolean::enforce_smaller_or_equal_than_le(
        &end_exclusive_var.to_bits_le()?,
        [(data.len() * 16) as u64],
    )?;

    let grouped_out_len = 1 + ceil((max_len - 1) as u64, nums_per_group as u64);

    let (start_idx_by_p_var, start_idx_mod_p_var) = divide_mod_power_of_2_circuit(start_var, p)?;

    let minus_one_u16 = UInt16::constant(u16::MAX);

    let (end_idx_by_p_var, _) = divide_mod_power_of_2_circuit(
        &UInt16::<F>::wrapping_add_many(&[start_var.clone(), len_var.clone(), minus_one_u16])?,
        // &UInt16::addmany([start_var.clone(), len_var.clone(), minus_one_u16].as_slice()).unwrap(),
        p,
    )?;

    let group_length_idx = Boolean::le_bits_to_fp(&end_idx_by_p_var.to_bits_le()?)?
        - Boolean::le_bits_to_fp(&start_idx_by_p_var.to_bits_le()?)?
        + F::one();

    let out_grouped = slice_in_binary_tree(
        data,
        &start_idx_by_p_var,
        &group_length_idx,
        grouped_out_len as usize,
    )?;

    let x = nums_per_group * grouped_out_len as usize;

    let out_final: Vec<FpVar<F>> = out_grouped
        .iter()
        .map(|group| unpack_fp_to_byte_fps(group))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    assert!(out_final.len() == x);

    let mut out_options = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let mut current_option = Vec::with_capacity(nums_per_group as usize);
        // j는 0부터 numsPerGroup - 1 까지 반복 (각 행의 열 채우기)
        for j in 0..nums_per_group {
            let idx = i + j; // out_final_values에서 접근할 인덱스

            current_option.push(out_final[idx].clone());
        }
        // 완성된 16개짜리 벡터(current_option)를 out_options에 추가
        out_options.push(current_option);
    }

    let start_idx_mod_p_var = Boolean::le_bits_to_fp(&start_idx_mod_p_var.to_bits_le()?)?;
    let out_with_suffix = multi_mux(&out_options, &start_idx_mod_p_var)?;
    let output = slice_from_start(
        &out_with_suffix,
        &Boolean::le_bits_to_fp(&len_var.to_bits_le()?)?,
        max_len,
        pad_char,
    )?;

    // --- 결과 반환 ---
    Ok(output)
}

pub fn reconstruct_payload_with_overlap<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    length_selector: &FpVar<F>,
    payload: &[FpVar<F>],
    overlap: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let max_overlap_len = overlap.len();
    let max_payload_len = payload.len();
    let max_total_len = max_overlap_len + max_payload_len;
    let pad_char = FpVar::<F>::Constant(F::from(b'A'));

    let is_len_0 = length_selector.is_eq(&FpVar::<F>::zero())?;
    let is_len_1 = length_selector.is_eq(&FpVar::<F>::one())?;
    let is_len_2 = length_selector.is_eq(&FpVar::<F>::constant(F::from(2u64)))?;
    let is_len_3 = length_selector.is_eq(&FpVar::<F>::constant(F::from(3u64)))?;

    let selector = vec![&is_len_0, &is_len_1, &is_len_2, &is_len_3];
    let mut sum = FpVar::<F>::zero();
    for &b in selector.iter() {
        let is_len = FpVar::<F>::from(b.clone());
        sum += is_len;
    }

    sum.enforce_equal(&FpVar::<F>::one())?;

    // --- 결과 벡터 재구성 ---
    let mut combined_b64 = Vec::with_capacity(max_total_len);

    for i in 0..max_total_len {
        // ✅ 수정된 부분: 4가지 경우의 수를 각각 계산

        // Case 0: length_selector == 0
        let val_for_len_0 = payload.get(i).cloned().unwrap_or_else(|| pad_char.clone());

        // Case 1: length_selector == 1
        let val_for_len_1 = if i < 1 {
            overlap[i].clone()
        } else {
            payload
                .get(i - 1)
                .cloned()
                .unwrap_or_else(|| pad_char.clone())
        };

        // Case 2: length_selector == 2
        let val_for_len_2 = if i < 2 {
            overlap[i].clone()
        } else {
            payload
                .get(i - 2)
                .cloned()
                .unwrap_or_else(|| pad_char.clone())
        };

        // Case 3: length_selector == 3
        let val_for_len_3 = if i < 3 {
            overlap[i].clone()
        } else {
            payload
                .get(i - 3)
                .cloned()
                .unwrap_or_else(|| pad_char.clone())
        };

        // ✅ 수정된 부분: 4-to-1 멀티플렉서로 4개의 값 중 하나를 최종 선택
        let result1 = is_len_1.select(&val_for_len_1, &val_for_len_0)?;
        let result2 = is_len_2.select(&val_for_len_2, &result1)?;
        let final_val = is_len_3.select(&val_for_len_3, &result2)?;

        combined_b64.push(final_val);
    }

    Ok(combined_b64)
}

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
    // length_bits.resize(comp_bit_len, Boolean::constant(false));

    let mut output = Vec::new();
    for i in 0..output_len {
        let i_fp = UInt16::<F>::constant(i as u16);

        // let idx = UInt16::<F>::addmany(&[offset.clone(), i_fp.clone()])?;
        let idx = offset.wrapping_add(&i_fp);

        // idx의 비트 표현
        let mut idx_bits = idx.to_bits_le()?;
        idx_bits = idx_bits[..comp_bit_len].to_vec();
        // idx_bits.resize(comp_bit_len, Boolean::constant(false));

        // i를 비트로 표현
        let mut i_bits = i_fp.to_bits_le()?;
        i_bits = i_bits[..comp_bit_len].to_vec();
        // i_bits.resize(comp_bit_len, Boolean::constant(false));

        // i < length인지 확인
        let i_lt_length = a_lt_b(&i_bits, &length_bits)?;

        // idx < input_len인지 확인
        let idx_lt_input_len = a_lt_b(&idx_bits, &input_len_bits)?;

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

/// ## 인자들
/// * `cs`: 제약 시스템 참조 (`ConstraintSystemRef<F>`).
/// * `in_vec`: 전체 입력 벡터를 나타내는 `FpVar<F>` 슬라이스 (`&[FpVar<F>]`).
/// * `length`: 반환할 슬라이스의 실제 길이를 나타내는 `FpVar<F>`. `1 <= length <= out_len` 범위의 값을 가져야 합니다.
/// * `out_len`: 반환될 벡터의 고정된 길이 (`usize`).
///
/// ## 반환값
/// * `Result<Vec<FpVar<F>>, SynthesisError>`: 길이가 `out_len`인 결과 벡터. 첫 `length` 요소는 `in_vec`에서 가져오고 나머지는 0입니다. 제약 조건이 충족되지 않으면 `SynthesisError`.
pub fn slice_from_start<F: PrimeField>(
    in_vec: &[FpVar<F>],
    length: &FpVar<F>,
    out_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let in_len = in_vec.len();

    // ---- 입력값 검증 (Asserts) ----
    // Rust의 assert 매크로를 사용하여 개발 중에 조건을 확인합니다.
    // 이 조건들은 Circom의 컴파일 타임 assert와 유사한 역할을 합니다.
    assert!(out_len > 0, "출력 길이(out_len)는 0보다 커야 합니다.");
    assert!(
        out_len <= in_len,
        "출력 길이(out_len)는 입력 길이(in_len = {})보다 작거나 같아야 합니다.",
        in_len
    );
    // `1 <= length <= out_len` 검증은 아래 lt_bit_vector 호출에서 암시적으로 수행됩니다.

    // ---- 마스크 생성 ----
    // 1. lt_bit_vector를 호출하여 마스크 벡터를 생성합니다.
    //    lt_bit_vector(length, out_len)는 i < length 일 때 1 (FpVar), 아닐 때 0 (FpVar)을 반환합니다.
    //    이 함수는 내부적으로 length가 1과 out_len 사이의 값인지 검증합니다.
    let mask_vec: Vec<FpVar<F>> = lt_bit_vector(length, out_len)?;
    // mask_vec의 길이는 out_len입니다. 각 요소는 0 또는 1 값을 가집니다.

    // ---- 슬라이스 및 패딩 적용 ----
    // 2. 입력 벡터의 첫 out_len 요소와 마스크 벡터를 요소별로 곱합니다.
    //    - i < length 이면, mask_vec[i]는 1이므로 in_vec[i] * 1 = in_vec[i]가 됩니다.
    //    - i >= length 이면, mask_vec[i]는 0이므로 in_vec[i] * 0 = 0이 됩니다.
    //    `.take(out_len)`: 입력 벡터가 out_len보다 길 수 있으므로, 앞에서부터 out_len 개만 사용합니다.
    //    `.zip()`: 입력 요소와 마스크 요소를 짝지어줍니다. 길이는 짧은 쪽(out_len)에 맞춰집니다.
    //    `.map()`: 각 쌍에 대해 곱셈을 수행합니다.
    //    `.collect()`: 결과를 새로운 벡터로 만듭니다.
    let out_vec: Vec<FpVar<F>> = in_vec
        .iter()
        .take(out_len) // 입력 벡터에서 필요한 만큼만 사용
        .zip(mask_vec.iter()) // 마스크 벡터와 짝짓기
        .map(|(inp_val, mask_val)| {
            mask_val * (inp_val * mask_val) + (FpVar::Constant(F::from(1u8)) - mask_val) * pad_char
        }) // 요소별 곱셈 (제약조건 생성)
        .collect();

    // 결과 벡터의 길이는 항상 out_len이어야 합니다.
    debug_assert_eq!(
        out_vec.len(),
        out_len,
        "결과 벡터의 길이가 out_len과 다릅니다."
    );

    Ok(out_vec)
}

/// `slice_from_start`의 제약 조건 최적화 버전입니다.
/// 상태 저장 스캔 방식을 사용하여 중간 벡터 생성을 제거하고 제약 조건을 줄입니다.
pub fn slice_from_start_optimized<F: PrimeField>(
    _cs: ConstraintSystemRef<F>, // 네임스페이스가 필요할 경우를 위해 남겨둠
    in_vec: &[FpVar<F>],
    length: &FpVar<F>, // 슬라이스 할 실제 길이 (회로 내 변수)
    out_len: usize,    // 최종 출력 벡터의 고정 길이
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // ---- 입력값 검증 (개발 중 확인) ----
    assert!(out_len > 0, "출력 길이는 0보다 커야 합니다.");
    assert!(
        out_len <= in_vec.len(),
        "출력 길이는 입력 길이({})보다 작거나 같아야 합니다.",
        in_vec.len()
    );

    let mut output = Vec::with_capacity(out_len);

    // --- 상태 저장 스캔을 위한 상태 변수 ---
    // 이 플래그는 루프가 `length`를 지나는 순간 true로 바뀝니다.
    let mut is_past_the_end = Boolean::FALSE;

    for i in 0..out_len {
        // 현재 루프 인덱스 `i`를 회로 내 상수로 변환합니다.
        let i_const = FpVar::<F>::Constant(F::from(i as u64));

        // 현재 위치가 슬라이스의 끝인지 확인합니다 (`length == i`).
        let is_at_boundary = length.is_eq(&i_const)?;

        // 상태 업데이트: 이전에 이미 끝을 지났거나, 바로 지금 끝에 도달했다면 `is_past_the_end`는 true가 됩니다.
        is_past_the_end = is_past_the_end | is_at_boundary;

        // 마스크 생성: `is_past_the_end`가 true이면 패딩해야 하므로, 마스크는 그 반대(`not`)가 됩니다.
        // 즉, `i < length`일 때만 `should_take_from_input`은 true가 됩니다.
        let should_take_from_input = !is_past_the_end.clone();

        // 최종 출력 요소 선택: `should_take_from_input` 값에 따라 입력값 또는 패딩 문자를 선택합니다.
        // এটি `if should_take_from_input { in_vec[i] } else { pad_char }` 와 동일합니다.
        let out_element =
            FpVar::conditionally_select(&should_take_from_input, &in_vec[i], pad_char)?;
        output.push(out_element);
    }

    Ok(output)
}

/// UInt 타입의 비트들을 사용하여 효율적으로 원-핫 벡터를 생성합니다. (Decoder)
/// N번의 is_eq 비교를 훨씬 저렴한 Boolean 로직으로 대체합니다.
fn one_hot_from_uint<F: PrimeField>(
    index: &UInt16<F>, // 타입을 UInt16으로 강제
    n: usize,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    // index의 비트 표현을 한 번만 얻습니다.
    let index_bits = index.to_bits_le()?;
    let num_index_bits = index_bits.len();

    (0..n)
        .map(|i| {
            // 상수 i의 비트 표현
            let i_bits = UInt16::constant(i as u16).to_bits_le()?;

            // index의 각 비트와 상수 i의 각 비트가 같은지 확인 (XNOR)
            let mut all_bits_match = Boolean::TRUE;
            for k in 0..num_index_bits {
                // is_eq = !(a ^ b)
                let bit_match = !index_bits[k].clone().bitxor(&i_bits[k]);
                all_bits_match = all_bits_match & bit_match;
            }
            Ok(all_bits_match)
        })
        .collect()
}

/// 원-핫 벡터로부터 `[1,1,...,0,0]` 형태의 마스크 벡터를 생성합니다.
/// (기존 lt_bit_vector의 접미사 스캔 로직 재사용)
fn lt_mask_from_one_hot<F: PrimeField>(
    one_hot_vec: &[Boolean<F>],
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let n = one_hot_vec.len();
    if n == 0 {
        return Ok(Vec::new());
    }

    let mut out = vec![Boolean::FALSE; n];
    out[n - 1] = one_hot_vec[n - 1].clone();

    if n >= 2 {
        for i in (0..=(n - 2)).rev() {
            // out[i] = Boolean::or(&one_hot_vec[i], &out[i + 1])?;
            out[i] = one_hot_vec[i].clone() | &out[i + 1];
        }
    }
    Ok(out)
}

/// 제약 조건이 최종 최적화된 slice_from_start 함수
pub fn slice_from_start_final<F: PrimeField>(
    in_vec: &[FpVar<F>],
    length: &UInt16<F>, // 타입을 FpVar가 아닌 UInt16으로 받음
    out_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    assert!(out_len > 0, "출력 길이는 0보다 커야 합니다.");
    assert!(
        out_len <= in_vec.len(),
        "출력 길이는 입력 길이보다 작거나 같아야 합니다."
    );

    // --- 🛠️ 수정된 핵심 로직 ---
    // 1. `length - 1`을 계산합니다. length가 0이면 u16::MAX로 안전하게 감싸집니다.
    let length_minus_one = length.wrapping_add(&UInt16::constant(u16::MAX));

    // 2. `length - 1`에 해당하는 위치에 1이 있는 원-핫 벡터를 효율적으로 생성합니다.
    //    length가 0이면, length_minus_one은 out_len보다 훨씬 큰 값이므로 모두 0인 벡터가 생성됩니다.
    let one_hot_vec = one_hot_from_uint(&length_minus_one, out_len)?;

    // 3. 원-핫 벡터를 `i < length`일 때 true인 마스크로 변환합니다.
    let should_take_from_input_mask = lt_mask_from_one_hot(&one_hot_vec)?;
    // --- 로직 수정 종료 ---

    let mut output = Vec::with_capacity(out_len);
    for i in 0..out_len {
        // 4. 최종 선택: 생성된 마스크를 그대로 사용하여 결과를 선택합니다. .not()이 필요 없습니다.
        let out_element =
            FpVar::conditionally_select(&should_take_from_input_mask[i], &in_vec[i], pad_char)?;
        output.push(out_element);
    }

    Ok(output)
}

/// 나눗셈의 올림 연산을 수행합니다.
/// ceil(n / q)를 계산합니다.
pub fn ceil(n: u64, q: u64) -> u64 {
    assert!(q != 0, "Divisor q cannot be zero"); // q가 0이면 패닉

    let quotient = n / q; // 정수 나눗셈 (버림)
    let remainder = n % q; // 나머지

    if remainder == 0 {
        // 나누어 떨어지면 몫을 그대로 반환
        quotient
    } else {
        // 나머지가 있으면 몫에 1을 더하여 올림 효과
        quotient + 1
    }
}

/// x가 2의 거듭제곱인지 확인하고, 맞다면 log2(x)를 반환합니다.
/// x가 2의 거듭제곱이 아니면 None을 반환합니다.
pub fn log_base_2(x: usize) -> Option<u32> {
    if x <= 0 {
        return None;
    }

    // x가 2의 거듭제곱인지 확인 (비트가 하나만 설정되어 있는지)
    if x & (x - 1) != 0 {
        return None;
    }

    // trailing_zeros는 가장 낮은 비트부터 0의 개수를 센다 (즉, log2)
    Some(x.trailing_zeros())
}

/// w비트 세그먼트 배열을 big-endian 순서로 하나의 필드 원소로 결합합니다.
///
/// Circom의 Segments2NumBE와 동일한 기능을 수행합니다.
///
/// # Arguments
/// * `segments` - w비트 값들의 배열 (각 원소는 0 ~ 2^w-1 범위)
/// * `bit_width` - 각 세그먼트의 비트 너비
///
/// # Returns
/// * 결합된 필드 원소
pub fn segments_to_num_be<F: PrimeField>(
    segments: &[FpVar<F>],
    bit_width: usize,
) -> Result<FpVar<F>, SynthesisError> {
    // n * w <= 253 검증 (필드 크기 제한)
    assert!(
        segments.len() * bit_width <= 253,
        "Total bit width exceeds field capacity"
    );

    let mut result = FpVar::<F>::zero();
    let mut multiplier = F::one();

    // Big-endian이므로 마지막 원소부터 처리
    for i in (0..segments.len()).rev() {
        result += &segments[i] * FpVar::constant(multiplier);
        // multiplier *= 2^bit_width
        multiplier *= F::from(1u64 << bit_width);
    }

    Ok(result)
}

/// 필드 원소를 여러 세그먼트로 분해합니다 (big-endian).
/// segments_to_num_be의 역연산입니다.
///
/// # Arguments
/// * `num` - 분해할 필드 원소
/// * `num_segments` - 출력 세그먼트 개수
/// * `bit_width` - 각 세그먼트의 비트 너비
///
/// # Returns
/// * 세그먼트 배열
pub fn num_to_segments_be<F: PrimeField>(
    num: &FpVar<F>,
    num_segments: usize,
    bit_width: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // 전체 비트로 변환
    let total_bits = num_segments * bit_width;
    let bits = num.to_bits_le()?;

    // 필요한 비트만큼만 사용
    let bits = &bits[..total_bits.min(bits.len())];

    let mut segments = Vec::with_capacity(num_segments);

    // Big-endian이므로 높은 비트부터 처리
    for i in 0..num_segments {
        let start_bit = (num_segments - 1 - i) * bit_width;
        let end_bit = start_bit + bit_width;

        let segment_bits = if end_bit <= bits.len() {
            &bits[start_bit..end_bit]
        } else if start_bit < bits.len() {
            &bits[start_bit..]
        } else {
            &[]
        };

        let segment = Boolean::le_bits_to_fp(segment_bits)?;
        segments.push(segment);
    }

    Ok(segments)
}

fn pad_input<F: PrimeField>(input: &[FpVar<F>]) -> Vec<FpVar<F>> {
    let mut input_padded = input.to_vec();
    let next_power_of_two = input.len().next_power_of_two();
    let zero = FpVar::<F>::zero();
    input_padded.resize(next_power_of_two, zero);
    input_padded
}

// ============================================================================
// V2 API: Refactored for Better Readability and Efficiency
// ============================================================================

/// Enhanced slice function with improved readability and optimized constraints.
///
/// Extracts a substring from `data` starting at `start` with length `len`,
/// padding the result to `max_len` with `pad_char`.
///
/// # Arguments
/// * `data` - Input byte array (each `FpVar<F>` represents one byte)
/// * `start` - Starting index for the slice
/// * `len` - Length of the slice
/// * `max_len` - Maximum output length (for circuit sizing)
/// * `pad_char` - Character to pad the output with
///
/// # Constraints
/// - `start <= data.len()`
/// - `len <= max_len`
/// - `start + len <= data.len()`
pub fn slice_v2<F: PrimeField>(
    data: &[FpVar<F>],
    start: &UInt16<F>,
    len: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // Validate input bounds
    enforce_slice_bounds_v2(data.len(), start, len, max_len)?;

    // Pack bytes into field elements (16 bytes per element)
    let packed_data = pack_bytes_for_slicing_v2(data)?;

    // Perform the slice operation on packed data
    slice_packed_v2(&packed_data, start, len, max_len, pad_char)
}

/// Validates that slice parameters are within valid bounds.
fn enforce_slice_bounds_v2<F: PrimeField>(
    data_len: usize,
    start: &UInt16<F>,
    len: &UInt16<F>,
    max_len: usize,
) -> Result<(), SynthesisError> {
    let start_bits = start.to_bits_le()?;
    let len_bits = len.to_bits_le()?;

    // Constraint 1: start <= data_len
    Boolean::enforce_smaller_or_equal_than_le(&start_bits, [data_len as u64])?;

    // Constraint 2: len <= max_len
    Boolean::enforce_smaller_or_equal_than_le(&len_bits, [max_len as u64])?;

    // Constraint 3: start + len <= data_len (prevents overflow access)
    let end_index = start.wrapping_add(len);
    Boolean::enforce_smaller_or_equal_than_le(&end_index.to_bits_le()?, [data_len as u64])?;

    Ok(())
}

/// Packs byte array into field elements (16 bytes per element) for efficient processing.
fn pack_bytes_for_slicing_v2<F: PrimeField>(
    data: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    const BYTES_PER_ELEMENT: usize = 16;

    data.chunks(BYTES_PER_ELEMENT)
        .map(|chunk| {
            let mut padded_chunk = chunk.to_vec();
            // Pad with constant zeros (not witnesses)
            padded_chunk.resize(BYTES_PER_ELEMENT, FpVar::constant(F::zero()));
            pack_byte_fps_to_fp(&padded_chunk, BYTES_PER_ELEMENT)
        })
        .collect()
}

/// Performs slice operation on packed field elements.
fn slice_packed_v2<F: PrimeField>(
    packed_data: &[FpVar<F>],
    start: &UInt16<F>,
    len: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    const BYTES_PER_GROUP: usize = 16;
    const GROUP_BITS: u32 = 4; // log2(16)

    let total_bytes = packed_data.len() * BYTES_PER_GROUP;

    // Validate bounds for packed data
    enforce_slice_bounds_v2(total_bytes, start, len, max_len)?;

    // Calculate how many packed groups we need for output
    let output_groups = calculate_output_groups_v2(max_len, BYTES_PER_GROUP);

    // Decompose start index into group index and offset within group
    let (group_start, byte_offset) = divide_mod_power_of_2_circuit(start, GROUP_BITS)?;

    // Calculate end group index
    let end_index = UInt16::<F>::wrapping_add_many(&[
        start.clone(),
        len.clone(),
        UInt16::constant(u16::MAX), // -1 in wrapping arithmetic
    ])?;
    let (group_end, _) = divide_mod_power_of_2_circuit(&end_index, GROUP_BITS)?;

    // Calculate number of groups needed
    let num_groups = calculate_group_length_v2::<F>(&group_start, &group_end)?;

    // Extract relevant packed groups using binary tree selection
    let selected_groups =
        select_groups_binary_tree_v2(packed_data, &group_start, &num_groups, output_groups)?;

    // Unpack field elements back to bytes
    let unpacked_bytes = unpack_groups_to_bytes_v2(&selected_groups)?;

    // Align bytes based on the offset within the starting group
    let aligned_bytes = align_bytes_by_offset_v2(&unpacked_bytes, &byte_offset, max_len)?;

    // Trim to final length with padding
    trim_and_pad_v2(&aligned_bytes, len, max_len, pad_char)
}

/// Calculates the number of output groups needed.
fn calculate_output_groups_v2(max_len: usize, bytes_per_group: usize) -> usize {
    if max_len == 0 {
        return 0;
    }
    (max_len - 1) / bytes_per_group + 1
}

/// Calculates the number of groups between start and end indices.
fn calculate_group_length_v2<F: PrimeField>(
    group_start: &UInt16<F>,
    group_end: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let start_fp = Boolean::le_bits_to_fp(&group_start.to_bits_le()?)?;
    let end_fp = Boolean::le_bits_to_fp(&group_end.to_bits_le()?)?;
    Ok(end_fp - start_fp + FpVar::one())
}

/// Selects groups from packed data using binary tree selection for efficiency.
fn select_groups_binary_tree_v2<F: PrimeField>(
    packed_data: &[FpVar<F>],
    offset: &UInt16<F>,
    length: &FpVar<F>,
    output_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let input_len = packed_data.len();
    let padded_input = pad_to_power_of_two_v2(packed_data);

    let select_bits = (padded_input.len().next_power_of_two().trailing_zeros()) as usize;
    let compare_bits = select_bits + 1;

    // Input length as constant bits
    let input_len_bits: Vec<Boolean<F>> = (0..compare_bits)
        .map(|k| Boolean::constant(((input_len >> k) & 1) == 1))
        .collect();

    // Length as variable bits
    let length_bits = length.to_bits_le()?;
    let length_bits = &length_bits[..compare_bits.min(length_bits.len())];

    let mut result = Vec::with_capacity(output_len);

    for i in 0..output_len {
        let i_uint = UInt16::<F>::constant(i as u16);
        let index = offset.wrapping_add(&i_uint);

        // Check if this position is valid
        let is_within_length = is_index_valid_v2(i, length_bits)?;
        let is_within_input = is_index_within_bounds_v2(&index, &input_len_bits, compare_bits)?;
        let is_valid = is_within_length & is_within_input;

        // Select element using binary tree
        let selected = select_element_binary_v2(&padded_input, &index, select_bits)?;

        // Use zero padding for invalid indices
        let element =
            FpVar::conditionally_select(&is_valid, &selected, &FpVar::constant(F::zero()))?;

        result.push(element);
    }

    Ok(result)
}

/// Checks if index i < length
fn is_index_valid_v2<F: PrimeField>(
    i: usize,
    length_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let i_bits = UInt16::<F>::constant(i as u16).to_bits_le()?;
    let i_bits = &i_bits[..length_bits.len().min(i_bits.len())];
    a_lt_b(i_bits, length_bits)
}

/// Checks if index < bound
fn is_index_within_bounds_v2<F: PrimeField>(
    index: &UInt16<F>,
    bound_bits: &[Boolean<F>],
    num_bits: usize,
) -> Result<Boolean<F>, SynthesisError> {
    let index_bits = index.to_bits_le()?;
    let index_bits = &index_bits[..num_bits.min(index_bits.len())];
    a_lt_b(index_bits, bound_bits)
}

/// Selects an element from array using binary tree approach
fn select_element_binary_v2<F: PrimeField>(
    array: &[FpVar<F>],
    index: &UInt16<F>,
    num_select_bits: usize,
) -> Result<FpVar<F>, SynthesisError> {
    let index_bits = index.to_bits_le()?;
    let select_bits = &index_bits[..num_select_bits];
    select_array_element(array, select_bits)
}

/// Pads array to the next power of two
fn pad_to_power_of_two_v2<F: PrimeField>(input: &[FpVar<F>]) -> Vec<FpVar<F>> {
    let mut padded = input.to_vec();
    let target_len = input.len().next_power_of_two();
    padded.resize(target_len, FpVar::constant(F::zero()));
    padded
}

/// Unpacks field elements back into individual bytes
fn unpack_groups_to_bytes_v2<F: PrimeField>(
    groups: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    Ok(groups
        .iter()
        .map(unpack_fp_to_byte_fps)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect())
}

/// Aligns bytes by rotating based on the offset within a group
fn align_bytes_by_offset_v2<F: PrimeField>(
    bytes: &[FpVar<F>],
    offset: &UInt16<F>,
    max_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    const BYTES_PER_GROUP: usize = 16;

    // Create rotation options (16 possible alignments)
    let mut rotation_options = Vec::with_capacity(max_len);

    for output_pos in 0..max_len {
        let mut position_options = Vec::with_capacity(BYTES_PER_GROUP);

        for rotation in 0..BYTES_PER_GROUP {
            let source_index = output_pos + rotation;
            position_options.push(
                bytes
                    .get(source_index)
                    .cloned()
                    .unwrap_or_else(|| FpVar::constant(F::zero())),
            );
        }

        rotation_options.push(position_options);
    }

    // Select the correct rotation based on offset
    let offset_fp = Boolean::le_bits_to_fp(&offset.to_bits_le()?)?;
    multi_mux(&rotation_options, &offset_fp)
}

/// Trims the byte array to the specified length and pads with pad_char
fn trim_and_pad_v2<F: PrimeField>(
    bytes: &[FpVar<F>],
    length: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let length_fp = Boolean::le_bits_to_fp(&length.to_bits_le()?)?;
    slice_from_start(bytes, &length_fp, max_len, pad_char)
}

/// 그룹화된 슬라이스 함수 (Circom의 SliceGrouped와 동일).
///
/// 입력 배열을 그룹으로 묶은 후 슬라이싱하여 효율성을 높입니다.
///
/// # Arguments
/// * `data` - 입력 바이트 배열 (각 FpVar<F>는 1바이트)
/// * `index` - 슬라이스 시작 인덱스
/// * `length` - 슬라이스 길이
/// * `max_len` - 최대 출력 길이
/// * `pad_char` - 패딩 문자
/// * `nums_per_group` - 그룹당 원소 개수 (2의 거듭제곱이어야 함)
///
/// # Cost
/// Circom 주석 참고:
/// - Slice: (inLen / g) + (outLen / g) + ((outLen * inLen) / (2 * g))
/// - Multiplexer: outLen * g
/// - SliceFromStart: outLen * 2
///
/// # Range checks
/// - index in [0, inLen)
/// - length in (0, outLen]
/// - index + length in [0, inLen]
/// - nums_per_group는 2의 거듭제곱 (컴파일 타임에 확인)
pub fn slice_grouped<F: PrimeField>(
    data: &[FpVar<F>],
    index: &UInt16<F>,
    length: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
    nums_per_group: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let in_len = data.len();

    // nums_per_group이 2의 거듭제곱인지 확인
    let log_p = log_base_2(nums_per_group).expect("nums_per_group must be a power of 2");

    // --- Range Checks ---
    // 1. index in [0, inLen - 1]
    Boolean::enforce_smaller_or_equal_than_le(&index.to_bits_le()?, [in_len as u64 - 1])?;

    // 2. length in [1, outLen]
    let length_minus_one = length.wrapping_add(&UInt16::constant(u16::MAX)); // length - 1
    Boolean::enforce_smaller_or_equal_than_le(
        &length_minus_one.to_bits_le()?,
        [max_len as u64 - 1],
    )?;

    // 3. index + length in [0, inLen]
    let end_index = index.wrapping_add(length);
    Boolean::enforce_smaller_or_equal_than_le(&end_index.to_bits_le()?, [in_len as u64])?;

    // --- 입력 그룹화 ---
    let grouped_in_width = nums_per_group * 8; // 각 바이트는 8비트
    assert!(
        grouped_in_width < 253,
        "Grouped width must be less than field size"
    );

    let grouped_in_len = ceil(in_len as u64, nums_per_group as u64) as usize;
    let mut in_grouped = Vec::with_capacity(grouped_in_len);

    // 입력을 nums_per_group 크기의 그룹으로 묶어 big-endian으로 결합
    for i in 0..grouped_in_len {
        let mut group = Vec::with_capacity(nums_per_group);
        for j in 0..nums_per_group {
            let idx = i * nums_per_group + j;
            if idx < in_len {
                group.push(data[idx].clone());
            } else {
                // 부족한 부분은 0으로 패딩
                group.push(FpVar::constant(F::zero()));
            }
        }
        // Big-endian으로 결합 (segments_to_num_be 사용)
        let grouped_elem = segments_to_num_be(&group, 8)?; // 각 세그먼트는 8비트
        in_grouped.push(grouped_elem);
    }

    // --- 인덱스 분해 ---
    // index = startIdxByP * numsPerGroup + startIdxModP
    let (start_idx_by_p, start_idx_mod_p) = divide_mod_power_of_2_circuit(index, log_p)?;

    // (index + length - 1) = endIdxByP * numsPerGroup + endIdxModP
    let index_plus_length_minus_one = UInt16::<F>::wrapping_add_many(&[
        index.clone(),
        length.clone(),
        UInt16::constant(u16::MAX), // -1
    ])?;
    let (end_idx_by_p, _end_idx_mod_p) =
        divide_mod_power_of_2_circuit(&index_plus_length_minus_one, log_p)?;

    // --- 출력 그룹 개수 계산 ---
    // 서브리스트가 최대한 많은 그룹에 걸칠 수 있는 경우는
    // 그룹의 마지막 원소에서 시작할 때입니다.
    // 따라서: 1 + ceil((outLen - 1) / numsPerGroup)
    let grouped_out_len = 1 + ceil((max_len - 1) as u64, nums_per_group as u64) as usize;

    // --- 그룹화된 배열에서 슬라이싱 ---
    // length_in_groups = endIdxByP - startIdxByP + 1
    let start_fp = Boolean::le_bits_to_fp(&start_idx_by_p.to_bits_le()?)?;
    let end_fp = Boolean::le_bits_to_fp(&end_idx_by_p.to_bits_le()?)?;
    let length_in_groups = end_fp - start_fp + FpVar::one();

    let out_grouped = slice_in_binary_tree(
        &in_grouped,
        &start_idx_by_p,
        &length_in_groups,
        grouped_out_len,
    )?;

    // --- 그룹 해제 (ConvertBase 역할) ---
    let x = nums_per_group * grouped_out_len;
    let mut out_final = Vec::with_capacity(x);

    for group in &out_grouped {
        // 각 그룹을 바이트로 분해
        let bytes = num_to_segments_be(group, nums_per_group, 8)?;
        out_final.extend(bytes);
    }

    // 검증: (outLen - 1) + (numsPerGroup - 1) <= X - 1
    assert!((max_len - 1) + (nums_per_group - 1) <= x - 1);

    // --- 회전 옵션 생성 (MultiMux 역할) ---
    // outOptions[i][j] = outFinal[i + j]
    let mut out_options = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let mut option = Vec::with_capacity(nums_per_group);
        for j in 0..nums_per_group {
            option.push(out_final[i + j].clone());
        }
        out_options.push(option);
    }

    // --- Multiplexer로 올바른 오프셋 선택 ---
    // startIdxModP를 사용하여 올바른 정렬 선택
    let start_idx_mod_p_fp = Boolean::le_bits_to_fp(&start_idx_mod_p.to_bits_le()?)?;
    let out_with_suffix = multi_mux(&out_options, &start_idx_mod_p_fp)?;

    // --- 최종적으로 길이만큼만 자르고 나머지는 패딩 ---
    let length_fp = Boolean::le_bits_to_fp(&length.to_bits_le()?)?;
    let output = slice_from_start(&out_with_suffix, &length_fp, max_len, pad_char)?;

    Ok(output)
}

/// 효율적인 슬라이스 함수 (Circom의 SliceEfficient와 동일).
///
/// slice_grouped의 래퍼로, 동일한 함수 시그니처를 가지며
/// 기존 slice 함수의 대체로 사용할 수 있습니다.
///
/// # Arguments
/// * `data` - 입력 바이트 배열 (각 FpVar<F>는 1바이트)
/// * `index` - 슬라이스 시작 인덱스
/// * `length` - 슬라이스 길이
/// * `max_len` - 최대 출력 길이
/// * `pad_char` - 패딩 문자
///
/// # Returns
/// * 슬라이스된 배열
pub fn slice_efficient<F: PrimeField>(
    data: &[FpVar<F>],
    index: &UInt16<F>,
    length: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // inWidth = 8 (각 원소가 1바이트)
    // numsPerGroup = 16 (최대값, 8 * 16 = 128 < 253)
    const NUMS_PER_GROUP: usize = 16;

    slice_grouped(data, index, length, max_len, pad_char, NUMS_PER_GROUP)
}

#[cfg(test)]
mod tests {
    use ark_ff::PrimeField;
    use ark_r1cs_std::{
        R1CSVar,
        alloc::AllocVar,
        eq::EqGadget,
        fields::{FieldVar, fp::FpVar},
        uint16::UInt16,
    };
    use ark_relations::r1cs::ConstraintSystem;

    use crate::slice_v2::{log_base_2, segments_to_num_be, slice_efficient, slice_grouped};
    use crate::{slice, slice_from_start, slice_unopt, slice_v2};

    type F = ark_bn254::Fr;

    #[test]
    fn test_slice_from_start() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789".to_vec();
        let input = input.repeat(10);
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let length = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(10u64))).unwrap();
        let out_len = 93;
        let pad_char = FpVar::<F>::Constant(F::from(b'A' as u64));

        let mut expected = vec![FpVar::<F>::zero(); out_len];
        for i in 0..10 {
            expected[i] = FpVar::<F>::new_constant(cs.clone(), F::from(input[i])).unwrap();
        }

        let result = slice_from_start(&input_var, &length, out_len, &pad_char).unwrap();
        assert!(cs.is_satisfied().unwrap());

        expected.enforce_equal(&result).unwrap();

        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_slice_opt() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789ABCDEFGHIJ";
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let start = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let len = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 15;
        let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

        let result = slice(&input_var, &start, &len, max_len, &pad_char).unwrap();
        assert!(cs.is_satisfied().unwrap());

        println!(
            "Optimized slice - number of constraints: {}",
            cs.num_constraints()
        );

        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();

        // Expected: "56789ABCDE" + 5 padding chars
        let expected = b"56789ABCDE_____";
        assert_eq!(result_values.len(), max_len);
        for i in 0..max_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_slice_unopt() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789ABCDEFGHIJ";
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let start = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let len = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 15;
        let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

        let result = slice_unopt(&input_var, &start, &len, max_len, &pad_char).unwrap();
        assert!(cs.is_satisfied().unwrap());

        println!(
            "Unoptimized slice - number of constraints: {}",
            cs.num_constraints()
        );

        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();

        // Expected: "56789ABCDE" + 5 padding chars
        let expected = b"56789ABCDE_____";
        assert_eq!(result_values.len(), max_len);
        for i in 0..max_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_compare_slice_opt_vs_unopt() {
        println!("\n=== Comparing Optimized vs Unoptimized Slice Function ===\n");

        let test_cases = vec![
            (20, 5, 10, 15),   // data_len=20, start=5, len=10, max_len=15
            (50, 10, 20, 30),  // data_len=50, start=10, len=20, max_len=30
            (100, 20, 40, 50), // data_len=100, start=20, len=40, max_len=50
        ];

        for (data_len, start_pos, slice_len, max_len) in test_cases {
            println!(
                "Testing with data_len={}, start={}, len={}, max_len={}:",
                data_len, start_pos, slice_len, max_len
            );

            // Generate test data
            let input: Vec<u8> = (0..data_len).map(|i| (i % 256) as u8).collect();

            // Test optimized version
            let cs_opt = ConstraintSystem::<F>::new_ref();
            let input_var_opt = input
                .iter()
                .map(|byte| FpVar::<F>::new_witness(cs_opt.clone(), || Ok(F::from(*byte))).unwrap())
                .collect::<Vec<_>>();
            let start_opt = UInt16::<F>::new_witness(cs_opt.clone(), || Ok(start_pos)).unwrap();
            let len_opt = UInt16::<F>::new_witness(cs_opt.clone(), || Ok(slice_len)).unwrap();
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            let _result_opt =
                slice(&input_var_opt, &start_opt, &len_opt, max_len, &pad_char).unwrap();
            assert!(cs_opt.is_satisfied().unwrap());
            let constraints_opt = cs_opt.num_constraints();

            // Test unoptimized version
            let cs_unopt = ConstraintSystem::<F>::new_ref();
            let input_var_unopt = input
                .iter()
                .map(|byte| {
                    FpVar::<F>::new_witness(cs_unopt.clone(), || Ok(F::from(*byte))).unwrap()
                })
                .collect::<Vec<_>>();
            let start_unopt = UInt16::<F>::new_witness(cs_unopt.clone(), || Ok(start_pos)).unwrap();
            let len_unopt = UInt16::<F>::new_witness(cs_unopt.clone(), || Ok(slice_len)).unwrap();

            let _result_unopt = slice_unopt(
                &input_var_unopt,
                &start_unopt,
                &len_unopt,
                max_len,
                &pad_char,
            )
            .unwrap();
            assert!(cs_unopt.is_satisfied().unwrap());
            let constraints_unopt = cs_unopt.num_constraints();

            println!("  Optimized:     {} constraints", constraints_opt);
            println!("  Unoptimized:   {} constraints", constraints_unopt);
            println!(
                "  Difference:    {} constraints",
                constraints_unopt as i64 - constraints_opt as i64
            );
            if constraints_opt > 0 {
                println!(
                    "  Ratio:         {:.2}x\n",
                    constraints_unopt as f64 / constraints_opt as f64
                );
            } else {
                println!("  Ratio:         N/A (optimized has 0 constraints)\n");
            }
        }
    }

    #[test]
    fn test_compare_slice_vs_slice_from_start() {
        println!("\n=== Comparing slice() vs slice_from_start() ===\n");

        let test_cases = vec![
            (20, 10, 15),   // data_len=20, len=10, max_len=15
            (50, 20, 30),   // data_len=50, len=20, max_len=30
            (100, 40, 50),  // data_len=100, len=40, max_len=50
            (200, 80, 100), // data_len=200, len=80, max_len=100
        ];

        for (data_len, slice_len, max_len) in test_cases {
            println!(
                "Testing with data_len={}, len={}, max_len={}:",
                data_len, slice_len, max_len
            );

            // Generate test data
            let input: Vec<u8> = (0..data_len).map(|i| (i % 256) as u8).collect();
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            // Test slice() - starts from index 0
            let cs_slice = ConstraintSystem::<F>::new_ref();
            let input_var_slice = input
                .iter()
                .map(|byte| {
                    FpVar::<F>::new_witness(cs_slice.clone(), || Ok(F::from(*byte))).unwrap()
                })
                .collect::<Vec<_>>();
            let start = UInt16::<F>::new_witness(cs_slice.clone(), || Ok(0u16)).unwrap();
            let len = UInt16::<F>::new_witness(cs_slice.clone(), || Ok(slice_len)).unwrap();

            let result_slice = slice(&input_var_slice, &start, &len, max_len, &pad_char).unwrap();
            assert!(cs_slice.is_satisfied().unwrap());
            let constraints_slice = cs_slice.num_constraints();

            // Test slice_from_start()
            let cs_from_start = ConstraintSystem::<F>::new_ref();
            let input_var_from_start = input
                .iter()
                .map(|byte| {
                    FpVar::<F>::new_witness(cs_from_start.clone(), || Ok(F::from(*byte))).unwrap()
                })
                .collect::<Vec<_>>();
            let len_fp =
                FpVar::<F>::new_witness(cs_from_start.clone(), || Ok(F::from(slice_len as u64)))
                    .unwrap();

            let result_from_start =
                slice_from_start(&input_var_from_start, &len_fp, max_len, &pad_char).unwrap();
            assert!(cs_from_start.is_satisfied().unwrap());
            let constraints_from_start = cs_from_start.num_constraints();

            // Verify results are the same
            let result_slice_values: Vec<u8> = result_slice
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();
            let result_from_start_values: Vec<u8> = result_from_start
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            assert_eq!(
                result_slice_values, result_from_start_values,
                "Results differ for data_len={}, len={}, max_len={}",
                data_len, slice_len, max_len
            );

            println!("  slice():            {} constraints", constraints_slice);
            println!(
                "  slice_from_start(): {} constraints",
                constraints_from_start
            );
            println!(
                "  Difference:         {} constraints",
                constraints_slice as i64 - constraints_from_start as i64
            );
            if constraints_from_start > 0 {
                println!(
                    "  Ratio (slice/from_start): {:.2}x\n",
                    constraints_slice as f64 / constraints_from_start as f64
                );
            } else {
                println!("  Ratio:              N/A\n");
            }
        }
    }

    #[test]
    fn test_slice_v2_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789ABCDEFGHIJ";
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let start = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let len = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 15;
        let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

        let result = slice_v2(&input_var, &start, &len, max_len, &pad_char).unwrap();
        assert!(cs.is_satisfied().unwrap());

        println!("slice_v2 - number of constraints: {}", cs.num_constraints());

        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();

        // Expected: "56789ABCDE" + 5 padding chars
        let expected = b"56789ABCDE_____";
        assert_eq!(result_values.len(), max_len);
        for i in 0..max_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_slice_v2_edge_cases() {
        println!("\n=== Testing slice_v2 Edge Cases ===\n");

        // Test case 1: Start from beginning
        {
            let cs = ConstraintSystem::<F>::new_ref();
            let input = b"ABCDEFGHIJ";
            let input_var = input
                .iter()
                .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
                .collect::<Vec<_>>();

            let start = UInt16::<F>::new_witness(cs.clone(), || Ok(0u16)).unwrap();
            let len = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
            let max_len = 8;
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            let result = slice_v2(&input_var, &start, &len, max_len, &pad_char).unwrap();
            assert!(cs.is_satisfied().unwrap());

            let result_values: Vec<u8> = result
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            let expected = b"ABCDE___";
            assert_eq!(result_values, expected, "Start from beginning failed");
            println!(
                "✓ Start from beginning: {} constraints",
                cs.num_constraints()
            );
        }

        // Test case 2: Slice to the end
        {
            let cs = ConstraintSystem::<F>::new_ref();
            let input = b"ABCDEFGHIJ";
            let input_var = input
                .iter()
                .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
                .collect::<Vec<_>>();

            let start = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
            let len = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
            let max_len = 8;
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            let result = slice_v2(&input_var, &start, &len, max_len, &pad_char).unwrap();
            assert!(cs.is_satisfied().unwrap());

            let result_values: Vec<u8> = result
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            let expected = b"FGHIJ___";
            assert_eq!(result_values, expected, "Slice to end failed");
            println!("✓ Slice to end: {} constraints", cs.num_constraints());
        }

        // Test case 3: Full length slice
        {
            let cs = ConstraintSystem::<F>::new_ref();
            let input = b"ABCDEFGHIJ";
            let input_var = input
                .iter()
                .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
                .collect::<Vec<_>>();

            let start = UInt16::<F>::new_witness(cs.clone(), || Ok(0u16)).unwrap();
            let len = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
            let max_len = 10;
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            let result = slice_v2(&input_var, &start, &len, max_len, &pad_char).unwrap();
            assert!(cs.is_satisfied().unwrap());

            let result_values: Vec<u8> = result
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            let expected = b"ABCDEFGHIJ";
            assert_eq!(result_values, expected, "Full length slice failed");
            println!("✓ Full length slice: {} constraints", cs.num_constraints());
        }
    }

    #[test]
    fn test_compare_slice_v2_vs_original() {
        println!("\n=== Comparing slice_v2 vs slice (original) ===\n");

        let test_cases = vec![
            (20, 5, 10, 15),   // data_len=20, start=5, len=10, max_len=15
            (50, 10, 20, 30),  // data_len=50, start=10, len=20, max_len=30
            (100, 20, 40, 50), // data_len=100, start=20, len=40, max_len=50
        ];

        for (data_len, start_pos, slice_len, max_len) in test_cases {
            println!(
                "Testing with data_len={}, start={}, len={}, max_len={}:",
                data_len, start_pos, slice_len, max_len
            );

            // Generate test data
            let input: Vec<u8> = (0..data_len).map(|i| (i % 256) as u8).collect();
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            // Test original slice()
            let cs_original = ConstraintSystem::<F>::new_ref();
            let input_var_original = input
                .iter()
                .map(|byte| {
                    FpVar::<F>::new_witness(cs_original.clone(), || Ok(F::from(*byte))).unwrap()
                })
                .collect::<Vec<_>>();
            let start_original =
                UInt16::<F>::new_witness(cs_original.clone(), || Ok(start_pos)).unwrap();
            let len_original =
                UInt16::<F>::new_witness(cs_original.clone(), || Ok(slice_len)).unwrap();

            let result_original = slice(
                &input_var_original,
                &start_original,
                &len_original,
                max_len,
                &pad_char,
            )
            .unwrap();
            assert!(cs_original.is_satisfied().unwrap());
            let constraints_original = cs_original.num_constraints();

            // Test slice_v2()
            let cs_v2 = ConstraintSystem::<F>::new_ref();
            let input_var_v2 = input
                .iter()
                .map(|byte| FpVar::<F>::new_witness(cs_v2.clone(), || Ok(F::from(*byte))).unwrap())
                .collect::<Vec<_>>();
            let start_v2 = UInt16::<F>::new_witness(cs_v2.clone(), || Ok(start_pos)).unwrap();
            let len_v2 = UInt16::<F>::new_witness(cs_v2.clone(), || Ok(slice_len)).unwrap();

            let result_v2 =
                slice_v2(&input_var_v2, &start_v2, &len_v2, max_len, &pad_char).unwrap();
            assert!(cs_v2.is_satisfied().unwrap());
            let constraints_v2 = cs_v2.num_constraints();

            // Verify results are the same
            let result_original_values: Vec<u8> = result_original
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();
            let result_v2_values: Vec<u8> = result_v2
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            assert_eq!(
                result_original_values, result_v2_values,
                "Results differ for data_len={}, start={}, len={}, max_len={}",
                data_len, start_pos, slice_len, max_len
            );

            println!("  slice (original): {} constraints", constraints_original);
            println!("  slice_v2:         {} constraints", constraints_v2);
            println!(
                "  Difference:       {} constraints",
                constraints_v2 as i64 - constraints_original as i64
            );
            if constraints_original > 0 {
                println!(
                    "  Ratio (v2/original): {:.2}x\n",
                    constraints_v2 as f64 / constraints_original as f64
                );
            } else {
                println!("  Ratio:            N/A\n");
            }
        }
    }

    #[test]
    fn test_log_base_2() {
        assert_eq!(log_base_2(1), Some(0));
        assert_eq!(log_base_2(2), Some(1));
        assert_eq!(log_base_2(4), Some(2));
        assert_eq!(log_base_2(8), Some(3));
        assert_eq!(log_base_2(16), Some(4));
        assert_eq!(log_base_2(32), Some(5));

        // 2의 거듭제곱이 아닌 경우
        assert_eq!(log_base_2(3), None);
        assert_eq!(log_base_2(5), None);
        assert_eq!(log_base_2(6), None);
        assert_eq!(log_base_2(7), None);
        assert_eq!(log_base_2(15), None);
    }

    #[test]
    fn test_segments_to_num_be() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 테스트: [1, 2, 3, 4]를 8비트 세그먼트로 결합
        // Big-endian: 0x01020304
        let segments = vec![
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(4u8))).unwrap(),
        ];

        let result = segments_to_num_be(&segments, 8).unwrap();
        let expected = F::from(0x01020304u32);

        assert_eq!(result.value().unwrap(), expected);
    }

    #[test]
    fn test_slice_grouped_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789ABCDEFGHIJ";
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let index = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let length = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 15;

        let result = slice_grouped(&input_var, &index, &length, max_len, 16).unwrap();
        assert!(cs.is_satisfied().unwrap());

        println!(
            "slice_grouped (16 per group) - number of constraints: {}",
            cs.num_constraints()
        );

        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();

        // Expected: "56789ABCDE" + 5 padding chars
        let expected = b"56789ABCDE\0\0\0\0\0";
        assert_eq!(result_values.len(), max_len);
        for i in 0..max_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_slice_efficient_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789ABCDEFGHIJ";
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let index = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let length = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 15;

        let result = slice_efficient(&input_var, &index, &length, max_len).unwrap();
        assert!(cs.is_satisfied().unwrap());

        println!(
            "slice_efficient - number of constraints: {}",
            cs.num_constraints()
        );

        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();

        // Expected: "56789ABCDE" + 5 padding chars
        let expected = b"56789ABCDE_____";
        assert_eq!(result_values.len(), max_len);
        for i in 0..max_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_compare_slice_efficient_vs_original() {
        println!("\n=== Comparing slice_efficient vs slice (original) ===\n");

        let test_cases = vec![
            (20, 5, 10, 15),    // data_len=20, start=5, len=10, max_len=15
            (50, 10, 20, 30),   // data_len=50, start=10, len=20, max_len=30
            (100, 20, 40, 50),  // data_len=100, start=20, len=40, max_len=50
            (200, 40, 80, 100), // data_len=200, start=40, len=80, max_len=100
        ];

        for (data_len, start_pos, slice_len, max_len) in test_cases {
            println!(
                "Testing with data_len={}, start={}, len={}, max_len={}:",
                data_len, start_pos, slice_len, max_len
            );

            // Generate test data
            let input: Vec<u8> = (0..data_len).map(|i| (i % 256) as u8).collect();
            let pad_char = FpVar::<F>::Constant(F::from(b'_' as u64));

            // Test original slice()
            let cs_original = ConstraintSystem::<F>::new_ref();
            let input_var_original = input
                .iter()
                .map(|byte| {
                    FpVar::<F>::new_witness(cs_original.clone(), || Ok(F::from(*byte))).unwrap()
                })
                .collect::<Vec<_>>();
            let start_original =
                UInt16::<F>::new_witness(cs_original.clone(), || Ok(start_pos)).unwrap();
            let len_original =
                UInt16::<F>::new_witness(cs_original.clone(), || Ok(slice_len)).unwrap();

            let result_original = slice(
                &input_var_original,
                &start_original,
                &len_original,
                max_len,
                &pad_char,
            )
            .unwrap();
            assert!(cs_original.is_satisfied().unwrap());
            let constraints_original = cs_original.num_constraints();

            // Test slice_efficient()
            let cs_efficient = ConstraintSystem::<F>::new_ref();
            let input_var_efficient = input
                .iter()
                .map(|byte| {
                    FpVar::<F>::new_witness(cs_efficient.clone(), || Ok(F::from(*byte))).unwrap()
                })
                .collect::<Vec<_>>();
            let start_efficient =
                UInt16::<F>::new_witness(cs_efficient.clone(), || Ok(start_pos)).unwrap();
            let len_efficient =
                UInt16::<F>::new_witness(cs_efficient.clone(), || Ok(slice_len)).unwrap();

            let result_efficient = slice_efficient(
                &input_var_efficient,
                &start_efficient,
                &len_efficient,
                max_len,
            )
            .unwrap();
            assert!(cs_efficient.is_satisfied().unwrap());
            let constraints_efficient = cs_efficient.num_constraints();

            // Verify results are the same
            let result_original_values: Vec<u8> = result_original
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();
            let result_efficient_values: Vec<u8> = result_efficient
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            assert_eq!(
                result_original_values, result_efficient_values,
                "Results differ for data_len={}, start={}, len={}, max_len={}",
                data_len, start_pos, slice_len, max_len
            );

            println!("  slice (original):   {} constraints", constraints_original);
            println!(
                "  slice_efficient:    {} constraints",
                constraints_efficient
            );
            println!(
                "  Difference:         {} constraints",
                constraints_efficient as i64 - constraints_original as i64
            );
            if constraints_original > 0 {
                println!(
                    "  Ratio (efficient/original): {:.2}x\n",
                    constraints_efficient as f64 / constraints_original as f64
                );
            } else {
                println!("  Ratio:              N/A\n");
            }
        }
    }

    #[test]
    fn test_slice_grouped_different_group_sizes() {
        println!("\n=== Testing slice_grouped with different group sizes ===\n");

        let test_data_len = 64;
        let start_pos = 10;
        let slice_len = 30;
        let max_len = 40;

        let input: Vec<u8> = (0..test_data_len).map(|i| (i % 256) as u8).collect();

        // Test with different group sizes (all powers of 2)
        for &group_size in &[2, 4, 8, 16] {
            let cs = ConstraintSystem::<F>::new_ref();
            let input_var = input
                .iter()
                .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
                .collect::<Vec<_>>();
            let start = UInt16::<F>::new_witness(cs.clone(), || Ok(start_pos)).unwrap();
            let length = UInt16::<F>::new_witness(cs.clone(), || Ok(slice_len)).unwrap();

            let result = slice_grouped(&input_var, &start, &length, max_len, group_size).unwrap();
            assert!(cs.is_satisfied().unwrap());

            println!(
                "  Group size {}: {} constraints",
                group_size,
                cs.num_constraints()
            );

            // Verify correctness
            let result_values: Vec<u8> = result
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();

            // Expected values
            for i in 0..slice_len as usize {
                assert_eq!(
                    result_values[i],
                    input[start_pos as usize + i],
                    "Mismatch at position {} for group_size {}",
                    i,
                    group_size
                );
            }
        }
    }
}
