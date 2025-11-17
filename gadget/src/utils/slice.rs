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

use crate::utils::{
    a_lt_b, divide_mod_power_of_2_circuit, lt_bit_vector, multi_mux, pack_byte_fps_to_fp,
    select_array_element, unpack_fp_to_byte_fps,
};

pub fn slice<F: PrimeField>(
    data: &[FpVar<F>], // FpVar<F> 하나 당 1byte를 나타냄
    start_var: &UInt16<F>,
    len_var: &UInt16<F>,
    max_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
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
    Boolean::enforce_smaller_or_equal_than_le(&start_var.to_bits_le()?, [(data.len() * 16) as u64])
        .unwrap();

    // 2. len_var <= max_len
    Boolean::enforce_smaller_or_equal_than_le(&len_var.to_bits_le()?, [max_len as u64]).unwrap();

    // 3. start_var + length_var <= input_len 강제
    // let end_exclusive_var = UInt16::<F>::addmany(&[start_var.clone(), len_var.clone()]).unwrap();
    let end_exclusive_var = start_var.wrapping_add(len_var);
    Boolean::enforce_smaller_or_equal_than_le(
        &end_exclusive_var.to_bits_le()?,
        [(data.len() * 16) as u64],
    )
    .unwrap();

    let grouped_out_len = 1 + ceil((max_len - 1) as u64, nums_per_group as u64);

    let (start_idx_by_p_var, start_idx_mod_p_var) =
        divide_mod_power_of_2_circuit(start_var, p).unwrap();

    let minus_one_u16 = UInt16::constant(u16::MAX);

    let (end_idx_by_p_var, _) = divide_mod_power_of_2_circuit(
        &UInt16::<F>::wrapping_add_many(&[start_var.clone(), len_var.clone(), minus_one_u16])?,
        // &UInt16::addmany([start_var.clone(), len_var.clone(), minus_one_u16].as_slice()).unwrap(),
        p,
    )
    .unwrap();

    let group_length_idx = Boolean::le_bits_to_fp(&end_idx_by_p_var.to_bits_le()?).unwrap()
        - Boolean::le_bits_to_fp(&start_idx_by_p_var.to_bits_le()?).unwrap()
        + F::one();

    let out_grouped = slice_in_binary_tree(
        data,
        &start_idx_by_p_var,
        &group_length_idx,
        grouped_out_len as usize,
    )
    .unwrap();

    let x = nums_per_group * grouped_out_len as usize;

    let out_final: Vec<FpVar<F>> = out_grouped
        .iter()
        .flat_map(|group| unpack_fp_to_byte_fps(group).unwrap())
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

    let start_idx_mod_p_var = Boolean::le_bits_to_fp(&start_idx_mod_p_var.to_bits_le()?).unwrap();
    let out_with_suffix = multi_mux(&out_options, &start_idx_mod_p_var).unwrap();
    let output = slice_from_start(
        &out_with_suffix,
        &Boolean::le_bits_to_fp(&len_var.to_bits_le()?).unwrap(),
        max_len,
        pad_char,
    )
    .unwrap();

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

fn slice_in_binary_tree<F: PrimeField>(
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

fn pad_input<F: PrimeField>(input: &[FpVar<F>]) -> Vec<FpVar<F>> {
    let mut input_padded = input.to_vec();
    let next_power_of_two = input.len().next_power_of_two();
    let zero = FpVar::<F>::zero();
    input_padded.resize(next_power_of_two, zero);
    input_padded
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{FieldVar, fp::FpVar},
    };
    use ark_relations::r1cs::ConstraintSystem;

    use crate::utils::slice_from_start;

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
}
