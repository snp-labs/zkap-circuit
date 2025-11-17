use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::utils::a_lt_b;

/// 자릿수 배열(FpVar)을 단일 숫자(FpVar)로 변환하는 제약 조건 함수
///
/// ## Arguments
/// * `cs`: 제약 조건 시스템에 대한 참조
/// * `digits`: 각 자릿수를 나타내는 FpVar의 슬라이스. 최대 길이에 맞게 0과 같은
///            padding 문자로 채워져 있어야 합니다.
/// * `len`: 실제 자릿수의 길이를 나타내는 UInt16 변수
///
/// ## Returns
/// 조합된 숫자를 나타내는 FpVar
pub fn non_prefix_digits_to_number_var<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    digits: &[FpVar<F>],
    len: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // 1. 최종 결과를 저장할 변수를 0으로 초기화합니다.
    let mut result = FpVar::<F>::zero();
    // 2. 곱셈에 사용할 상수 10을 FpVar로 만듭니다.
    let ten = FpVar::<F>::Constant(F::from(10u8));
    let ascii_zero_offset = FpVar::<F>::Constant(F::from(48u8));

    // 3. 최대 길이만큼 루프를 실행합니다.
    for (i, current_digit) in digits.iter().enumerate() {
        // 현재 인덱스(i)를 `UInt16` 상수로 변환합니다.
        let i_var = UInt16::<F>::constant(i as u16);

        // 현재 인덱스가 실제 길이(len)보다 작은지 검사합니다.
        // is_active는 i < len 이면 true, 아니면 false 값을 갖는 Boolean 변수입니다.
        let len_bits = len.to_bits_le()?;
        let i_bits = i_var.to_bits_le()?;
        let is_active = a_lt_b(&i_bits, &len_bits)? | Boolean::from(i_var.is_eq(len)?); // i가 len과 같을 때도 활성화

        let numeric_digit = current_digit - &ascii_zero_offset; // ASCII '0'을 빼서 실제 숫자 값으로 변환
        // Horner's method: result = result * 10 + current_digit
        let next_result = &result * &ten + numeric_digit;

        // is_active 값에 따라 결과를 선택적으로 갱신합니다.
        // is_active가 true이면 next_result를, false이면 기존 result를 선택합니다.
        result = is_active.select(&next_result, &result)?;
    }

    Ok(result)
}
pub fn decimal_bytes_to_fp<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    decimal_ascii_bytes: &[FpVar<F>],
    last_quote_index_var: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // --- 초기화 ---
    let mut accumulated_value = FpVar::<F>::zero();
    let mut has_seen_closing_quote = Boolean::<F>::FALSE;

    let quote_char = FpVar::<F>::Constant(F::from(b'"'));
    let ten = FpVar::Constant(F::from(10u8));

    // --- 1. 첫 번째 바이트가 `"`인지 강제 ---
    decimal_ascii_bytes[0].enforce_equal(&quote_char)?;

    // --- 2. 10진수 문자열 파싱 루프 ---
    for i in 1..decimal_ascii_bytes.len() {
        let current_byte = &decimal_ascii_bytes[i];
        let current_index_const = UInt16::constant(i as u16);

        // --- '현재 상태'에 대한 Boolean 조건 계산 ---
        let is_at_last_quote_pos = current_index_const.is_eq(last_quote_index_var)?;
        let is_before_closing_quote = !&has_seen_closing_quote;
        let should_accumulate = is_before_closing_quote & !&is_at_last_quote_pos;

        // --- 제약조건 강제 ---
        // 1. (ascii -> 10진수) 변환: current_byte가 숫자 문자라면, 실제 값은 (byte - '0') 입니다.
        let (numeric_value, validity) = decimal_byte_to_fp(cs.clone(), current_byte)?;
        (!&should_accumulate | validity).enforce_equal(&Boolean::TRUE)?;

        let potential_next_value = &accumulated_value * &ten + &numeric_value;

        accumulated_value = should_accumulate.select(&potential_next_value, &accumulated_value)?;

        // 2. 닫는 따옴표 위치에는 반드시 `"` 문자가 와야 함
        let current_byte_is_quote = current_byte.is_eq(&quote_char)?;
        (!&is_at_last_quote_pos | current_byte_is_quote).enforce_equal(&Boolean::TRUE)?;

        has_seen_closing_quote = has_seen_closing_quote | is_at_last_quote_pos;
    }

    // --- 최종 확인 ---
    has_seen_closing_quote.enforce_equal(&Boolean::TRUE)?;

    Ok(accumulated_value)
}

pub fn hex_bytes_to_fp<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    hex_bytes: &[FpVar<F>],
    last_quote_index_var: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // Debug 트레잇 추가

    let hex_bytes_len = hex_bytes.len();
    if hex_bytes_len < 4 {
        eprintln!("경고: hex_bytes 길이가 4 미만입니다 ({}).", hex_bytes_len);
        return Ok(FpVar::<F>::zero());
    }

    // --- 회로 내에서 사용할 상수 정의 ---
    let quote_char = FpVar::<F>::Constant(F::from(b'"'));
    let zero_char = FpVar::<F>::Constant(F::from(b'0')); // 패딩 확인용으로도 사용 가능
    let x_char = FpVar::<F>::Constant(F::from(b'x'));
    let sixteen = FpVar::Constant(F::from(16u8));

    // --- 1. 고정 접두사 '"' '0' 'x' 강제 ---
    quote_char.enforce_equal(&hex_bytes[0])?;
    zero_char.enforce_equal(&hex_bytes[1])?;
    x_char.enforce_equal(&hex_bytes[2])?;

    // --- 루프에서 사용할 변수 초기화 ---
    let mut accumulated_value = FpVar::<F>::zero(); // 최종 숫자 값 누적
    // 이 플래그는 루프 시작 시, *이전 반복까지* 닫는 따옴표를 만났었는지를 나타냅니다.
    let mut found_quote_at_or_before_prev_index = Boolean::FALSE;

    // --- 2. 모든 가능한 위치 순회 (인덱스 3부터 배열 끝까지) ---
    for i in 3..hex_bytes_len {
        let current_index_const = UInt16::constant(i as u16);

        // --- Boolean 조건 계산 (현재 인덱스 `i` 기준) ---
        // a) 현재 인덱스 `i`가 `last_quote_index_var`와 같은가?
        let is_last_quote_pos = current_index_const.is_eq(last_quote_index_var)?;
        // b) 현재 바이트가 `"` 문자인가?
        let current_byte = &hex_bytes[i];
        let is_quote = current_byte.is_eq(&quote_char)?;

        // --- 5. 다음 반복을 위해 상태 플래그 업데이트 ---
        // 현재 인덱스 `i`에서 닫는 따옴표를 찾았는지 여부를 or 연산으로 누적합니다.
        // 이 값은 다음 반복(i+1)에서 `is_before_last_quote`를 계산하는 데 사용됩니다.
        // **주의: 반드시 is_before_last_quote 계산 이후, 그리고 루프 종료 전에 업데이트되어야 합니다.**
        found_quote_at_or_before_prev_index =
            found_quote_at_or_before_prev_index | &is_last_quote_pos;

        // --- 현재 인덱스 'i'가 닫는 따옴표 *앞*에 있는지 결정 ---
        // 이는 이전 반복까지 닫는 따옴표를 만나지 않았는지(`found_quote_at_or_before_prev_index`가 FALSE인지)와 동일합니다.
        let is_before_last_quote = !&found_quote_at_or_before_prev_index;

        // --- 3. 닫는 따옴표 위치 제약 조건 강제 ---
        // "만약 현재 인덱스 `i`가 `last_quote_index_var`와 같다면, 현재 바이트는 반드시 `"` 문자여야 한다."
        let not_is_last_quote_pos = !&is_last_quote_pos;
        let quote_requirement = not_is_last_quote_pos | is_quote;
        quote_requirement.enforce_equal(&Boolean::TRUE)?;

        // --- 4. 값 누적 및 16진수 유효성 조건부 강제 ---
        // a) 현재 바이트를 16진수 값으로 변환 시도하고, 유효성 플래그를 얻습니다.
        let (value, validity) = hex_to_fp_with_validation(cs.clone(), current_byte)?;

        // b) 조건부 유효성 강제:
        let validity_requirement = &is_last_quote_pos | validity;

        validity_requirement.enforce_equal(&Boolean::TRUE)?;

        // c) 조건부 값 누적:
        //    `is_before_last_quote`가 참일 경우에만 값을 누적합니다.
        let potential_next_value = &accumulated_value * &sixteen + &value;
        accumulated_value =
            is_before_last_quote.select(&potential_next_value, &accumulated_value)?;

        // --- 6. (선택 사항) 패딩이 '0'인지 강제 ---
        // 만약 닫는 따옴표 뒤의 모든 패딩 문자가 반드시 '0'이어야 한다는 요구사항이 있다면,
        // 여기에 추가적인 제약 조건을 넣을 수 있습니다.
        // 예시:
        // 현재 위치가 패딩 영역인지 계산 (마지막 따옴표 위치도 아니고, 그 이전도 아닌 경우)
        let is_padding_pos = &found_quote_at_or_before_prev_index & !is_last_quote_pos; // 따옴표 위치도 아니고 그 앞도 아님
        // 현재 바이트가 '0' 문자인지 확인
        let is_zero_char_byte = current_byte.is_eq(&zero_char)?;
        // "만약 패딩 위치라면, 반드시 '0' 문자여야 한다" 를 강제
        // 논리: is_padding_pos => is_zero_char_byte (동치: (NOT is_padding_pos) OR is_zero_char_byte == TRUE)
        let not_is_padding_pos = !is_padding_pos;
        let padding_requirement = not_is_padding_pos | is_zero_char_byte;
        padding_requirement.enforce_equal(&Boolean::TRUE)?;
    } // --- 루프 종료 ---

    // --- 6. 최종 확인 ---
    // 루프 종료 후, `found_quote_at_or_before_prev_index`는 최종적으로 true여야 합니다.
    // 이는 `last_quote_index_var`가 유효한 범위 내에 있었고 해당 위치에서 닫는 따옴표 검사가
    // (성공적으로) 수행되었음을 의미합니다.
    found_quote_at_or_before_prev_index.enforce_equal(&Boolean::TRUE)?;

    // --- 7. 결과 반환 ---
    Ok(accumulated_value)
}

fn decimal_byte_to_fp<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let decimal_table = decimal_table::<F>();
    let mut sum = FpVar::<F>::zero(); // 초기값은 0

    for decimal_char in decimal_table.iter() {
        // 현재 바이트가 decimal_char와 같은지 확인
        let is_equal = byte.is_eq(decimal_char)?;

        // is_equal이 true이면, sum에 1 누적
        let value_to_add = is_equal.select(&FpVar::<F>::Constant(F::one()), &FpVar::<F>::zero())?;

        // sum에 누적
        sum += &value_to_add;
    }

    let validity = sum.is_eq(&FpVar::<F>::Constant(F::from(1u8)))?; // sum이 1이면 유효한 10진수 문자

    let result = byte - &FpVar::<F>::Constant(F::from(b'0')); // 10진수 값 계산

    Ok((result, validity)) // 반환: 10진수 값과 유효성 플래그
}

/// 단일 바이트 변수(FpVar)를 해당하는 16진수 숫자 값 (0-15 범위의 FpVar)으로 변환합니다.
/// 변환된 값과 함께, 입력 바이트가 유효한 16진수 문자('0'-'9', 'a'-'f')였는지를 나타내는 Boolean 값을 반환합니다.
/// 중요: 유효하지 않은 입력 바이트에 대해 증명 생성을 실패시키지 않고, 단지 유효성 플래그(is_valid_hex)를 false로 설정하여 반환합니다.
fn hex_to_fp_with_validation<F: PrimeField>(
    _cs: ConstraintSystemRef<F>, // 현재 구현에서는 CS가 직접 필요하지 않을 수 있지만, 일관성을 위해 유지
    // table: &[FpVar<F>],          // hex_table()로 생성된 16진수 상수 테이블
    byte: &FpVar<F>, // 변환 및 검사할 입력 바이트 변수
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let mut result = FpVar::<F>::zero(); // 결과 숫자 값 (0-15)을 누적할 변수
    let mut is_valid_hex = Boolean::<F>::FALSE; // 유효성 플래그, 기본값은 false (유효하지 않음)
    let table = hex_table::<F>();
    let len = table.len();

    // 테이블은 '0'부터 'f'까지 총 16개의 문자를 포함해야 함
    assert_eq!(len, 16, "Hex table must have length 16");

    // 테이블의 모든 문자와 입력 바이트를 비교
    for i in 0..len {
        // is_equal: 입력 바이트가 테이블의 i번째 문자와 같은지 여부를 나타내는 Boolean<F> 변수
        let is_equal = byte.is_eq(&table[i])?;

        // is_equal이 true이면 i (0-15)를 결과에 더함.
        // Boolean::from()은 true일 때 FpVar(1), false일 때 FpVar(0)으로 변환됨.
        let value_to_add =
            FpVar::<F>::from(is_equal.clone()) * FpVar::<F>::Constant(F::from(i as u64));
        result += &value_to_add;

        // 유효성 플래그 업데이트: 만약 테이블 내 어떤 문자와라도 일치했다면, is_valid_hex는 true가 됨.
        // or 연산은 한 번이라도 true가 되면 그 이후 계속 true를 유지함.
        is_valid_hex = is_valid_hex | is_equal;
    }

    // result: 유효한 16진수 문자였다면 해당하는 숫자 값(0-15), 아니면 0.
    // is_valid_hex: 입력 바이트가 테이블 내 문자와 일치했으면 true, 아니면 false.
    Ok((result, is_valid_hex))
}

fn decimal_table<F: PrimeField>() -> Vec<FpVar<F>> {
    let decs = b"0123456789";
    let dec_table: Vec<FpVar<F>> = decs
        .iter()
        .map(|byte| FpVar::<F>::Constant(F::from(*byte)))
        .collect();
    dec_table
}

fn hex_table<F: PrimeField>() -> Vec<FpVar<F>> {
    let hexs = b"0123456789abcdef";
    let hex_table: Vec<FpVar<F>> = hexs
        .iter()
        .map(|byte| FpVar::<F>::Constant(F::from(*byte)))
        .collect();
    hex_table
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, uint16::UInt16};
    use ark_relations::r1cs::ConstraintSystem;

    use crate::utils::hex_bytes_to_fp;
    use std::str::FromStr;

    type F = ark_bn254::Fr;

    #[test]
    fn test_hex_byes_to_fp() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = r#""0x0e758262e33fe28c37e8612505582e3c341481cbc106e47a617e9471cf5732cc""#;
        let mut input_bytes = input.as_bytes().to_vec();
        let expected = F::from_str(
            "6540000879776827511546239914827296250681122647808546265151524760879082451660",
        )
        .unwrap();

        let last_quote_idx = 67;
        input_bytes.resize(200, b'0');
        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let expected_var = FpVar::<F>::new_witness(cs.clone(), || Ok(expected)).unwrap();

        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = hex_bytes_to_fp(cs.clone(), &input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        result.enforce_equal(&expected_var).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }
}
