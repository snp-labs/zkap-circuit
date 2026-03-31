use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// JWT nonce 필드의 16진수 문자열을 필드 원소로 변환합니다.
///
/// # 형식
/// - 입력: `"0x[0-9a-f]+"` (예: "0xabcd1234...")
/// - 최대 256비트 값 지원
/// - BN254 필드 사용 시 자동으로 modular 연산 적용 (254비트 넘으면)
///
/// # 제약 조건
/// 1. 첫 3바이트는 반드시 `"0x` (고정)
/// 2. `last_quote_index`까지의 모든 바이트는 유효한 16진수 문자
/// 3. `last_quote_index` 위치는 반드시 `"`
/// 4. 16진수 문자열 길이는 1-64자 (4비트~256비트)
///
/// # Arguments
/// * `hex_bytes` - JWT nonce 값의 바이트 배열 (패딩 포함 가능)
/// * `last_quote_index` - 닫는 따옴표 `"` 위치 (witness)
///
/// # Returns
/// * 변환된 필드 원소 값
///
/// # Example
/// ```text
/// Input:  ["0x1234...abcd"000000...]  (패딩된 배열)
///          ^             ^
///          |             last_quote_index
///          시작
/// Output: Field element representing 0x1234...abcd
/// ```
pub fn jwt_nonce_hex_to_field<F: PrimeField>(
    hex_bytes: &[FpVar<F>],
    last_quote_index: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let hex_bytes_len = hex_bytes.len();

    // 최소 길이 검증: "0x0" (5바이트)
    if hex_bytes_len < 5 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // --- 상수 정의 ---
    let quote_char = FpVar::<F>::Constant(F::from(b'"'));
    let zero_char = FpVar::<F>::Constant(F::from(b'0'));
    let x_char = FpVar::<F>::Constant(F::from(b'x'));
    let sixteen = FpVar::Constant(F::from(16u8));

    // --- 1. 고정 접두사 검증: "0x ---
    crate::enforce_eq_internal!("nonce_prefix_quote", quote_char, hex_bytes[0])?;
    crate::enforce_eq_internal!("nonce_prefix_zero", zero_char, hex_bytes[1])?;
    crate::enforce_eq_internal!("nonce_prefix_x", x_char, hex_bytes[2])?;

    // --- 2. 누적 변수 초기화 ---
    let mut accumulated_value = FpVar::<F>::zero();
    let mut found_closing_quote = Boolean::FALSE;
    let mut hex_digit_count = FpVar::<F>::zero(); // 16진수 자릿수 카운트

    // --- 3. 16진수 파싱 루프 (인덱스 3부터) ---
    for i in 3..hex_bytes_len {
        let current_index = UInt16::constant(i as u16);
        let current_byte = &hex_bytes[i];

        // 현재 위치가 닫는 따옴표 위치인가?
        let is_closing_quote_pos = current_index.is_eq(last_quote_index)?;

        // 현재 바이트가 따옴표인가?
        let is_quote_char = current_byte.is_eq(&quote_char)?;

        // 닫는 따옴표를 아직 못 봤는가?
        let is_before_closing_quote = !&found_closing_quote;

        // --- 3.1. 닫는 따옴표 위치 검증 ---
        // "닫는 따옴표 위치라면 반드시 " 문자여야 함"
        let quote_pos_requirement = !&is_closing_quote_pos | &is_quote_char;
        crate::enforce_true_internal!("nonce_quote_pos", quote_pos_requirement)?;

        // --- 3.2. 16진수 파싱 (닫는 따옴표 이전에만) ---
        let should_parse = &is_before_closing_quote & !&is_closing_quote_pos;

        // 16진수 변환
        let (hex_value, is_valid_hex) = hex_char_to_value(current_byte)?;

        // 유효성 검증: "파싱해야 한다면 반드시 유효한 16진수여야 함"
        let validity_requirement = !&should_parse | &is_valid_hex;
        crate::enforce_true_internal!("nonce_hex_valid", validity_requirement)?;

        // 값 누적 (should_parse가 true일 때만)
        let potential_next_value = &accumulated_value * &sixteen + &hex_value;
        accumulated_value = should_parse.select(&potential_next_value, &accumulated_value)?;

        // 16진수 자릿수 카운트
        let should_parse_fp = FpVar::from(should_parse.clone());
        hex_digit_count += &should_parse_fp;

        // --- 3.3. 상태 업데이트 ---
        found_closing_quote = found_closing_quote | is_closing_quote_pos;
    }

    // --- 4. 최종 검증 ---
    // 4.1. 닫는 따옴표를 반드시 찾았어야 함
    crate::enforce_true_internal!("nonce_closing_quote_found", found_closing_quote)?;

    // 4.2. 16진수 자릿수는 1~64자여야 함 (4비트~256비트)
    // 최소 1자
    let zero = FpVar::<F>::zero();
    let digit_count_ge_1 = hex_digit_count.is_neq(&zero)?;
    crate::enforce_true_internal!("nonce_digit_count_ge_1", digit_count_ge_1)?;

    // [ZKAPCIR-004] 최대 64자 (256비트) - 회로 내에서 실제로 enforce
    // 기존 코드는 비교 결과를 제약하지 않아 65자 이상도 허용되었음.
    let max_hex_digits = FpVar::<F>::Constant(F::from(64u64));
    let digit_count_bits = hex_digit_count.to_bits_le()?;
    let max_bits = max_hex_digits.to_bits_le()?;
    let digit_le_max = crate::comparison_v2::is_less_or_equal(&digit_count_bits, &max_bits)?;
    crate::enforce_true_internal!("nonce_digit_le_max", digit_le_max)?;

    Ok(accumulated_value)
}

/// 16진수 문자 하나를 0-15 값으로 변환하고 유효성 검증
///
/// # Arguments
/// * `byte` - ASCII 바이트 ('0'-'9', 'a'-'f', 'A'-'F')
///
/// # Returns
/// * `(value, is_valid)` - 변환된 값(0-15)과 유효성 플래그
///
/// # 제약 조건
/// - byte를 8비트로 한 번 분해 후 비트 패턴으로 3개 범위를 효율적으로 검사
/// - '0'-'9': 0x30..=0x39 → 상위 4비트 == 0011, 하위 4비트 <= 9
/// - 'A'-'F': 0x41..=0x46 → 상위 4비트 == 0100, 하위 4비트 <= 5  (단, bit6=0, bit7=0)
/// - 'a'-'f': 0x61..=0x66 → 상위 4비트 == 0110, 하위 4비트 <= 5  (단, bit7=0)
///
/// # 건전성
/// - byte를 8비트 분해 + 재구성 enforce_equal로 byte in [0,255] 보장
/// - 상위 비트 패턴 검사는 Boolean 상수와의 XOR(무비용)로 구현
/// - 하위 비트 범위 검사는 4비트 is_less_or_equal로 구현
fn hex_char_to_value<F: PrimeField>(
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    // byte를 8비트 witness로 분해하고 재구성을 강제 (byte in [0, 255] 보장)
    let cs = byte.cs();
    let byte_val = byte.value().unwrap_or_default();
    let mut b: Vec<Boolean<F>> = Vec::with_capacity(8);
    for i in 0..8usize {
        let bit_val = byte_val.into_bigint().get_bit(i);
        let bit = if cs.is_none() {
            Boolean::constant(bit_val)
        } else {
            Boolean::new_witness(cs.clone(), || Ok(bit_val))?
        };
        b.push(bit);
    }
    // b[0]..b[7]: b[0]=LSB, b[7]=MSB

    // 재구성 강제: reconstructed == byte
    let mut reconstructed = FpVar::<F>::zero();
    let mut power = F::one();
    for bit in &b {
        let bit_fp = FpVar::from(bit.clone());
        reconstructed += bit_fp * FpVar::Constant(power);
        power.double_in_place();
    }
    reconstructed.enforce_equal(byte)?;

    // 하위 4비트 (nibble): b[0..4]
    // 상위 4비트: b[4..8]
    let lo_nibble = &b[0..4]; // bits 0-3
    let hi_nibble = &b[4..8]; // bits 4-7

    // 상위 4비트 패턴 검사 (모두 상수 비트와 XOR → 비용 거의 0)
    // '0'-'9': 0x3? → hi = 0011 (b4=1,b5=1,b6=0,b7=0)
    // 'A'-'F': 0x4? → hi = 0100 (b4=0,b5=0,b6=1,b7=0)  + lower nibble check
    // 'a'-'f': 0x6? → hi = 0110 (b4=0,b5=1,b6=1,b7=0)  + lower nibble check
    //
    // hi_nibble[0]=b4, hi_nibble[1]=b5, hi_nibble[2]=b6, hi_nibble[3]=b7

    // '0'-'9': b7=0, b6=0, b5=1, b4=1
    let hi_is_3 = {
        let b4_eq_1 = hi_nibble[0].clone(); // b4==1
        let b5_eq_1 = hi_nibble[1].clone(); // b5==1
        let b6_eq_0 = !&hi_nibble[2];       // b6==0
        let b7_eq_0 = !&hi_nibble[3];       // b7==0
        &(&b4_eq_1 & &b5_eq_1) & &(&b6_eq_0 & &b7_eq_0)
    };

    // 'A'-'F': b7=0, b6=1, b5=0, b4=0 (0x4?)
    let hi_is_4 = {
        let b4_eq_0 = !&hi_nibble[0];
        let b5_eq_0 = !&hi_nibble[1];
        let b6_eq_1 = hi_nibble[2].clone();
        let b7_eq_0 = !&hi_nibble[3];
        &(&b4_eq_0 & &b5_eq_0) & &(&b6_eq_1 & &b7_eq_0)
    };

    // 'a'-'f': b7=0, b6=1, b5=1, b4=0 (0x6?)
    let hi_is_6 = {
        let b4_eq_0 = !&hi_nibble[0];
        let b5_eq_1 = hi_nibble[1].clone();
        let b6_eq_1 = hi_nibble[2].clone();
        let b7_eq_0 = !&hi_nibble[3];
        &(&b4_eq_0 & &b5_eq_1) & &(&b6_eq_1 & &b7_eq_0)
    };

    // 하위 nibble 범위 검사
    // '0'-'9': lo_nibble <= 9 (0x9 = 1001)
    // 'A'-'F': lo_nibble <= 5 (0x5 = 0101) AND lo_nibble >= 1 (0x41='A', lo=1)
    // 'a'-'f': lo_nibble <= 5 AND lo_nibble >= 1 (0x61='a', lo=1)
    //
    // Note: 0x40='@' (lo=0), 0x60='`' (lo=0) 은 유효하지 않으므로 lo >= 1 검사 필요
    let nine_bits: Vec<Boolean<F>> = vec![
        Boolean::constant(true),  // bit0: 1
        Boolean::constant(false), // bit1: 0
        Boolean::constant(false), // bit2: 0
        Boolean::constant(true),  // bit3: 1
    ]; // 9 = 0b1001
    let six_bits: Vec<Boolean<F>> = vec![
        Boolean::constant(false), // bit0: 0
        Boolean::constant(true),  // bit1: 1
        Boolean::constant(true),  // bit2: 1
        Boolean::constant(false), // bit3: 0
    ]; // 6 = 0b0110
    let one_bits: Vec<Boolean<F>> = vec![
        Boolean::constant(true),  // bit0: 1
        Boolean::constant(false), // bit1: 0
        Boolean::constant(false), // bit2: 0
        Boolean::constant(false), // bit3: 0
    ]; // 1 = 0b0001

    let lo_le_9 = crate::comparison::is_less_or_equal(lo_nibble, &nine_bits)?;
    let lo_le_6 = crate::comparison::is_less_or_equal(lo_nibble, &six_bits)?;
    let lo_ge_1 = crate::comparison::is_less_or_equal(&one_bits, lo_nibble)?;

    // 범위 매칭
    let is_digit = &hi_is_3 & &lo_le_9;            // '0'-'9'
    let is_upper = &hi_is_4 & &(&lo_ge_1 & &lo_le_6); // 'A'-'F'
    let is_lower = &hi_is_6 & &(&lo_ge_1 & &lo_le_6); // 'a'-'f'

    // 유효성 플래그
    let is_valid = &is_digit | &(&is_upper | &is_lower);

    // hex 값 계산
    // digit_value = lo_nibble 값 (0-9) = byte - 0x30
    // upper_value = lo_nibble 값 - 1 + 10 = lo_nibble + 9 = byte - 0x41 + 10
    // lower_value = lo_nibble 값 - 1 + 10 = byte - 0x61 + 10
    let ten = FpVar::Constant(F::from(10u64));
    let digit_value = byte - FpVar::Constant(F::from(48u64)); // 0-9
    let upper_value = byte - FpVar::Constant(F::from(55u64)); // 'A'=65 → 65-55=10, 'F'=70 → 70-55=15
    let lower_value = byte - FpVar::Constant(F::from(87u64)); // 'a'=97 → 97-87=10, 'f'=102 → 102-87=15

    // lo_nibble >= 1이고 hi 패턴이 맞으면 upper/lower 값이 10-15 범위임
    // upper_value = byte - 55 = (0x40 + lo) - 55 = lo + 9, lo in [1,5] → [10,14] ✓
    // lower_value = byte - 87 = (0x60 + lo) - 87 = lo + 9, lo in [1,5] → [10,14] ✓
    // Wait: 'F'=70 → 70-55=15, 'f'=102 → 102-87=15 ✓

    // 조건부 선택: is_digit → digit값, is_upper → upper값, else → lower값
    let value_if_upper_or_lower = is_upper.select(&upper_value, &lower_value)?;
    let result = is_digit.select(&digit_value, &value_if_upper_or_lower)?;

    // 미사용 변수 제거
    let _ = ten;

    Ok((result, is_valid))
}

/// JWT 필드의 10진수 문자열을 필드 원소로 변환합니다.
///
/// # 형식
/// - 입력: `"[0-9]+"` (예: "1234567890")
/// - 최대 값은 필드 크기에 의해 제한
///
/// # 제약 조건
/// 1. 첫 바이트는 반드시 `"`
/// 2. `last_quote_index`까지의 모든 바이트는 유효한 10진수 문자
/// 3. `last_quote_index` 위치는 반드시 `"`
/// 4. 최소 1자리 이상
///
/// # Arguments
/// * `cs` - 제약 조건 시스템 참조
/// * `decimal_bytes` - 10진수 문자열 바이트 배열
/// * `last_quote_index` - 닫는 따옴표 위치
///
/// # Returns
/// * 변환된 필드 원소 값
pub fn jwt_decimal_to_field<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    decimal_bytes: &[FpVar<F>],
    last_quote_index: &UInt16<F>,
) -> Result<FpVar<F>, SynthesisError> {
    let bytes_len = decimal_bytes.len();

    if bytes_len < 2 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // --- 상수 정의 ---
    let quote_char = FpVar::<F>::Constant(F::from(b'"'));
    let ten = FpVar::Constant(F::from(10u8));

    // --- 1. 첫 바이트는 따옴표 ---
    quote_char.enforce_equal(&decimal_bytes[0])?;

    // --- 2. 누적 변수 초기화 ---
    let mut accumulated_value = FpVar::<F>::zero();
    let mut found_closing_quote = Boolean::FALSE;
    let mut digit_count = FpVar::<F>::zero();

    // --- 3. 10진수 파싱 루프 ---
    for i in 1..bytes_len {
        let current_index = UInt16::constant(i as u16);
        let current_byte = &decimal_bytes[i];

        let is_closing_quote_pos = current_index.is_eq(last_quote_index)?;
        let is_quote_char = current_byte.is_eq(&quote_char)?;
        let is_before_closing_quote = !&found_closing_quote;

        // --- 3.1. 닫는 따옴표 검증 ---
        let quote_pos_requirement = !&is_closing_quote_pos | &is_quote_char;
        quote_pos_requirement.enforce_equal(&Boolean::TRUE)?;

        // --- 3.2. 10진수 파싱 ---
        let should_parse = &is_before_closing_quote & !&is_closing_quote_pos;

        let (decimal_value, is_valid_decimal) = decimal_char_to_value(cs.clone(), current_byte)?;

        let validity_requirement = !&should_parse | &is_valid_decimal;
        validity_requirement.enforce_equal(&Boolean::TRUE)?;

        let potential_next_value = &accumulated_value * &ten + &decimal_value;
        accumulated_value = should_parse.select(&potential_next_value, &accumulated_value)?;

        let should_parse_fp = FpVar::from(should_parse.clone());
        digit_count += &should_parse_fp;

        found_closing_quote = found_closing_quote | is_closing_quote_pos;
    }

    // --- 4. 최종 검증 ---
    found_closing_quote.enforce_equal(&Boolean::TRUE)?;

    // 최소 1자리
    let zero = FpVar::<F>::zero();
    let digit_count_ge_1 = digit_count.is_neq(&zero)?;
    digit_count_ge_1.enforce_equal(&Boolean::TRUE)?;

    Ok(accumulated_value)
}

/// 10진수 문자 하나를 0-9 값으로 변환하고 유효성 검증
fn decimal_char_to_value<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let mut result = FpVar::<F>::zero();
    let mut is_valid = Boolean::<F>::FALSE;

    let decimal_chars = b"0123456789";

    for (i, &dec_char) in decimal_chars.iter().enumerate() {
        let char_const = FpVar::<F>::Constant(F::from(dec_char));
        let is_equal = byte.is_eq(&char_const)?;

        let value_to_add = FpVar::from(is_equal.clone()) * FpVar::<F>::Constant(F::from(i as u64));
        result += &value_to_add;

        is_valid = is_valid | is_equal;
    }

    Ok((result, is_valid))
}

/// JWT exp 필드 등의 10진수 바이트 배열을 필드 원소로 변환합니다.
///
/// # 형식
/// - 입력: `[b'0'..=b'9', 0, 0, ...]` (패딩된 배열)
/// - 예: `[49, 50, 51, ...]` = `['1', '2', '3', ...]`
/// - 항상 정확히 10자리 숫자여야 함
/// - 10자리 이후는 0으로 패딩
///
/// # 제약 조건
/// 1. 처음 10개 바이트는 반드시 유효한 10진수 문자 (b'0'~b'9')
/// 2. 10자리 이후는 모두 0이어야 함
/// 3. 결과값은 0 ~ 9,999,999,999 범위
///
/// # Arguments
/// * `decimal_bytes` - 10진수 바이트 배열 (정확히 10자리 + 패딩)
///
/// # Returns
/// * 변환된 필드 원소 값
///
/// # Example
/// ```text
/// Input:  [49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 0, 0, ...]
///         ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ...]
/// Output: Field element 1234567890
/// ```
pub fn jwt_exp_to_field<F: PrimeField>(
    decimal_bytes: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    // 최소 길이 검증: 10자리 필요
    if decimal_bytes.len() < 10 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let ten = FpVar::Constant(F::from(10u8));
    let zero = FpVar::<F>::Constant(F::zero());

    let mut accumulated_value = FpVar::<F>::zero();

    // --- 1. 첫 10자리 파싱 및 검증 ---
    for i in 0..10 {
        let current_byte = &decimal_bytes[i];

        // 10진수 변환
        let (digit_value, is_valid_digit) = decimal_byte_to_digit(current_byte)?;

        // 유효성 검증: 반드시 유효한 10진수여야 함
        crate::enforce_true_internal!("exp_digit_valid", is_valid_digit)?;

        // 값 누적: accumulated_value = accumulated_value * 10 + digit_value
        accumulated_value = &accumulated_value * &ten + &digit_value;
    }

    // --- 2. 나머지는 모두 0 패딩 검증 ---
    for i in 10..decimal_bytes.len() {
        crate::enforce_eq_internal!("exp_padding_zero", decimal_bytes[i], zero)?;
    }

    Ok(accumulated_value)
}

/// 10진수 바이트 하나를 0-9 값으로 변환하고 유효성 검증
///
/// # Arguments
/// * `byte` - ASCII 바이트 (b'0'~b'9', 즉 48~57)
///
/// # Returns
/// * `(value, is_valid)` - 변환된 값(0-9)과 유효성 플래그
///
/// # 제약 조건
/// - 정확히 하나의 10진수 문자와 매칭되어야 함
/// - b'0'(48) ~ b'9'(57) 범위
fn decimal_byte_to_digit<F: PrimeField>(
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let mut result = FpVar::<F>::zero();
    let mut is_valid = Boolean::<F>::FALSE;

    // b'0' = 48, b'1' = 49, ..., b'9' = 57
    for digit in 0..10u8 {
        let byte_value = b'0' + digit; // 48 + digit
        let byte_const = FpVar::<F>::Constant(F::from(byte_value));
        let is_equal = byte.is_eq(&byte_const)?;

        // 값 누적 (digit 그 자체가 값)
        let value_to_add =
            FpVar::from(is_equal.clone()) * FpVar::<F>::Constant(F::from(digit as u64));
        result += &value_to_add;

        // 유효성 플래그 업데이트
        is_valid = is_valid | is_equal;
    }

    Ok((result, is_valid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use std::str::FromStr;

    type F = ark_bn254::Fr;

    #[test]
    fn test_jwt_nonce_hex_to_field_basic() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 테스트 입력: "0x1234"
        let input = b"\"0x1234\"";
        let mut input_bytes = input.to_vec();
        println!("Input bytes: {:?}", &input_bytes[..8]);
        println!(
            "Input string: {}",
            String::from_utf8_lossy(&input_bytes[..8])
        );
        input_bytes.resize(100, b'0'); // 패딩

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 7; // "0x1234" 의 닫는 따옴표 위치 (0-indexed)
        println!("Last quote index: {}", last_quote_idx);
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        if !cs.is_satisfied().unwrap() {
            println!("Constraints not satisfied!");
            println!("Number of constraints: {}", cs.num_constraints());
        }
        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(0x1234u64);
        assert_eq!(result.value().unwrap(), expected);

        println!("Basic test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_nonce_hex_to_field_256bit() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 64자리 16진수 (256비트)
        let hex_str = "0e758262e33fe28c37e8612505582e3c341481cbc106e47a617e9471cf5732cc";
        let input = format!("\"0x{}\"", hex_str);
        let mut input_bytes = input.as_bytes().to_vec();

        let expected = F::from_str(
            "6540000879776827511546239914827296250681122647808546265151524760879082451660",
        )
        .unwrap();

        let last_quote_idx = input_bytes.len() - 1;
        input_bytes.resize(200, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);

        println!("256-bit test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_nonce_hex_uppercase() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 대문자 포함 테스트
        let input = b"\"0xABCD\"";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 7; // "0xABCD" 의 닫는 따옴표 위치
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(0xABCDu64);
        assert_eq!(result.value().unwrap(), expected);

        println!("Uppercase test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_nonce_hex_with_padding() {
        let cs = ConstraintSystem::<F>::new_ref();
        // 64자리 16진수 (256비트)
        let hex_str = "0e758262e33fe28c37e8612505582e3c341481cbc106e47a617e9471cf5732cc";
        let input = format!("\"0x{}\"", hex_str);
        let mut input_bytes = input.as_bytes().to_vec();

        let expected = F::from_str(
            "6540000879776827511546239914827296250681122647808546265151524760879082451660",
        )
        .unwrap();

        let last_quote_idx = input_bytes.len() - 1; // 닫는 따옴표 위치
        input_bytes.resize(200, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.value().unwrap(), expected);

        println!("256-bit test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_decimal_to_field() {
        let cs = ConstraintSystem::<F>::new_ref();

        let input = b"\"12345\"";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 6; // "12345" 의 닫는 따옴표 위치
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let result = jwt_decimal_to_field(cs.clone(), &input_var, &last_quote_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(12345u64);
        assert_eq!(result.value().unwrap(), expected);

        println!("Decimal test - constraints: {}", cs.num_constraints());
    }

    #[test]
    #[should_panic]
    fn test_jwt_nonce_invalid_hex() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 잘못된 16진수 문자 포함
        let input = b"\"0x12G4\""; // 'G'는 유효하지 않음
        let mut input_bytes = input.to_vec();
        input_bytes.resize(100, b'0');

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let last_quote_idx = 8;
        let last_quote_var =
            UInt16::<F>::new_witness(cs.clone(), || Ok(last_quote_idx as u16)).unwrap();

        let _ = jwt_nonce_hex_to_field(&input_var, &last_quote_var).unwrap();

        // 유효하지 않은 입력이므로 제약 조건 불만족
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_jwt_exp_to_field_basic() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 테스트 입력: 1234567890 (10자리)
        let input = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'];
        let mut input_bytes = input.clone();
        input_bytes.resize(70, 0); // 0으로 패딩

        println!("Input bytes: {:?}", &input_bytes[..15]);
        println!("Expected: 1234567890");

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );

        let expected = F::from(1234567890u64);
        assert_eq!(result.value().unwrap(), expected);

        println!(
            "✓ Basic exp test (1234567890) - constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_jwt_exp_to_field_all_zeros() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 테스트 입력: 0000000000 (10자리 모두 0)
        let input = vec![b'0'; 10];
        let mut input_bytes = input.clone();
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(0u64);
        assert_eq!(result.value().unwrap(), expected);

        println!("✓ All zeros test - constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_jwt_exp_to_field_max_value() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 테스트 입력: 9999999999 (10자리 최대값)
        let input = vec![b'9'; 10];
        let mut input_bytes = input.clone();
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(9999999999u64);
        assert_eq!(result.value().unwrap(), expected);

        println!(
            "✓ Max value test (9999999999) - constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    fn test_jwt_exp_to_field_realistic_timestamp() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 실제 타임스탬프 예시: 1734000000 (2024년 12월경)
        let input = b"1734000000";
        let mut input_bytes = input.to_vec();
        input_bytes.resize(70, 0);

        println!("Input: {}", String::from_utf8_lossy(&input_bytes[..10]));

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let result = jwt_exp_to_field(&input_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let expected = F::from(1734000000u64);
        assert_eq!(result.value().unwrap(), expected);

        println!(
            "✓ Realistic timestamp test (1734000000) - constraints: {}",
            cs.num_constraints()
        );
    }

    #[test]
    #[should_panic(expected = "not satisfied")]
    fn test_jwt_exp_to_field_invalid_digit() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 잘못된 문자 포함: 123456789a (마지막 문자가 'a')
        let mut input_bytes = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a'];
        input_bytes.resize(70, 0);

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let _result = jwt_exp_to_field(&input_var).unwrap();

        // 유효하지 않은 입력이므로 제약 조건 불만족
        if !cs.is_satisfied().unwrap() {
            panic!("Constraints not satisfied - invalid digit detected");
        }
    }

    #[test]
    #[should_panic(expected = "not satisfied")]
    fn test_jwt_exp_to_field_non_zero_padding() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 10자리 이후에 0이 아닌 값
        let mut input_bytes = vec![b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0'];
        input_bytes.resize(70, 0);
        input_bytes[15] = 1; // 패딩 영역에 0이 아닌 값

        let input_var = input_bytes
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let _result = jwt_exp_to_field(&input_var).unwrap();

        // 패딩이 0이 아니므로 제약 조건 불만족
        if !cs.is_satisfied().unwrap() {
            panic!("Constraints not satisfied - non-zero padding detected");
        }
    }
}
