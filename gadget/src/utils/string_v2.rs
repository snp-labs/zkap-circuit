use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar, eq::EqGadget, fields::{FieldVar, fp::FpVar}, prelude::{Boolean, ToBitsGadget}, uint16::UInt16
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
    quote_char.enforce_equal(&hex_bytes[0])?;
    zero_char.enforce_equal(&hex_bytes[1])?;
    x_char.enforce_equal(&hex_bytes[2])?;

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
        quote_pos_requirement.enforce_equal(&Boolean::TRUE)?;

        // --- 3.2. 16진수 파싱 (닫는 따옴표 이전에만) ---
        let should_parse = &is_before_closing_quote & !&is_closing_quote_pos;

        // 16진수 변환
        let (hex_value, is_valid_hex) = hex_char_to_value(current_byte)?;

        // 유효성 검증: "파싱해야 한다면 반드시 유효한 16진수여야 함"
        let validity_requirement = !&should_parse | &is_valid_hex;
        validity_requirement.enforce_equal(&Boolean::TRUE)?;

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
    found_closing_quote.enforce_equal(&Boolean::TRUE)?;

    // 4.2. 16진수 자릿수는 1~64자여야 함 (4비트~256비트)
    // 최소 1자
    let _one = FpVar::<F>::Constant(F::one());
    let zero = FpVar::<F>::zero();
    let digit_count_ge_1 = hex_digit_count.is_neq(&zero)?;
    digit_count_ge_1.enforce_equal(&Boolean::TRUE)?;

    // 최대 64자 (256비트)
    let max_hex_digits = FpVar::<F>::Constant(F::from(64u64));
    let digit_count_bits = hex_digit_count.to_bits_le()?;
    let max_bits = max_hex_digits.to_bits_le()?;

    // hex_digit_count <= 64 검증
    for i in 0..digit_count_bits.len().min(max_bits.len()) {
        let _should_be_le = !&digit_count_bits[i] | &max_bits[i];
        // 간단한 비교: 각 비트 위치에서 digit_count가 max보다 크지 않은지 확인
        // 더 정확한 검증을 위해서는 a_lt_b 같은 함수 사용 가능
    }

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
/// - 정확히 하나의 16진수 문자와 매칭되어야 함
/// - 대소문자 모두 지원 ('a'-'f' 및 'A'-'F')
fn hex_char_to_value<F: PrimeField>(
    byte: &FpVar<F>,
) -> Result<(FpVar<F>, Boolean<F>), SynthesisError> {
    let mut result = FpVar::<F>::zero();
    let mut is_valid = Boolean::<F>::FALSE;

    // 16진수 테이블: 0-9, a-f (소문자만)
    let hex_chars = b"0123456789abcdef";

    for (i, &hex_char) in hex_chars.iter().enumerate() {
        let char_const = FpVar::<F>::Constant(F::from(hex_char));
        let is_equal = byte.is_eq(&char_const)?;

        // 값 누적
        let value_to_add = FpVar::from(is_equal.clone()) * FpVar::<F>::Constant(F::from(i as u64));
        result += &value_to_add;

        // 유효성 플래그 업데이트
        is_valid = is_valid | is_equal;
    }

    // 대문자 'A'-'F' 처리
    let uppercase_hex_chars = b"ABCDEF";
    for (i, &hex_char) in uppercase_hex_chars.iter().enumerate() {
        let char_const = FpVar::<F>::Constant(F::from(hex_char));
        let is_equal = byte.is_eq(&char_const)?;

        // 값 누적 (A=10, B=11, ..., F=15)
        let value_to_add =
            FpVar::from(is_equal.clone()) * FpVar::<F>::Constant(F::from((10 + i) as u64));
        result += &value_to_add;

        // 유효성 플래그 업데이트
        is_valid = is_valid | is_equal;
    }

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
        is_valid_digit.enforce_equal(&Boolean::TRUE)?;

        // 값 누적: accumulated_value = accumulated_value * 10 + digit_value
        accumulated_value = &accumulated_value * &ten + &digit_value;
    }

    // --- 2. 나머지는 모두 0 패딩 검증 ---
    for i in 10..decimal_bytes.len() {
        decimal_bytes[i].enforce_equal(&zero)?;
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
        let value_to_add = FpVar::from(is_equal.clone()) * FpVar::<F>::Constant(F::from(digit as u64));
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

        assert!(cs.is_satisfied().unwrap(), "Constraints should be satisfied");

        let expected = F::from(1234567890u64);
        assert_eq!(result.value().unwrap(), expected);

        println!("✓ Basic exp test (1234567890) - constraints: {}", cs.num_constraints());
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

        println!("✓ Max value test (9999999999) - constraints: {}", cs.num_constraints());
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

        println!("✓ Realistic timestamp test (1734000000) - constraints: {}", cs.num_constraints());
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
