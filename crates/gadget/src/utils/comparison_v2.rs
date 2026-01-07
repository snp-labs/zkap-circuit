use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

/// A < B (Strictly Less)
pub fn is_less_than<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, _) = compare_bits_raw(a_bits, b_bits)?;
    Ok(less)
}

/// A <= B (Less or Equal)
pub fn is_less_or_equal<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, equal) = compare_bits_raw(a_bits, b_bits)?;
    // (A < B) OR (A == B)
    Ok(&less | &equal)
}

/// A > B (Greater Than)
pub fn is_greater_than<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, equal) = compare_bits_raw(a_bits, b_bits)?;
    // A > B 는 "NOT (A <= B)" 와 동일합니다.
    // 즉, !(less | equal) 혹은 (!less & !equal)
    let less_or_equal = &less | &equal;
    Ok(!less_or_equal)
}

/// A >= B (Greater or Equal)
pub fn is_greater_or_equal<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, _) = compare_bits_raw(a_bits, b_bits)?;
    // A >= B 는 "NOT (A < B)" 와 동일합니다.
    Ok(!less)
}

/// 비트 단위 비교를 수행하여 (is_less, is_equal) 튜플을 반환합니다.
///
/// * 입력: Little-Endian으로 구성된 Boolean 벡터 (예: to_bits_le()의 결과)
/// * 출력: (a < b, a == b)
pub fn compare_bits_raw<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<(Boolean<F>, Boolean<F>), SynthesisError> {
    // 1. 길이 검증 (필수)
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "Bit lengths must be equal for comparison"
    );

    let mut less = Boolean::constant(false);
    let mut equal = Boolean::constant(true);

    // 2. MSB(최상위 비트)부터 LSB(최하위 비트) 순으로 순회
    // arkworks의 to_bits_le는 [LSB, ..., MSB] 순서이므로 rev()를 사용합니다.
    for (a_bit, b_bit) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        // --- Step A: 현재 비트에서 A < B 인지 판별 ---
        // 조건: (상위 비트들이 모두 같음) AND (A=0, B=1)
        // 로직: equal & (!A & B)
        let a_is_zero = !a_bit;
        let a_is_zero_b_is_one = &a_is_zero & b_bit;
        let strict_less_at_here = &equal & &a_is_zero_b_is_one;

        // 상태 누적: 기존에 이미 작았거나(less) OR 이번 비트에서 작음이 확정됨
        less = &less | &strict_less_at_here;

        // --- Step B: 현재 비트까지 A == B 인지 판별 ---
        // 조건: (상위 비트들이 모두 같음) AND (A == B)
        // 로직: equal & !(A ^ B)
        let bits_are_equal = !(a_bit ^ b_bit); // XNOR
        equal = &equal & &bits_are_equal;
    }

    Ok((less, equal))
}
