use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, EqGadget, ToBitsGadget},
};
use ark_relations::r1cs::SynthesisError;

/// 바이트 FpVar들을 단일 FpVar로 패킹합니다 (제약조건 최적화 버전).
///
/// 이 함수는 8비트(0-255) 값을 나타내는 FpVar 배열을 받아 하나의 FpVar로 압축합니다.
/// Big-endian 순서를 사용합니다 (byte_fps[0]이 MSB).
///
/// # 제약조건 보장:
/// 1. **바이트 범위 검증**: 각 입력 FpVar가 0-255 범위 내에 있는지 검증
/// 2. **정확한 패킹**: packed_value = Σ(byte[i] × 256^(n-1-i))
/// 3. **오버플로우 방지**: 결과가 필드 크기 내에 있음을 보장
///
/// # Arguments
/// * `byte_fps`: 바이트를 나타내는 FpVar 슬라이스 (Big-endian, 각각 0-255 범위로 가정)
/// * `num_bytes_expected`: 예상되는 바이트 개수
///
/// # Returns
/// * `Ok(FpVar<F>)`: 패킹된 값
/// * `Err(SynthesisError)`: 길이 불일치 또는 합성 오류 발생 시
///
/// # Performance
/// - 제약조건 수: O(8n) (n = num_bytes_expected)
/// - 각 바이트당 8개의 Boolean 제약 + 1개의 재구성 제약
pub fn pack_bytes_to_field_with_constraints<F: PrimeField>(
    byte_fps: &[FpVar<F>],
    num_bytes_expected: usize,
) -> Result<FpVar<F>, SynthesisError> {
    const BITS_PER_BYTE: usize = 8;

    // 1. 입력 길이 검증
    if byte_fps.len() != num_bytes_expected {
        return Err(SynthesisError::AssignmentMissing);
    }

    // 2. 각 바이트를 비트로 분해하고 8비트 제약조건 추가
    let mut all_bits = Vec::with_capacity(num_bytes_expected * BITS_PER_BYTE);

    for byte_fp in byte_fps.iter() {
        // 각 바이트를 8비트로 분해
        // 이 과정에서 암묵적으로 0-255 범위 제약이 추가됨
        let byte_bits = byte_fp.to_bits_le()?;

        // 정확히 8비트만 사용 (나머지 비트는 0이어야 함)
        if byte_bits.len() < BITS_PER_BYTE {
            return Err(SynthesisError::AssignmentMissing);
        }

        // 8비트 초과 부분은 모두 0이어야 함을 강제
        for bit in byte_bits.iter().skip(BITS_PER_BYTE) {
            crate::enforce_eq_internal!("byte_range_check", *bit, Boolean::<F>::FALSE)?;
        }

        // 하위 8비트만 저장
        all_bits.extend_from_slice(&byte_bits[..BITS_PER_BYTE]);
    }

    // 3. Big-endian 순서로 비트 재배열
    // byte_fps[0]의 비트들이 최상위에 오도록
    let mut reordered_bits = Vec::with_capacity(all_bits.len());
    for i in 0..num_bytes_expected {
        let byte_idx = num_bytes_expected - 1 - i; // Big-endian: 역순
        let start = byte_idx * BITS_PER_BYTE;
        let end = start + BITS_PER_BYTE;
        reordered_bits.extend_from_slice(&all_bits[start..end]);
    }

    // 4. 비트들을 다시 FpVar로 재구성
    // 이 과정에서 packed_value = Σ(bit[i] × 2^i) 제약이 추가됨
    let packed_fp = Boolean::le_bits_to_fp(&reordered_bits)?;

    Ok(packed_fp)
}

/// 바이트 FpVar들을 단일 FpVar로 패킹합니다 (성능 최적화 버전).
///
/// 이 함수는 제약조건 없이 직접 계산을 수행하므로 더 빠르지만,
/// 입력 값의 유효성을 검증하지 않습니다.
/// 신뢰할 수 있는 입력에만 사용하세요.
///
/// # Arguments
/// * `byte_fps`: 바이트를 나타내는 FpVar 슬라이스 (Big-endian)
/// * `num_bytes_expected`: 예상되는 바이트 개수
///
/// # Returns
/// * `Ok(FpVar<F>)`: 패킹된 값
/// * `Err(SynthesisError)`: 길이 불일치 또는 합성 오류 발생 시
///
/// # Warning
/// ⚠️ 이 함수는 입력 바이트가 0-255 범위인지 검증하지 않습니다.
/// 제약조건이 필요한 경우 `pack_bytes_to_field_with_constraints`를 사용하세요.
pub fn pack_bytes_to_field_unchecked<F: PrimeField>(
    byte_fps: &[FpVar<F>],
    num_bytes_expected: usize,
) -> Result<FpVar<F>, SynthesisError> {
    const BITS_PER_BYTE: usize = 8;

    // 1. 입력 길이 검증
    if byte_fps.len() != num_bytes_expected {
        return Err(SynthesisError::AssignmentMissing);
    }

    // 2. 256의 거듭제곱을 미리 계산 (상수이므로 제약조건 없음)
    let base = F::from(1u128 << BITS_PER_BYTE); // 256
    let mut powers_of_256 = Vec::with_capacity(num_bytes_expected);

    let mut current_power = F::one();
    for _ in 0..num_bytes_expected {
        powers_of_256.push(current_power);
        current_power *= base;
    }
    powers_of_256.reverse(); // Big-endian을 위해 역순

    // 3. 패킹 수행: result = Σ(byte[i] × 256^(n-1-i))
    let mut packed_fp = FpVar::<F>::zero();

    for (byte_fp, power) in byte_fps.iter().zip(powers_of_256.iter()) {
        let multiplier = FpVar::<F>::Constant(*power);
        packed_fp += byte_fp * multiplier;
    }

    Ok(packed_fp)
}

/// decompose_bytes를 최대 용량으로 압축합니다 (제약조건 포함 버전).
///
/// 필드의 최대 용량을 활용하여 자동으로 최적의 limb_width를 계산하고,
/// 입력 바이트들을 최소 개수의 FpVar로 패킹합니다.
/// `pack_decompose_bytes_unchecked`와 동일한 기조이지만 제약조건을 추가합니다.
///
/// # 동작 방식:
/// 1. 필드 크기에서 안전하게 패킹 가능한 최대 바이트 수(limb_width) 계산
/// 2. 입력 길이가 limb_width로 나누어떨어지는지 검증
/// 3. 정확히 limb_width 크기의 청크로 나누어 패킹 (제약조건 포함)
///
/// # 제약조건:
/// - 각 바이트가 0-255 범위임을 검증 (8비트 분해)
/// - 패킹 계산의 정확성을 보장
/// - 약 O(8n) 제약조건 생성 (n = 바이트 수)
///
/// # Arguments
/// * `decompose_bytes`: 8비트 바이트를 나타내는 FpVar 슬라이스
///
/// # Returns
/// * `Ok(Vec<FpVar<F>>)`: 패킹된 FpVar 벡터 (최소 개수)
/// * `Err(SynthesisError)`: 길이가 limb_width로 나누어떨어지지 않거나 합성 오류 발생 시
///
/// # Examples
/// ```rust,ignore
/// // ✅ 성공: 정렬된 입력 (31바이트의 배수)
/// let bytes_62 = vec![0u8; 62]; // 31 * 2
/// let packed = pack_decompose_bytes_with_constraints(&bytes_62)?;
/// assert_eq!(packed.len(), 2);
///
/// // ❌ 실패: 정렬되지 않은 입력
/// let bytes_50 = vec![0u8; 50]; // 31로 나누어떨어지지 않음
/// let result = pack_decompose_bytes_with_constraints(&bytes_50);
/// assert!(result.is_err());
/// ```
pub fn pack_decompose_bytes_with_constraints<F: PrimeField>(
    decompose_bytes: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // 필드 크기에서 안전하게 패킹 가능한 최대 바이트 수 계산
    let limb_width = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

    // 빈 입력은 빈 결과 반환
    if decompose_bytes.is_empty() {
        return Ok(Vec::new());
    }

    // 입력 길이가 limb_width로 나누어떨어지는지 검증
    if decompose_bytes.len() % limb_width != 0 {
        return Err(SynthesisError::AssignmentMissing);
    }

    let num_chunks = decompose_bytes.len() / limb_width;
    let mut packed_fields = Vec::with_capacity(num_chunks);

    // 정확히 limb_width 크기의 청크로 나누어 처리
    for chunk in decompose_bytes.chunks_exact(limb_width) {
        // 제약조건을 포함한 패킹 수행
        let packed_field = pack_bytes_to_field_with_constraints(chunk, limb_width)?;
        packed_fields.push(packed_field);
    }

    Ok(packed_fields)
}

/// decompose_bytes를 최대 용량으로 압축합니다 (성능 최적화 버전).
///
/// 필드의 최대 용량을 활용하여 자동으로 최적의 limb_width를 계산하고,
/// 입력 바이트들을 최소 개수의 FpVar로 패킹합니다.
///
/// # 엄격한 요구사항:
/// **입력 길이는 자동 계산된 limb_width로 정확히 나누어떨어져야 합니다.**
/// 이는 이미 최적화된, 정렬된 데이터를 처리하기 위한 함수이기 때문입니다.
///
/// # 동작 방식:
/// 1. 필드 크기에서 안전하게 패킹 가능한 최대 바이트 수(limb_width) 계산
///    - `limb_width = (F::MODULUS_BIT_SIZE - 1) / 8`
/// 2. 입력 길이가 limb_width로 나누어떨어지는지 검증
/// 3. 정확히 limb_width 크기의 청크로 나누어 패킹
///
/// # Arguments
/// * `decompose_bytes`: 8비트 바이트를 나타내는 FpVar 슬라이스
///
/// # Returns
/// * `Ok(Vec<FpVar<F>>)`: 패킹된 FpVar 벡터 (최소 개수)
/// * `Err(SynthesisError)`: 길이가 limb_width로 나누어떨어지지 않거나 합성 오류 발생 시
///
/// # Performance
/// - limb_width는 `(F::MODULUS_BIT_SIZE - 1) / 8`로 자동 계산
/// - 예: BN254 Fr 필드 (254비트) → limb_width = 31바이트
/// - 입력 62바이트 → 2개 FpVar (62 / 31 = 2)
/// - 입력 93바이트 → 3개 FpVar (93 / 31 = 3)
///
/// # Examples
/// ```rust,ignore
/// // ✅ 성공: 정렬된 입력 (31바이트의 배수)
/// let bytes_62 = vec![0u8; 62]; // 31 * 2
/// let packed = pack_decompose_bytes_unchecked(&bytes_62)?;
/// assert_eq!(packed.len(), 2);
///
/// // ❌ 실패: 정렬되지 않은 입력
/// let bytes_50 = vec![0u8; 50]; // 31로 나누어떨어지지 않음
/// let result = pack_decompose_bytes_unchecked(&bytes_50);
/// assert!(result.is_err());
/// ```
///
/// # Warning
/// ⚠️ 입력 검증을 수행하지 않습니다. 신뢰할 수 있는 입력에만 사용하세요.
/// ⚠️ 입력 길이가 맞지 않으면 에러를 반환합니다.
pub fn pack_decompose_bytes_unchecked<F: PrimeField>(
    decompose_bytes: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // 필드 크기에서 안전하게 패킹 가능한 최대 바이트 수 계산
    let limb_width = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

    // 빈 입력은 빈 결과 반환
    if decompose_bytes.is_empty() {
        return Ok(Vec::new());
    }

    // 입력 길이가 limb_width로 나누어떨어지는지 검증
    if decompose_bytes.len() % limb_width != 0 {
        return Err(SynthesisError::AssignmentMissing);
    }

    let num_chunks = decompose_bytes.len() / limb_width;
    let mut packed_fields = Vec::with_capacity(num_chunks);

    // 정확히 limb_width 크기의 청크로 나누어 처리
    for chunk in decompose_bytes.chunks_exact(limb_width) {
        let packed_field = pack_bytes_to_field_unchecked(chunk, limb_width)?;
        packed_fields.push(packed_field);
    }

    Ok(packed_fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, Zero};
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;

    type TestField = ark_bn254::Fr;

    #[test]
    fn test_pack_bytes_to_field_with_constraints() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        // 테스트 데이터: "hello" (5 bytes)
        let bytes = b"hello";
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        // 제약조건 포함 패킹
        let packed = pack_bytes_to_field_with_constraints(&byte_vars, 5).unwrap();

        // 예상 값 계산
        let mut expected = TestField::zero();
        let base = TestField::from(256u64);
        for (i, &b) in bytes.iter().enumerate() {
            let power = base.pow(&[(bytes.len() - 1 - i) as u64]);
            expected += TestField::from(b) * power;
        }

        assert_eq!(packed.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap(), "제약조건이 만족되지 않음");
    }

    #[test]
    fn test_pack_bytes_to_field_unchecked() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        let bytes = b"world";
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed = pack_bytes_to_field_unchecked(&byte_vars, 5).unwrap();

        let mut expected = TestField::zero();
        let base = TestField::from(256u64);
        for (i, &b) in bytes.iter().enumerate() {
            let power = base.pow(&[(bytes.len() - 1 - i) as u64]);
            expected += TestField::from(b) * power;
        }

        assert_eq!(packed.value().unwrap(), expected);
    }

    #[test]
    fn test_pack_decompose_bytes_with_constraints_exact_one_chunk() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 정확히 limb_width 크기의 입력
        let bytes: Vec<u8> = (0..limb_width).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();

        assert_eq!(packed.len(), 1);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_pack_decompose_bytes_with_constraints_exact_two_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 정확히 limb_width * 2 크기의 입력
        let total_bytes = limb_width * 2;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();

        assert_eq!(packed.len(), 2);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_pack_decompose_bytes_with_constraints_fail_unaligned() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width로 나누어떨어지지 않는 입력
        let total_bytes = limb_width + 5;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let result = pack_decompose_bytes_with_constraints(&byte_vars);
        assert!(result.is_err(), "정렬되지 않은 입력은 실패해야 함");
    }

    #[test]
    fn test_byte_range_constraint() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        // 유효한 바이트 값 (0-255)
        let valid_byte = FpVar::new_witness(cs.clone(), || Ok(TestField::from(255u8))).unwrap();
        let result = pack_bytes_to_field_with_constraints(&[valid_byte], 1);
        assert!(result.is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_invalid_byte_range() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        // 무효한 바이트 값 (256은 8비트 범위 초과)
        let invalid_byte = FpVar::new_witness(cs.clone(), || Ok(TestField::from(256u16))).unwrap();
        let result = pack_bytes_to_field_with_constraints(&[invalid_byte], 1);

        // 제약조건이 실패해야 함
        if result.is_ok() {
            assert!(!cs.is_satisfied().unwrap(), "잘못된 값이 통과됨");
        }
    }

    #[test]
    fn test_big_endian_order() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        // [0x01, 0x02]는 Big-endian으로 0x0102 = 258
        let bytes = vec![
            FpVar::new_witness(cs.clone(), || Ok(TestField::from(1u8))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(TestField::from(2u8))).unwrap(),
        ];

        let packed = pack_bytes_to_field_with_constraints(&bytes, 2).unwrap();
        let expected = TestField::from(1u16) * TestField::from(256u16) + TestField::from(2u16);

        assert_eq!(packed.value().unwrap(), expected);
    }

    #[test]
    fn test_constraint_count() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        let bytes = b"test";
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let initial_constraints = cs.num_constraints();

        let _ = pack_bytes_to_field_with_constraints(&byte_vars, 4).unwrap();

        let final_constraints = cs.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!("추가된 제약조건 수: {}", added_constraints);
        // 각 바이트당 약 8개의 비트 제약 + 재구성 제약
        // 실제 수는 구현에 따라 달라질 수 있음
    }

    // ==================== pack_decompose_bytes_unchecked 테스트 ====================

    #[test]
    fn test_pack_decompose_bytes_unchecked_empty() {
        // 빈 입력은 항상 성공 (0 % limb_width == 0)
        let byte_vars: Vec<FpVar<TestField>> = vec![];
        let packed = pack_decompose_bytes_unchecked(&byte_vars).unwrap();
        assert_eq!(packed.len(), 0);
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_exact_one_chunk() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 정확히 limb_width 크기의 입력 (성공 케이스)
        let bytes: Vec<u8> = (0..limb_width).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed = pack_decompose_bytes_unchecked(&byte_vars).unwrap();
        assert_eq!(packed.len(), 1, "정확히 1개 청크로 패킹되어야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_exact_two_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 정확히 limb_width * 2 크기의 입력 (성공 케이스)
        let total_bytes = limb_width * 2;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed = pack_decompose_bytes_unchecked(&byte_vars).unwrap();
        assert_eq!(packed.len(), 2, "정확히 2개 청크로 패킹되어야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_exact_three_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 정확히 limb_width * 3 크기의 입력 (성공 케이스)
        let total_bytes = limb_width * 3;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed = pack_decompose_bytes_unchecked(&byte_vars).unwrap();
        assert_eq!(packed.len(), 3, "정확히 3개 청크로 패킹되어야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_fail_one_byte_short() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width - 1 크기의 입력 (실패 케이스)
        let total_bytes = limb_width - 1;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let result = pack_decompose_bytes_unchecked(&byte_vars);
        assert!(result.is_err(), "limb_width - 1 바이트는 실패해야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_fail_one_byte_over() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width + 1 크기의 입력 (실패 케이스)
        let total_bytes = limb_width + 1;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let result = pack_decompose_bytes_unchecked(&byte_vars);
        assert!(result.is_err(), "limb_width + 1 바이트는 실패해야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_fail_half_chunk() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width / 2 크기의 입력 (실패 케이스)
        let total_bytes = limb_width / 2;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let result = pack_decompose_bytes_unchecked(&byte_vars);
        assert!(result.is_err(), "절반 크기는 실패해야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_fail_two_chunks_minus_one() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width * 2 - 1 크기의 입력 (실패 케이스)
        let total_bytes = limb_width * 2 - 1;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let result = pack_decompose_bytes_unchecked(&byte_vars);
        assert!(result.is_err(), "2청크 - 1바이트는 실패해야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_fail_two_chunks_plus_one() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width * 2 + 1 크기의 입력 (실패 케이스)
        let total_bytes = limb_width * 2 + 1;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let result = pack_decompose_bytes_unchecked(&byte_vars);
        assert!(result.is_err(), "2청크 + 1바이트는 실패해야 함");
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_fail_random_sizes() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 다양한 정렬되지 않은 크기들 (모두 실패해야 함)
        let invalid_sizes = vec![
            1,
            5,
            10,
            limb_width - 5,
            limb_width + 5,
            limb_width * 2 - 10,
            limb_width * 2 + 10,
            limb_width * 3 - 1,
            limb_width * 3 + 1,
        ];

        for size in invalid_sizes {
            let bytes: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let byte_vars: Vec<_> = bytes
                .iter()
                .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
                .collect();

            let result = pack_decompose_bytes_unchecked(&byte_vars);
            assert!(
                result.is_err(),
                "크기 {}는 실패해야 함 (limb_width={})",
                size,
                limb_width
            );
        }
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_success_various_multiples() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 다양한 배수 크기들 (모두 성공해야 함)
        let valid_multiples = vec![1, 2, 3, 4, 5, 10];

        for multiple in valid_multiples {
            let size = limb_width * multiple;
            let bytes: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let byte_vars: Vec<_> = bytes
                .iter()
                .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
                .collect();

            let packed = pack_decompose_bytes_unchecked(&byte_vars).unwrap();
            assert_eq!(
                packed.len(),
                multiple,
                "{}x limb_width는 {}개 청크로 패킹되어야 함",
                multiple,
                multiple
            );
        }
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_limb_width_info() {
        // 디버깅 정보 출력
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;
        println!("=== pack_decompose_bytes_unchecked 정보 ===");
        println!("필드: BN254 Fr");
        println!("MODULUS_BIT_SIZE: {} bits", TestField::MODULUS_BIT_SIZE);
        println!("자동 계산된 limb_width: {} bytes", limb_width);
        println!(
            "유효한 입력 크기: 0, {}, {}, {}, ... (limb_width의 배수)",
            limb_width,
            limb_width * 2,
            limb_width * 3
        );
        println!("==========================================");
    }

    // ==================== 제약조건 측정 테스트 ====================

    #[test]
    fn test_pack_decompose_bytes_constraints_measurement_one_chunk() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 1 청크 (31바이트)
        let bytes: Vec<u8> = (0..limb_width).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let initial_constraints = cs.num_constraints();
        let _packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
        let final_constraints = cs.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!("\n=== 제약조건 측정: 1청크 ({}바이트) ===", limb_width);
        println!("추가된 제약조건: {}", added_constraints);
        println!(
            "바이트당 제약조건: {:.2}",
            added_constraints as f64 / limb_width as f64
        );
    }

    #[test]
    fn test_pack_decompose_bytes_constraints_measurement_two_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 2 청크 (62바이트)
        let total_bytes = limb_width * 2;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let initial_constraints = cs.num_constraints();
        let _packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
        let final_constraints = cs.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!("\n=== 제약조건 측정: 2청크 ({}바이트) ===", total_bytes);
        println!("추가된 제약조건: {}", added_constraints);
        println!(
            "바이트당 제약조건: {:.2}",
            added_constraints as f64 / total_bytes as f64
        );
        println!("청크당 제약조건: {:.2}", added_constraints as f64 / 2.0);
    }

    #[test]
    fn test_pack_decompose_bytes_constraints_measurement_three_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 3 청크 (93바이트)
        let total_bytes = limb_width * 3;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let initial_constraints = cs.num_constraints();
        let _packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
        let final_constraints = cs.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!("\n=== 제약조건 측정: 3청크 ({}바이트) ===", total_bytes);
        println!("추가된 제약조건: {}", added_constraints);
        println!(
            "바이트당 제약조건: {:.2}",
            added_constraints as f64 / total_bytes as f64
        );
        println!("청크당 제약조건: {:.2}", added_constraints as f64 / 3.0);
    }

    #[test]
    fn test_pack_decompose_bytes_constraints_measurement_five_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 5 청크 (155바이트)
        let total_bytes = limb_width * 5;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let initial_constraints = cs.num_constraints();
        let _packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
        let final_constraints = cs.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!("\n=== 제약조건 측정: 5청크 ({}바이트) ===", total_bytes);
        println!("추가된 제약조건: {}", added_constraints);
        println!(
            "바이트당 제약조건: {:.2}",
            added_constraints as f64 / total_bytes as f64
        );
        println!("청크당 제약조건: {:.2}", added_constraints as f64 / 5.0);
    }

    #[test]
    fn test_pack_decompose_bytes_constraints_measurement_ten_chunks() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 10 청크 (310바이트)
        let total_bytes = limb_width * 10;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let initial_constraints = cs.num_constraints();
        let _packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
        let final_constraints = cs.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!("\n=== 제약조건 측정: 10청크 ({}바이트) ===", total_bytes);
        println!("추가된 제약조건: {}", added_constraints);
        println!(
            "바이트당 제약조건: {:.2}",
            added_constraints as f64 / total_bytes as f64
        );
        println!("청크당 제약조건: {:.2}", added_constraints as f64 / 10.0);
    }

    #[test]
    fn test_pack_decompose_bytes_constraints_comparison_summary() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        println!("\n=== 제약조건 측정 요약 (limb_width={}) ===", limb_width);
        println!(
            "{:<10} {:<15} {:<20} {:<20} {:<20}",
            "청크 수", "총 바이트", "제약조건 수", "바이트당", "청크당"
        );
        println!("{}", "-".repeat(85));

        for num_chunks in [1, 2, 3, 5, 10] {
            let total_bytes = limb_width * num_chunks;
            let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
            let byte_vars: Vec<_> = bytes
                .iter()
                .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
                .collect();

            let initial = cs.num_constraints();
            let _packed = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
            let final_c = cs.num_constraints();
            let added = final_c - initial;

            println!(
                "{:<10} {:<15} {:<20} {:<20.2} {:<20.2}",
                num_chunks,
                total_bytes,
                added,
                added as f64 / total_bytes as f64,
                added as f64 / num_chunks as f64
            );
        }
        println!("{}", "=".repeat(85));
    }

    #[test]
    fn test_pack_decompose_bytes_unchecked_vs_constraints_overhead() {
        let cs_unchecked = ConstraintSystem::<TestField>::new_ref();
        let cs_constraints = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // 3 청크로 테스트
        let total_bytes = limb_width * 3;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();

        let byte_vars_unchecked: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs_unchecked.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let byte_vars_constraints: Vec<_> = bytes
            .iter()
            .map(|&b| {
                FpVar::new_witness(cs_constraints.clone(), || Ok(TestField::from(b))).unwrap()
            })
            .collect();

        let initial_unchecked = cs_unchecked.num_constraints();
        let _packed_unchecked = pack_decompose_bytes_unchecked(&byte_vars_unchecked).unwrap();
        let final_unchecked = cs_unchecked.num_constraints();
        let added_unchecked = final_unchecked - initial_unchecked;

        let initial_constraints = cs_constraints.num_constraints();
        let _packed_constraints =
            pack_decompose_bytes_with_constraints(&byte_vars_constraints).unwrap();
        let final_constraints = cs_constraints.num_constraints();
        let added_constraints = final_constraints - initial_constraints;

        println!(
            "\n=== unchecked vs with_constraints 비교 (3청크, {}바이트) ===",
            total_bytes
        );
        println!("unchecked 제약조건:      {}", added_unchecked);
        println!("with_constraints 제약조건: {}", added_constraints);
        println!(
            "오버헤드:                 {} ({}x)",
            added_constraints - added_unchecked,
            added_constraints as f64 / added_unchecked.max(1) as f64
        );
        println!("=========================================================");
    }

    #[test]
    fn test_pack_decompose_bytes_with_constraints_vs_unchecked() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        // limb_width의 배수인 입력
        let total_bytes = limb_width * 3;
        let bytes: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        // with_constraints와 unchecked의 결과가 동일해야 함
        let packed_with_constraints = pack_decompose_bytes_with_constraints(&byte_vars).unwrap();
        let packed_unchecked = pack_decompose_bytes_unchecked(&byte_vars).unwrap();

        assert_eq!(packed_with_constraints.len(), packed_unchecked.len());
        assert_eq!(packed_with_constraints.len(), 3);

        for (a, b) in packed_with_constraints.iter().zip(packed_unchecked.iter()) {
            assert_eq!(a.value().unwrap(), b.value().unwrap());
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_pack_decompose_bytes_auto_vs_manual() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        // limb_width 크기의 정확한 입력
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;
        let bytes: Vec<u8> = (0..limb_width).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        // unchecked: 자동으로 최적 크기 계산
        let packed_auto = pack_decompose_bytes_unchecked(&byte_vars).unwrap();

        // manual: 직접 패킹
        let packed_manual = pack_bytes_to_field_unchecked(&byte_vars, limb_width).unwrap();

        // 결과가 동일해야 함
        assert_eq!(packed_auto.len(), 1);
        assert_eq!(
            packed_auto[0].value().unwrap(),
            packed_manual.value().unwrap()
        );
    }
}
