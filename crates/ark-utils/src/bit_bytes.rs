use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

/// Arkworks 회로 내에서 입력 정수(UInt16)를 2의 p 제곱으로 나눈 몫과 나머지를 계산합니다.
///
/// # Arguments
/// * `input`: 나눗셈을 수행할 입력 정수 (`UInt16<ConstraintF>` 타입).
/// * `p`: 나눌 값 (2의 p 제곱)을 결정하는 지수 (0 < p < 16).
///
/// # Returns
/// (몫, 나머지)의 튜플 (`UInt16<ConstraintF>`, `UInt16<ConstraintF>`)
pub fn divide_mod_power_of_2_circuit<F: PrimeField>(
    input: &UInt16<F>,
    p: u32,
) -> Result<(UInt16<F>, UInt16<F>), SynthesisError> {
    assert!(
        p > 0 && p < 16,
        "p must be greater than 0 and less than 16 for UInt16"
    );

    let bits = input.to_bits_le()?;

    let remainder_bits_slice = &bits[0..p as usize];
    let mut remainder_bits_padded = remainder_bits_slice.to_vec();
    remainder_bits_padded.resize(16, Boolean::FALSE);
    let remainder = UInt16::from_bits_le(&remainder_bits_padded);

    let quotient_bits_slice = &bits[p as usize..16];
    let mut quotient_bits_padded = quotient_bits_slice.to_vec();
    quotient_bits_padded.resize(16, Boolean::FALSE);
    let quotient = UInt16::from_bits_le(&quotient_bits_padded);

    Ok((quotient, remainder))
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
/// 이 함수는 입력 바이트가 0-255 범위인지 검증하지 않습니다.
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

/// decompose_bytes를 최대 용량으로 압축합니다 (성능 최적화 버전).
///
/// 필드의 최대 용량을 활용하여 자동으로 최적의 limb_width를 계산하고,
/// 입력 바이트들을 최소 개수의 FpVar로 패킹합니다.
///
/// # 엄격한 요구사항:
/// **입력 길이는 자동 계산된 limb_width로 정확히 나누어떨어져야 합니다.**
///
/// # Arguments
/// * `decompose_bytes`: 8비트 바이트를 나타내는 FpVar 슬라이스
///
/// # Returns
/// * `Ok(Vec<FpVar<F>>)`: 패킹된 FpVar 벡터 (최소 개수)
/// * `Err(SynthesisError)`: 길이가 limb_width로 나누어떨어지지 않거나 합성 오류 발생 시
///
/// # Warning
/// 입력 검증을 수행하지 않습니다. 신뢰할 수 있는 입력에만 사용하세요.
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
    if !decompose_bytes.len().is_multiple_of(limb_width) {
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
    fn test_pack_decompose_bytes_unchecked_fail_random_sizes() {
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

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
    fn test_pack_decompose_bytes_auto_vs_manual() {
        let cs = ConstraintSystem::<TestField>::new_ref();

        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;
        let bytes: Vec<u8> = (0..limb_width).map(|i| (i % 256) as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed_auto = pack_decompose_bytes_unchecked(&byte_vars).unwrap();
        let packed_manual = pack_bytes_to_field_unchecked(&byte_vars, limb_width).unwrap();

        assert_eq!(packed_auto.len(), 1);
        assert_eq!(
            packed_auto[0].value().unwrap(),
            packed_manual.value().unwrap()
        );
    }
}
