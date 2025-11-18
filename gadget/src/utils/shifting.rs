use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

// 데이터를 오른쪽으로 shift_amount 만큼 미는 함수
// shift_amount는 Witness일 수 있음
//
// 반환값: [shift개의 0, 원본 데이터, (max_shift-shift)개의 0]
// 총 길이 = 원본 길이 + max_shift
pub fn dynamic_right_shift<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    data: &[UInt8<F>],
    shift_amount: &UInt8<F>, // Witness
    max_shift: usize,        // 64
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    // 1. shift_amount를 비트로 분해 (Little Endian)
    let shift_bits = shift_amount.to_bits_le()?; // 8비트지만 실제론 6비트 사용

    // 2. 초기 배열: 원본 데이터 + 뒤에 max_shift개의 0 추가
    let zero = UInt8::constant(0);
    let mut current_data = data.to_vec();
    current_data.extend(vec![zero; max_shift]);
    // 길이: data.len() + max_shift

    // 3. Barrel Shifter 단계별 적용 (1, 2, 4, 8, 16, 32)
    // 64바이트까지만 시프트하면 되므로 6단계만 수행 (2^6 = 64)
    for i in 0..6 {
        let shift_val = 1 << i;
        let bit = &shift_bits[i];

        // 오른쪽 시프트: shifted[j] = current[j - shift_val] (j >= shift_val일 때)
        // j < shift_val일 때는 0
        let mut shifted_version = vec![UInt8::constant(0); current_data.len()];

        // 앞쪽 shift_val개는 0 (이미 초기화됨)
        // 나머지는 current_data에서 가져옴
        for j in shift_val..current_data.len() {
            shifted_version[j] = current_data[j - shift_val].clone();
        }

        // bit가 1이면 shifted_version, 0이면 current_data 선택
        for j in 0..current_data.len() {
            current_data[j] =
                UInt8::conditionally_select(bit, &shifted_version[j], &current_data[j])?;
        }
    }

    // 결과물 반환
    // 결과: [shift개의 0, 원본 데이터, ...]
    Ok(current_data)
}

// JWT header tail과 payload를 병합하는 함수
//
// header_tail_pad: header의 tail 부분 (dot 포함, 64 bytes, 나머지는 0으로 패딩)
// data: payload 데이터
// shift_amount: header tail의 실제 길이 (dot까지의 길이)
// max_shift: 최대 shift 크기 (64)
//
// 반환값: [header_tail, payload, ...] 형태로 병합된 스트림
pub fn perform_barrel_shifting<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    header_tail_pad: &[UInt8<F>],
    data: &[UInt8<F>],
    shift_amount: &UInt8<F>,
    max_shift: usize,
) -> Result<Vec<UInt8<F>>, SynthesisError> {
    // 1. payload를 shift_amount만큼 오른쪽으로 이동
    // 결과: [shift_amount개의 0, payload, ...]
    let aligned_payload_stream = dynamic_right_shift(cs, data, shift_amount, max_shift)?;

    let mut combined_stream = aligned_payload_stream;

    // 2. header_tail_pad와 병합
    // 앞쪽 64바이트는 header_tail로 교체
    // (payload는 이미 shift되어 있으므로, header_tail 뒤에 위치함)
    for i in 0..max_shift {
        if i < header_tail_pad.len() {
            // header_tail_pad[i]가 0이 아니면 header_tail_pad 사용
            // 0이면 shifted payload 유지
            let is_zero = header_tail_pad[i].is_eq(&UInt8::constant(0))?;
            combined_stream[i] =
                UInt8::conditionally_select(&is_zero, &combined_stream[i], &header_tail_pad[i])?;
        }
    }

    Ok(combined_stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    type F = Fr;

    #[test]
    fn test_dynamic_right_shift_basic() {
        println!("\n=== Dynamic Right Shift Basic Test ===\n");

        let cs = ConstraintSystem::<F>::new_ref();

        // 테스트 데이터: "ABCDEFGH" (8바이트)
        let data = b"ABCDEFGH";
        let data_vars: Vec<UInt8<F>> = data
            .iter()
            .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
            .collect();

        // shift_amount = 2
        let shift_amount = UInt8::new_witness(cs.clone(), || Ok(2u8)).unwrap();

        let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();

        assert!(cs.is_satisfied().unwrap());

        let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

        println!("입력 데이터: {:?}", String::from_utf8_lossy(data));
        println!("Shift amount: 2");
        println!("결과 길이: {} bytes", result_bytes.len());
        println!(
            "결과 (처음 20바이트): {:?}",
            String::from_utf8_lossy(&result_bytes[..20.min(result_bytes.len())])
        );

        // 처음 2바이트는 0이어야 함
        assert_eq!(result_bytes[0], 0);
        assert_eq!(result_bytes[1], 0);
        // 그 다음부터 원본 데이터
        assert_eq!(result_bytes[2], b'A');
        assert_eq!(result_bytes[3], b'B');

        println!("✅ 기본 시프트 테스트 통과\n");
    }

    #[test]
    fn test_dynamic_right_shift_various_amounts() {
        println!("\n=== Dynamic Right Shift Various Amounts Test ===\n");

        let test_cases = vec![
            (0, "시프트 없음"),
            (1, "1바이트 시프트"),
            (4, "4바이트 시프트"),
            (8, "8바이트 시프트"),
            (16, "16바이트 시프트"),
            (32, "32바이트 시프트"),
            (63, "63바이트 시프트 (최대-1)"),
        ];

        for (shift, description) in test_cases {
            let cs = ConstraintSystem::<F>::new_ref();

            // 테스트 데이터: 0x01, 0x02, 0x03, ...
            let data: Vec<u8> = (1..=20).collect();
            let data_vars: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(shift as u8)).unwrap();

            let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            println!("{} (shift={})", description, shift);
            println!("  입력: {:?}", &data[..10.min(data.len())]);
            println!("  결과 (처음 10바이트): {:?}", &result_bytes[..10]);

            // 검증: 처음 shift 바이트는 0이어야 함
            for i in 0..shift {
                assert_eq!(result_bytes[i], 0, "Index {} should be 0", i);
            }

            // 그 다음부터 원본 데이터
            for i in 0..data.len() {
                if shift + i < result_bytes.len() {
                    assert_eq!(
                        result_bytes[shift + i],
                        data[i],
                        "Index {} mismatch",
                        shift + i
                    );
                }
            }

            println!("  ✅ 통과\n");
        }
    }

    #[test]
    fn test_dynamic_right_shift_constraints() {
        println!("\n=== Dynamic Right Shift Constraint Analysis ===\n");

        let data_sizes = vec![8, 16, 32, 64, 128, 256, 512, 1024];

        for data_size in data_sizes {
            let cs = ConstraintSystem::<F>::new_ref();

            // 테스트 데이터 생성
            let data: Vec<u8> = (0..data_size).map(|i| i as u8).collect();
            let data_vars: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(10u8)).unwrap();

            let constraints_before = cs.num_constraints();

            let _result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();

            let constraints_after = cs.num_constraints();
            let constraints_used = constraints_after - constraints_before;

            assert!(cs.is_satisfied().unwrap());

            println!("데이터 크기: {} bytes", data_size);
            println!("  제약조건 수: {}", constraints_used);
            println!(
                "  평균 제약조건/바이트: {:.2}",
                constraints_used as f64 / data_size as f64
            );
            println!();
        }
    }

    #[test]
    fn test_dynamic_right_shift_barrel_shifter_stages() {
        println!("\n=== Barrel Shifter Stage Analysis ===\n");

        let cs = ConstraintSystem::<F>::new_ref();

        let data: Vec<u8> = (0..16).collect();
        let data_vars: Vec<UInt8<F>> = data
            .iter()
            .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
            .collect();

        // 각 비트 위치에 해당하는 shift 값 테스트
        let power_of_two_shifts = vec![
            (1, "2^0 = 1"),
            (2, "2^1 = 2"),
            (4, "2^2 = 4"),
            (8, "2^3 = 8"),
            (16, "2^4 = 16"),
            (32, "2^5 = 32"),
        ];

        for (shift, description) in power_of_two_shifts {
            let cs_stage = ConstraintSystem::<F>::new_ref();

            let data_vars_stage: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs_stage.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs_stage.clone(), || Ok(shift)).unwrap();

            let result =
                dynamic_right_shift(cs_stage.clone(), &data_vars_stage, &shift_amount, 64).unwrap();

            assert!(cs_stage.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            println!("{}: shift={}", description, shift);
            println!("  입력: {:?}", &data[..8]);
            let shift_usize = shift as usize;
            println!(
                "  결과 (처음 8+shift 바이트): {:?}",
                &result_bytes[..((8 + shift_usize).min(result_bytes.len()))]
            );

            // 검증
            for i in 0..shift_usize {
                assert_eq!(result_bytes[i], 0);
            }
            for i in 0..data
                .len()
                .min(result_bytes.len().saturating_sub(shift_usize))
            {
                assert_eq!(result_bytes[shift_usize + i], data[i]);
            }

            println!("  ✅ 통과\n");
        }
    }

    #[test]
    fn test_dynamic_right_shift_combined_shifts() {
        println!("\n=== Combined Shift Test ===\n");

        // 여러 비트가 켜진 shift 값 테스트 (예: 3 = 1+2, 7 = 1+2+4)
        let combined_shifts = vec![
            (3, vec![1, 2], "1 + 2 = 3"),
            (7, vec![1, 2, 4], "1 + 2 + 4 = 7"),
            (15, vec![1, 2, 4, 8], "1 + 2 + 4 + 8 = 15"),
            (31, vec![1, 2, 4, 8, 16], "1 + 2 + 4 + 8 + 16 = 31"),
        ];

        for (shift, components, description) in combined_shifts {
            let cs = ConstraintSystem::<F>::new_ref();

            let data: Vec<u8> = (1..=20).collect();
            let data_vars: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(shift as u8)).unwrap();

            let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            println!("{} (shift={})", description, shift);
            println!("  구성 요소: {:?}", components);
            println!("  결과 (처음 10바이트): {:?}", &result_bytes[..10]);

            // 검증
            for i in 0..shift {
                assert_eq!(result_bytes[i], 0, "Index {} should be 0", i);
            }
            for i in 0..data.len().min(result_bytes.len() - shift) {
                assert_eq!(
                    result_bytes[shift + i],
                    data[i],
                    "Mismatch at shifted index {}",
                    i
                );
            }

            println!("  ✅ 통과\n");
        }
    }

    #[test]
    fn test_dynamic_right_shift_edge_cases() {
        println!("\n=== Edge Cases Test ===\n");

        // 엣지 케이스 1: 빈 데이터
        {
            let cs = ConstraintSystem::<F>::new_ref();
            let data_vars: Vec<UInt8<F>> = vec![];
            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(5u8)).unwrap();

            let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();
            assert!(cs.is_satisfied().unwrap());

            println!("빈 데이터: 결과 길이 = {} (모두 0이어야 함)", result.len());
            assert_eq!(result.len(), 64);
            for byte in result {
                assert_eq!(byte.value().unwrap(), 0);
            }
            println!("  ✅ 통과\n");
        }

        // 엣지 케이스 2: shift = 0
        {
            let cs = ConstraintSystem::<F>::new_ref();
            let data = b"HELLO";
            let data_vars: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();
            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(0u8)).unwrap();

            let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();
            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            println!("Shift = 0: 처음은 원본 데이터, 그 다음 padding");
            println!("  결과[0..5]: {:?}", &result_bytes[0..5]);
            println!("  결과[5..10]: {:?}", &result_bytes[5..10]);

            // shift=0이므로 원본 데이터가 처음부터 시작
            for i in 0..data.len() {
                assert_eq!(result_bytes[i], data[i]);
            }
            // 나머지는 0 (padding)
            for i in data.len()..result_bytes.len() {
                assert_eq!(result_bytes[i], 0);
            }
            println!("  ✅ 통과\n");
        }

        // 엣지 케이스 3: 큰 shift (64 이상이지만 UInt8이므로 최대 255)
        {
            let cs = ConstraintSystem::<F>::new_ref();
            let data = b"TEST";
            let data_vars: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            // shift = 100 (하지만 6비트만 사용하므로 100 & 0x3F = 36)
            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(100u8)).unwrap();

            let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();
            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            println!("Shift = 100 (6비트만 사용: 100 & 0x3F = {})", 100 & 0x3F);
            println!("  처음 10바이트: {:?}", &result_bytes[..10]);
            println!(
                "  ⚠️ 주의: 현재 구현은 6비트만 사용하므로 실제 shift는 {} 바이트",
                100 & 0x3F
            );
            println!("  ✅ 통과\n");
        }
    }

    #[test]
    fn test_dynamic_right_shift_constraint_breakdown() {
        println!("\n=== Constraint Breakdown Analysis ===\n");

        let cs = ConstraintSystem::<F>::new_ref();

        let data: Vec<u8> = (0..16).collect();
        let data_vars: Vec<UInt8<F>> = data
            .iter()
            .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
            .collect();

        let constraints_after_data = cs.num_constraints();
        println!(
            "1. UInt8 witness 생성 (16 bytes): {} constraints",
            constraints_after_data
        );

        let shift_amount = UInt8::new_witness(cs.clone(), || Ok(10u8)).unwrap();
        let constraints_after_shift = cs.num_constraints();
        println!(
            "2. shift_amount UInt8 생성: {} constraints",
            constraints_after_shift - constraints_after_data
        );

        let shift_bits = shift_amount.to_bits_le().unwrap();
        let constraints_after_to_bits = cs.num_constraints();
        println!(
            "3. to_bits_le() (8 bits): {} constraints",
            constraints_after_to_bits - constraints_after_shift
        );

        // 단일 조건부 선택 비용 측정
        let cs_select = ConstraintSystem::<F>::new_ref();
        let a = UInt8::new_witness(cs_select.clone(), || Ok(1u8)).unwrap();
        let b = UInt8::new_witness(cs_select.clone(), || Ok(2u8)).unwrap();
        let cond = Boolean::new_witness(cs_select.clone(), || Ok(true)).unwrap();
        let _selected = UInt8::conditionally_select(&cond, &a, &b).unwrap();
        let constraints_select = cs_select.num_constraints();
        println!(
            "4. UInt8::conditionally_select (1회): {} constraints",
            constraints_select
        );

        let _result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();
        let constraints_final = cs.num_constraints();
        let shift_constraints = constraints_final - constraints_after_to_bits;

        println!(
            "5. dynamic_right_shift 실행: {} constraints",
            shift_constraints
        );

        let padded_len = data.len() + 64;
        let num_stages = 6;
        let expected_selects = num_stages * padded_len;

        println!("\n=== 예상 계산 ===");
        println!("Barrel shifter 단계: {}", num_stages);
        println!("Padded 데이터 길이: {} bytes", padded_len);
        println!(
            "예상 conditionally_select 호출 횟수: {} × {} = {}",
            num_stages, padded_len, expected_selects
        );
        println!("예상 제약조건 (select만): ~{}", expected_selects * 8); // 대략적인 추정
        println!("실제 제약조건: {}", shift_constraints);

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_dynamic_right_shift_large_data() {
        use ark_bn254::Fr;
        use ark_relations::r1cs::ConstraintSystem;

        type F = Fr;

        println!("\n=== Large Data Test (512+ bytes) ===\n");

        // 데이터 크기: 512, 544, 576, ..., 1024 (32바이트씩 증가)
        let data_sizes = [
            512, 544, 576, 608, 640, 672, 704, 736, 768, 800, 832, 864, 896, 928, 960, 992, 1024,
        ];

        // Shift 양: 0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100
        let shift_amounts = [0, 10, 20, 30, 40, 50, 60, 63, 70, 80, 90, 100];

        for &size in &data_sizes {
            println!("📦 데이터 크기: {} bytes", size);

            // 테스트 데이터 생성: 0, 1, 2, ..., 255, 0, 1, 2, ...
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            for &shift in &shift_amounts {
                let cs = ConstraintSystem::<F>::new_ref();

                let data_vars: Vec<UInt8<F>> = data
                    .iter()
                    .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                    .collect();

                let shift_amount = UInt8::new_witness(cs.clone(), || Ok(shift)).unwrap();

                let constraints_before = cs.num_constraints();
                let result =
                    dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();
                let constraints_after = cs.num_constraints();

                assert!(
                    cs.is_satisfied().unwrap(),
                    "Circuit not satisfied for size={}, shift={}",
                    size,
                    shift
                );

                let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

                // 결과 검증
                assert_eq!(result_bytes.len(), size + 64, "Wrong result length");

                // UInt8은 최대 255이므로, shift가 64 이상이면 하위 6비트만 사용됨
                let effective_shift = (shift & 0x3F) as usize;

                // 앞쪽 effective_shift 바이트는 0이어야 함
                for i in 0..effective_shift {
                    assert_eq!(
                        result_bytes[i], 0,
                        "Byte {} should be 0 for shift={}",
                        i, shift
                    );
                }

                // 그 다음부터는 원본 데이터
                let data_end = (size + 64 - effective_shift).min(size);
                for i in 0..data_end {
                    if effective_shift + i < result_bytes.len() {
                        assert_eq!(
                            result_bytes[effective_shift + i],
                            data[i],
                            "Data mismatch at position {} for shift={}",
                            i,
                            shift
                        );
                    }
                }

                let shift_constraints = constraints_after - constraints_before;
                println!(
                    "  shift={:3} → {} constraints ({}개/바이트)",
                    shift,
                    shift_constraints,
                    shift_constraints as f64 / size as f64
                );
            }

            println!();
        }

        println!("✅ 모든 대용량 데이터 테스트 통과!\n");
    }

    #[test]
    fn test_dynamic_right_shift_stress_test() {
        use ark_bn254::Fr;
        use ark_relations::r1cs::ConstraintSystem;

        type F = Fr;

        println!("\n=== Stress Test: 다양한 shift 값 (0-100 bytes) ===\n");

        let data_size = 1024;
        let data: Vec<u8> = (0..data_size).map(|i| ((i * 7 + 13) % 256) as u8).collect();

        println!("데이터 크기: {} bytes", data_size);
        println!("테스트할 shift 값: 0-100 (모든 값)\n");

        let mut total_constraints = 0u64;
        let mut num_tests = 0u64;

        for shift in 0..=100 {
            let cs = ConstraintSystem::<F>::new_ref();

            let data_vars: Vec<UInt8<F>> = data
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(shift)).unwrap();

            let constraints_before = cs.num_constraints();
            let result = dynamic_right_shift(cs.clone(), &data_vars, &shift_amount, 64).unwrap();
            let constraints_after = cs.num_constraints();

            assert!(cs.is_satisfied().unwrap(), "Failed at shift={}", shift);

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            // 검증
            let effective_shift = (shift & 0x3F) as usize;

            for i in 0..effective_shift.min(result_bytes.len()) {
                assert_eq!(result_bytes[i], 0, "shift={}, pos={}", shift, i);
            }

            let shift_constraints = constraints_after - constraints_before;
            total_constraints += shift_constraints as u64;
            num_tests += 1;

            if shift % 10 == 0 || shift == 63 {
                println!(
                    "  shift={:3} (effective={:2}) → {:5} constraints",
                    shift, effective_shift, shift_constraints
                );
            }
        }

        let avg_constraints = total_constraints / num_tests;
        println!("\n평균 제약조건: {} constraints", avg_constraints);
        println!("총 테스트 수: {} 개", num_tests);
        println!("✅ 모든 shift 값 테스트 통과!\n");
    }

    #[test]
    fn test_perform_barrel_shifting_jwt_merge() {
        use ark_bn254::Fr;
        use ark_relations::r1cs::ConstraintSystem;

        type F = Fr;

        println!("\n=== JWT Header Tail + Payload Merge Test ===\n");

        // 테스트 케이스들
        let test_cases: Vec<(&[u8], &[u8], usize, &str)> = vec![
            (
                b"header.",
                b"payload_data_here",
                7,
                "기본 케이스: header. + payload",
            ),
            (
                b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.",
                b"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
                37,
                "실제 JWT 케이스 (shift는 dot 포함 길이)",
            ),
            (
                b"short.",
                b"very_long_payload_data_that_continues_for_a_while",
                6,
                "짧은 header + 긴 payload",
            ),
            (
                b"very_long_header_tail_that_takes_more_space_up_to_limit.",
                b"payload",
                56,
                "긴 header + 짧은 payload",
            ),
            (b"a.", b"b", 2, "최소 케이스"),
        ];

        for (header_tail, payload, shift, description) in test_cases {
            println!("📝 {}", description);
            let cs = ConstraintSystem::<F>::new_ref();

            // header_tail을 64바이트로 패딩
            let mut header_tail_padded = vec![0u8; 64];
            header_tail_padded[..header_tail.len()].copy_from_slice(header_tail);

            let header_tail_vars: Vec<UInt8<F>> = header_tail_padded
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let payload_vars: Vec<UInt8<F>> = payload
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(shift as u8)).unwrap();

            let result = perform_barrel_shifting(
                cs.clone(),
                &header_tail_vars,
                &payload_vars,
                &shift_amount,
                64,
            )
            .unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            // 검증: header_tail 부분
            for i in 0..header_tail.len() {
                assert_eq!(
                    result_bytes[i], header_tail[i],
                    "Header tail mismatch at position {}",
                    i
                );
            }

            // 검증: payload 부분
            for i in 0..payload.len() {
                let result_idx = shift + i;
                if result_idx < result_bytes.len() {
                    assert_eq!(
                        result_bytes[result_idx], payload[i],
                        "Payload mismatch at position {}",
                        i
                    );
                }
            }

            // 출력
            let header_str = String::from_utf8_lossy(header_tail);
            let payload_str = String::from_utf8_lossy(payload);
            let combined_len = shift + payload.len();
            let result_str =
                String::from_utf8_lossy(&result_bytes[..combined_len.min(result_bytes.len())]);

            println!(
                "  Header tail: {:?} ({} bytes)",
                header_str,
                header_tail.len()
            );
            println!("  Payload: {:?} ({} bytes)", payload_str, payload.len());
            println!("  Shift amount: {}", shift);
            println!("  Result: {:?}", result_str);
            println!("  ✅ 통과\n");
        }
    }

    #[test]
    fn test_perform_barrel_shifting_edge_cases() {
        use ark_bn254::Fr;
        use ark_relations::r1cs::ConstraintSystem;

        type F = Fr;

        println!("\n=== JWT Merge Edge Cases ===\n");

        // 엣지 케이스 1: 빈 payload
        {
            println!("1. 빈 payload");
            let cs = ConstraintSystem::<F>::new_ref();

            let header_tail = b"header.";
            let mut header_tail_padded = vec![0u8; 64];
            header_tail_padded[..header_tail.len()].copy_from_slice(header_tail);

            let header_tail_vars: Vec<UInt8<F>> = header_tail_padded
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let payload_vars: Vec<UInt8<F>> = vec![];
            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(7u8)).unwrap();

            let result = perform_barrel_shifting(
                cs.clone(),
                &header_tail_vars,
                &payload_vars,
                &shift_amount,
                64,
            )
            .unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            // header만 있어야 함
            for i in 0..header_tail.len() {
                assert_eq!(result_bytes[i], header_tail[i]);
            }

            println!("  ✅ Header만 유지됨\n");
        }

        // 엣지 케이스 2: shift = 0 (header_tail이 빈 문자열)
        {
            println!("2. shift = 0 (header tail 없음)");
            let cs = ConstraintSystem::<F>::new_ref();

            let header_tail_padded = vec![0u8; 64];
            let payload = b"payload_only";

            let header_tail_vars: Vec<UInt8<F>> = header_tail_padded
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let payload_vars: Vec<UInt8<F>> = payload
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(0u8)).unwrap();

            let result = perform_barrel_shifting(
                cs.clone(),
                &header_tail_vars,
                &payload_vars,
                &shift_amount,
                64,
            )
            .unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            // payload만 있어야 함
            for i in 0..payload.len() {
                assert_eq!(result_bytes[i], payload[i]);
            }

            println!("  ✅ Payload만 유지됨\n");
        }

        // 엣지 케이스 3: 거의 최대 크기 header (63 bytes + dot)
        {
            println!("3. 거의 최대 크기 header tail (63 bytes)");
            let cs = ConstraintSystem::<F>::new_ref();

            // 63 bytes의 데이터 + 마지막에 dot가 아닌 문자
            let mut header_tail_data: Vec<u8> = (0..62).map(|i| (i + 65) as u8).collect(); // 'A'..'B'...
            header_tail_data.push(b'.'); // 63번째는 dot

            let mut header_tail_padded = vec![0u8; 64];
            header_tail_padded[..63].copy_from_slice(&header_tail_data);

            let payload = b"payload_after_header";

            let header_tail_vars: Vec<UInt8<F>> = header_tail_padded
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let payload_vars: Vec<UInt8<F>> = payload
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount = UInt8::new_witness(cs.clone(), || Ok(63u8)).unwrap();

            let result = perform_barrel_shifting(
                cs.clone(),
                &header_tail_vars,
                &payload_vars,
                &shift_amount,
                64,
            )
            .unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            // header 검증 (63 bytes)
            for i in 0..63 {
                assert_eq!(
                    result_bytes[i], header_tail_data[i],
                    "Header mismatch at position {}: expected {}, got {}",
                    i, header_tail_data[i], result_bytes[i]
                );
            }

            // payload 검증
            for i in 0..payload.len() {
                if 63 + i < result_bytes.len() {
                    assert_eq!(
                        result_bytes[63 + i],
                        payload[i],
                        "Payload mismatch at position {}",
                        i
                    );
                }
            }

            println!("  ✅ 거의 최대 크기 header + payload 병합 성공\n");
        }

        // 엣지 케이스 4: 실제 JWT 형식
        {
            println!("4. 실제 Base64 URL 인코딩된 JWT");
            let cs = ConstraintSystem::<F>::new_ref();

            // 실제 JWT header 예시 (base64url encoded)
            let header_tail = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.";
            let payload = b"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

            let mut header_tail_padded = vec![0u8; 64];
            header_tail_padded[..header_tail.len()].copy_from_slice(header_tail);

            let header_tail_vars: Vec<UInt8<F>> = header_tail_padded
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let payload_vars: Vec<UInt8<F>> = payload
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount =
                UInt8::new_witness(cs.clone(), || Ok(header_tail.len() as u8)).unwrap();

            let result = perform_barrel_shifting(
                cs.clone(),
                &header_tail_vars,
                &payload_vars,
                &shift_amount,
                64,
            )
            .unwrap();

            assert!(cs.is_satisfied().unwrap());

            let result_bytes: Vec<u8> = result.iter().map(|v| v.value().unwrap()).collect();

            // 전체 JWT 형식 검증
            let expected_len = header_tail.len() + payload.len();
            let mut combined = Vec::new();
            combined.extend_from_slice(header_tail);
            combined.extend_from_slice(payload);

            for i in 0..expected_len {
                assert_eq!(result_bytes[i], combined[i], "Mismatch at position {}", i);
            }

            let result_str = String::from_utf8_lossy(&result_bytes[..expected_len]);
            println!("  Combined JWT: {}", result_str);
            println!("  ✅ 실제 JWT 병합 성공\n");
        }
    }

    #[test]
    fn test_perform_barrel_shifting_constraints() {
        use ark_bn254::Fr;
        use ark_relations::r1cs::ConstraintSystem;

        type F = Fr;

        println!("\n=== JWT Merge Constraint Analysis ===\n");

        let test_sizes = vec![
            (10, "작은 payload"),
            (100, "중간 payload"),
            (500, "큰 payload"),
            (1024, "매우 큰 payload"),
        ];

        for (payload_size, description) in test_sizes {
            let cs = ConstraintSystem::<F>::new_ref();

            let header_tail = b"eyJhbGciOiJSUzI1NiJ9.";
            let mut header_tail_padded = vec![0u8; 64];
            header_tail_padded[..header_tail.len()].copy_from_slice(header_tail);

            let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();

            let header_tail_vars: Vec<UInt8<F>> = header_tail_padded
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let payload_vars: Vec<UInt8<F>> = payload
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect();

            let shift_amount =
                UInt8::new_witness(cs.clone(), || Ok(header_tail.len() as u8)).unwrap();

            let constraints_before = cs.num_constraints();
            let _result = perform_barrel_shifting(
                cs.clone(),
                &header_tail_vars,
                &payload_vars,
                &shift_amount,
                64,
            )
            .unwrap();
            let constraints_after = cs.num_constraints();

            assert!(cs.is_satisfied().unwrap());

            let merge_constraints = constraints_after - constraints_before;

            println!("{} ({} bytes):", description, payload_size);
            println!("  Header tail: {} bytes", header_tail.len());
            println!("  Payload: {} bytes", payload_size);
            println!("  병합 제약조건: {} constraints", merge_constraints);
            println!(
                "  바이트당 제약조건: {:.2}\n",
                merge_constraints as f64 / payload_size as f64
            );
        }
    }
}
