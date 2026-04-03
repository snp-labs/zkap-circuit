use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    divide_mod_power_of_2_circuit, multi_mux,
    slice_in_binary_tree, ceil,
    slice_from_start,
};

/// x가 2의 거듭제곱인지 확인하고, 그렇다면 log2(x)를 반환합니다.
/// 
/// # Arguments
/// * `x` - 입력 값
/// 
/// # Returns
/// * x가 2의 거듭제곱이면 Some(log2(x)), 아니면 None
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
    let total_bits = num_segments * bit_width;
    // Only decompose needed bits, enforce top bits are zero
    let (bits, _top_bits_are_zero) = num.to_bits_le_with_top_bits_zero(total_bits)?;

    let mut segments = Vec::with_capacity(num_segments);

    for i in 0..num_segments {
        let start_bit = (num_segments - 1 - i) * bit_width;
        let end_bit = start_bit + bit_width;

        let segment_bits = &bits[start_bit..end_bit];
        let segment = Boolean::le_bits_to_fp(segment_bits)?;
        segments.push(segment);
    }

    Ok(segments)
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
/// * `nums_per_group` - 그룹당 원소 개수 (2의 거듭제곱이어야 함)
/// 
/// # Returns
/// * 슬라이스된 배열
pub fn slice_grouped<F: PrimeField>(
    data: &[FpVar<F>],
    index: &UInt16<F>,
    length: &UInt16<F>,
    max_len: usize,
    nums_per_group: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let in_len = data.len();
    
    // nums_per_group이 2의 거듭제곱인지 확인
    let log_p = log_base_2(nums_per_group)
        .expect("nums_per_group must be a power of 2");
    
    // --- Range Checks ---
    // 1. index in [0, inLen - 1]
    Boolean::enforce_smaller_or_equal_than_le(&index.to_bits_le()?, [in_len as u64 - 1])?;
    
    // 2. length in [1, outLen]
    let length_minus_one = length.wrapping_add(&UInt16::constant(u16::MAX)); // length - 1
    Boolean::enforce_smaller_or_equal_than_le(&length_minus_one.to_bits_le()?, [max_len as u64 - 1])?;
    
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
    let (end_idx_by_p, _end_idx_mod_p) = divide_mod_power_of_2_circuit(&index_plus_length_minus_one, log_p)?;
    
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
    let pad_zero = FpVar::zero();
    let output = slice_from_start(&out_with_suffix, &length_fp, max_len, &pad_zero)?;
    
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
/// 
/// # Returns
/// * 슬라이스된 배열
pub fn slice_efficient<F: PrimeField>(
    data: &[FpVar<F>],
    index: &UInt16<F>,
    length: &UInt16<F>,
    max_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // inWidth = 8 (각 원소가 1바이트)
    // numsPerGroup = 16 (최대값, 8 * 16 = 128 < 253)
    const NUMS_PER_GROUP: usize = 16;
    
    slice_grouped(data, index, length, max_len, NUMS_PER_GROUP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{
        alloc::AllocVar,
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

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

        let start = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let length = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 15;

        let result = slice_grouped(&input_var, &start, &length, max_len, 16).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        println!("slice_grouped - number of constraints: {}", cs.num_constraints());
        
        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();
        
        // Expected: "56789ABCDE" + 5 padding chars (0s, not '_')
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

        let start = UInt16::<F>::new_witness(cs.clone(), || Ok(5u16)).unwrap();
        let length = UInt16::<F>::new_witness(cs.clone(), || Ok(10u16)).unwrap();
        let max_len = 1024 - 320; // 704

        let result = slice_efficient(&input_var, &start, &length, max_len).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        println!("slice_efficient - number of constraints: {}", cs.num_constraints());
        
        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();
        
        // Expected: "56789ABCDE" + 1024 - 10 padding chars (0s, not '_')
        let expected = b"56789ABCDE\0\0\0\0\0";
        let expected = [expected.as_ref(), &[0u8; 694]].concat(); // 패딩 추가
        assert_eq!(result_values.len(), max_len);
        for i in 0..max_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
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
            
            println!("  Group size {}: {} constraints", group_size, cs.num_constraints());
            
            // Verify correctness
            let result_values: Vec<u8> = result
                .iter()
                .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
                .collect();
            
            // Expected values
            for i in 0..slice_len as usize {
                assert_eq!(result_values[i], input[start_pos as usize + i], 
                          "Mismatch at position {} for group_size {}", i, group_size);
            }
        }
    }

    #[test]
    fn test_slice_from_start_v2() {
        println!("\n=== Testing slice_from_start (v2 implementation) ===\n");
        
        let cs = ConstraintSystem::<F>::new_ref();
        let input = b"0123456789ABCDEFGHIJ";
        let input_var = input
            .iter()
            .map(|byte| FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*byte))).unwrap())
            .collect::<Vec<_>>();

        let length = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(10u64))).unwrap();
        let out_len = 15;

        let pad_zero = FpVar::<F>::zero();
        let result = slice_from_start(&input_var, &length, out_len, &pad_zero).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        println!("slice_from_start - number of constraints: {}", cs.num_constraints());
        
        // Verify result
        let result_values: Vec<u8> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0] as u8)
            .collect();
        
        // Expected: "0123456789" + 5 padding chars (0s, not '_')
        let expected = b"0123456789\0\0\0\0\0";
        assert_eq!(result_values.len(), out_len);
        for i in 0..out_len {
            assert_eq!(result_values[i], expected[i], "Mismatch at index {}", i);
        }
        
        println!("✓ slice_from_start test passed\n");
    }
}
