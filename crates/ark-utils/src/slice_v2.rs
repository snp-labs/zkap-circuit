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

/// Checks whether x is a power of 2, and if so returns log2(x).
///
/// # Arguments
/// * `x` - input value
///
/// # Returns
/// * Some(log2(x)) if x is a power of 2, otherwise None
pub fn log_base_2(x: usize) -> Option<u32> {
    if x == 0 {
        return None;
    }
    
    // Check if x is a power of 2 (only one bit set)
    if x & (x - 1) != 0 {
        return None;
    }
    
    // trailing_zeros counts zeros from the lowest bit (i.e., log2)
    Some(x.trailing_zeros())
}

/// Combines an array of w-bit segments into a single field element in big-endian order.
///
/// Performs the same function as Circom's Segments2NumBE.
///
/// # Arguments
/// * `segments` - array of w-bit values (each element in range 0 ~ 2^w-1)
/// * `bit_width` - bit width of each segment
///
/// # Returns
/// * combined field element
pub fn segments_to_num_be<F: PrimeField>(
    segments: &[FpVar<F>],
    bit_width: usize,
) -> Result<FpVar<F>, SynthesisError> {
    // Validate n * w <= 253 (field size limit)
    assert!(
        segments.len() * bit_width <= 253,
        "Total bit width exceeds field capacity"
    );
    
    let mut result = FpVar::<F>::zero();
    let mut multiplier = F::one();
    
    // Process from the last element since it is Big-endian
    for i in (0..segments.len()).rev() {
        result += &segments[i] * FpVar::constant(multiplier);
        // multiplier *= 2^bit_width
        multiplier *= F::from(1u64 << bit_width);
    }
    
    Ok(result)
}

/// Decomposes a field element into multiple segments (big-endian).
/// Inverse operation of segments_to_num_be.
///
/// # Arguments
/// * `num` - field element to decompose
/// * `num_segments` - number of output segments
/// * `bit_width` - bit width of each segment
///
/// # Returns
/// * segment array
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

/// Grouped slice function (equivalent to Circom's SliceGrouped).
///
/// Groups the input array before slicing to improve efficiency.
///
/// # Arguments
/// * `data` - input byte array (each FpVar<F> is 1 byte)
/// * `index` - slice start index
/// * `length` - slice length
/// * `max_len` - maximum output length
/// * `nums_per_group` - number of elements per group (must be a power of 2)
///
/// # Returns
/// * sliced array
pub fn slice_grouped<F: PrimeField>(
    data: &[FpVar<F>],
    index: &UInt16<F>,
    length: &UInt16<F>,
    max_len: usize,
    nums_per_group: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let in_len = data.len();
    
    // Check that nums_per_group is a power of 2
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
    
    // --- Group inputs ---
    let grouped_in_width = nums_per_group * 8; // each byte is 8 bits
    assert!(
        grouped_in_width < 253,
        "Grouped width must be less than field size"
    );
    
    let grouped_in_len = ceil(in_len as u64, nums_per_group as u64) as usize;
    let mut in_grouped = Vec::with_capacity(grouped_in_len);
    
    // Group inputs into chunks of nums_per_group and combine in big-endian order
    for i in 0..grouped_in_len {
        let mut group = Vec::with_capacity(nums_per_group);
        for j in 0..nums_per_group {
            let idx = i * nums_per_group + j;
            if idx < in_len {
                group.push(data[idx].clone());
            } else {
                // Pad missing positions with 0
                group.push(FpVar::constant(F::zero()));
            }
        }
        // Combine in big-endian order (using segments_to_num_be)
        let grouped_elem = segments_to_num_be(&group, 8)?; // each segment is 8 bits
        in_grouped.push(grouped_elem);
    }
    
    // --- Decompose index ---
    // index = startIdxByP * numsPerGroup + startIdxModP
    let (start_idx_by_p, start_idx_mod_p) = divide_mod_power_of_2_circuit(index, log_p)?;
    
    // (index + length - 1) = endIdxByP * numsPerGroup + endIdxModP
    let index_plus_length_minus_one = UInt16::<F>::wrapping_add_many(&[
        index.clone(),
        length.clone(),
        UInt16::constant(u16::MAX), // -1
    ])?;
    let (end_idx_by_p, _end_idx_mod_p) = divide_mod_power_of_2_circuit(&index_plus_length_minus_one, log_p)?;
    
    // --- Compute number of output groups ---
    // The sublist spans the most groups when it starts at the last element of a group.
    // Therefore: 1 + ceil((outLen - 1) / numsPerGroup)
    let grouped_out_len = 1 + ceil((max_len - 1) as u64, nums_per_group as u64) as usize;
    
    // --- Slice from grouped array ---
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
    
    // --- Ungroup (ConvertBase role) ---
    let x = nums_per_group * grouped_out_len;
    let mut out_final = Vec::with_capacity(x);
    
    for group in &out_grouped {
        // Decompose each group into bytes
        let bytes = num_to_segments_be(group, nums_per_group, 8)?;
        out_final.extend(bytes);
    }
    
    // Verify: (outLen - 1) + (numsPerGroup - 1) <= X - 1
    assert!((max_len - 1) + (nums_per_group - 1) <= x - 1);
    
    // --- Generate rotation options (MultiMux role) ---
    // outOptions[i][j] = outFinal[i + j]
    let mut out_options = Vec::with_capacity(max_len);
    for i in 0..max_len {
        let mut option = Vec::with_capacity(nums_per_group);
        for j in 0..nums_per_group {
            option.push(out_final[i + j].clone());
        }
        out_options.push(option);
    }
    
    // --- Select correct offset with Multiplexer ---
    // Use startIdxModP to select the correct alignment
    let start_idx_mod_p_fp = Boolean::le_bits_to_fp(&start_idx_mod_p.to_bits_le()?)?;
    let out_with_suffix = multi_mux(&out_options, &start_idx_mod_p_fp)?;
    
    // --- Finally trim to length and pad the rest ---
    let length_fp = Boolean::le_bits_to_fp(&length.to_bits_le()?)?;
    let pad_zero = FpVar::zero();
    let output = slice_from_start(&out_with_suffix, &length_fp, max_len, &pad_zero)?;
    
    Ok(output)
}

/// Efficient slice function (equivalent to Circom's SliceEfficient).
///
/// A wrapper around slice_grouped with the same function signature
/// that can be used as a drop-in replacement for the existing slice function.
///
/// # Arguments
/// * `data` - input byte array (each FpVar<F> is 1 byte)
/// * `index` - slice start index
/// * `length` - slice length
/// * `max_len` - maximum output length
///
/// # Returns
/// * sliced array
pub fn slice_efficient<F: PrimeField>(
    data: &[FpVar<F>],
    index: &UInt16<F>,
    length: &UInt16<F>,
    max_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // inWidth = 8 (each element is 1 byte)
    // numsPerGroup = 16 (maximum value, 8 * 16 = 128 < 253)
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
        
        // Not a power of 2
        assert_eq!(log_base_2(3), None);
        assert_eq!(log_base_2(5), None);
        assert_eq!(log_base_2(6), None);
        assert_eq!(log_base_2(7), None);
        assert_eq!(log_base_2(15), None);
    }

    #[test]
    fn test_segments_to_num_be() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Test: combine [1, 2, 3, 4] as 8-bit segments
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
        let expected = [expected.as_ref(), &[0u8; 694]].concat(); // add padding
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
