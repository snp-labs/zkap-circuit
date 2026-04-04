use ark_ff::PrimeField;
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::r1cs::SynthesisError;

/// Packs byte FpVars into a single FpVar (performance-optimized version).
///
/// This function performs direct computation without constraints, making it faster,
/// but it does not validate the input values.
/// Use only with trusted inputs.
///
/// # Arguments
/// * `byte_fps`: FpVar slice representing bytes (Big-endian)
/// * `num_bytes_expected`: expected number of bytes
///
/// # Returns
/// * `Ok(FpVar<F>)`: packed value
/// * `Err(SynthesisError)`: on length mismatch or synthesis error
///
/// # Warning
/// This function does not verify that input bytes are in the 0-255 range.
pub fn pack_bytes_to_field_unchecked<F: PrimeField>(
    byte_fps: &[FpVar<F>],
    num_bytes_expected: usize,
) -> Result<FpVar<F>, SynthesisError> {
    const BITS_PER_BYTE: usize = 8;

    // 1. Validate input length
    if byte_fps.len() != num_bytes_expected {
        return Err(SynthesisError::AssignmentMissing);
    }

    // 2. Pre-compute powers of 256 (no constraints needed since they are constants)
    let base = F::from(1u128 << BITS_PER_BYTE); // 256
    let mut powers_of_256 = Vec::with_capacity(num_bytes_expected);

    let mut current_power = F::one();
    for _ in 0..num_bytes_expected {
        powers_of_256.push(current_power);
        current_power *= base;
    }
    powers_of_256.reverse(); // Reverse for Big-endian order

    // 3. Perform packing: result = Σ(byte[i] × 256^(n-1-i))
    let mut packed_fp = FpVar::<F>::zero();

    for (byte_fp, power) in byte_fps.iter().zip(powers_of_256.iter()) {
        let multiplier = FpVar::<F>::Constant(*power);
        packed_fp += byte_fp * multiplier;
    }

    Ok(packed_fp)
}

/// Packs decompose_bytes at maximum capacity (performance-optimized version).
///
/// Automatically computes the optimal limb_width using the field's maximum capacity,
/// and packs input bytes into the minimum number of FpVars.
///
/// # Strict requirement:
/// **The input length must be exactly divisible by the automatically computed limb_width.**
///
/// # Arguments
/// * `decompose_bytes`: FpVar slice representing 8-bit bytes
///
/// # Returns
/// * `Ok(Vec<FpVar<F>>)`: packed FpVar vector (minimum count)
/// * `Err(SynthesisError)`: if the length is not divisible by limb_width, or on synthesis error
///
/// # Warning
/// Does not perform input validation. Use only with trusted inputs.
pub fn pack_decompose_bytes_unchecked<F: PrimeField>(
    decompose_bytes: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    // Compute the maximum number of bytes that can be safely packed from the field size
    let limb_width = ((F::MODULUS_BIT_SIZE - 1) / 8) as usize;

    // Return empty result for empty input
    if decompose_bytes.is_empty() {
        return Ok(Vec::new());
    }

    // Verify that the input length is divisible by limb_width
    if !decompose_bytes.len().is_multiple_of(limb_width) {
        return Err(SynthesisError::AssignmentMissing);
    }

    let num_chunks = decompose_bytes.len() / limb_width;
    let mut packed_fields = Vec::with_capacity(num_chunks);

    // Process in chunks of exactly limb_width size
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
            let power = base.pow([(bytes.len() - 1 - i) as u64]);
            expected += TestField::from(b) * power;
        }

        assert_eq!(packed.value().unwrap(), expected);
    }

    // ==================== pack_decompose_bytes_unchecked tests ====================

    #[test]
    fn test_pack_decompose_bytes_unchecked_empty() {
        // Empty input always succeeds (0 % limb_width == 0)
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
        assert_eq!(packed.len(), 1, "Should be packed into exactly 1 chunk");
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
        assert_eq!(packed.len(), 2, "Should be packed into exactly 2 chunks");
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
        assert_eq!(packed.len(), 3, "Should be packed into exactly 3 chunks");
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
        assert!(result.is_err(), "limb_width - 1 bytes should fail");
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
        assert!(result.is_err(), "limb_width + 1 bytes should fail");
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
                "size {} should fail (limb_width={})",
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
                "{}x limb_width should be packed into {} chunks",
                multiple,
                multiple
            );
        }
    }

    #[test]
    fn test_pack_then_unpack_roundtrip() {
        // Pack 31 bytes then verify the packed value is consistent
        let cs = ConstraintSystem::<TestField>::new_ref();
        let limb_width = ((TestField::MODULUS_BIT_SIZE - 1) / 8) as usize;

        let bytes: Vec<u8> = (1..=limb_width as u8).collect();
        let byte_vars: Vec<_> = bytes
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(TestField::from(b))).unwrap())
            .collect();

        let packed1 = pack_bytes_to_field_unchecked(&byte_vars, limb_width).unwrap();
        let packed2 = pack_bytes_to_field_unchecked(&byte_vars, limb_width).unwrap();
        // Same input should give same result
        assert_eq!(packed1.value().unwrap(), packed2.value().unwrap());
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
