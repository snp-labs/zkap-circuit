use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
};
use ark_relations::r1cs::SynthesisError;

use crate::one_bit_vector;

/// Generates a bit vector where `out[i] = 1` when `i < index`.
///
/// Builds the one-hot vector for `index - 1`, then performs a suffix OR scan
/// to implement thermometer encoding. Range constraint: `1 <= index <= n`.
///
/// Example: `n=5, index=3` → `[1, 1, 1, 0, 0]`
pub fn lt_bit_vector<F: PrimeField>(
    index: &FpVar<F>,
    n: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    if n == 0 {
        return Ok(Vec::new());
    }

    let one = FpVar::<F>::one();
    let index_minus_one = index - one;

    let eq: Vec<FpVar<F>> = one_bit_vector(&index_minus_one, n)?;

    let mut out = eq.clone();
    for i in (0..(n - 1)).rev() {
        out[i] = &out[i] + &out[i + 1];
    }

    // let mut out = vec![FpVar::Constant(F::zero()); n];

    // if n > 0 {
    //     out[n - 1] = eq[n - 1].clone();
    // }

    // if n >= 2 {
    //     for i in (0..=(n - 2)).rev() {
    //         out[i] = eq[i].clone() + &out[i + 1];
    //     }
    // }

    Ok(out)
}

// =============================================================================
// Boolean bit vector comparison functions (merged from comparison_v2)
// =============================================================================
//
// Custom implementation used due to a bug in FpVar::enforce_cmp in arkworks 0.5.0
// Reference: https://github.com/arkworks-rs/r1cs-std/issues/161

/// A < B (Strictly Less) - for Boolean bit vectors
///
/// Accepts Little-Endian bit vectors as input and compares them.
pub fn is_less_than<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, _) = compare_bits_raw(a_bits, b_bits)?;
    Ok(less)
}

/// A <= B (Less or Equal) - for Boolean bit vectors
pub fn is_less_or_equal<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, equal) = compare_bits_raw(a_bits, b_bits)?;
    Ok(&less | &equal)
}

/// A >= B (Greater or Equal) - for Boolean bit vectors
pub fn is_greater_or_equal<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<Boolean<F>, SynthesisError> {
    let (less, _) = compare_bits_raw(a_bits, b_bits)?;
    Ok(!less)
}

/// Enforces A < B directly using subtraction-based range proof.
///
/// Instead of building a Boolean through per-bit operations (5n constraints),
/// this allocates witness bits for `diff = b - a - 1` and checks they reconstruct (n+1 constraints).
///
/// Soundness: If a < b, then 0 <= b-a-1 < 2^n, so n-bit decomposition exists.
/// If a >= b, then b-a-1 wraps in the field, and no valid n-bit decomposition exists.
///
/// Precondition: a, b are n-bit bounded (guaranteed by the caller providing n-bit Boolean vectors).
pub fn enforce_less_than<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<(), SynthesisError> {
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "Bit lengths must be equal for comparison"
    );

    let n = a_bits.len();

    // Reconstruct field elements from bit vectors (linear combinations, 0 constraints)
    let mut a_fp = FpVar::<F>::zero();
    let mut b_fp = FpVar::<F>::zero();
    let mut power_of_two = F::one();
    for i in 0..n {
        a_fp += FpVar::from(a_bits[i].clone()) * power_of_two;
        b_fp += FpVar::from(b_bits[i].clone()) * power_of_two;
        power_of_two.double_in_place();
    }

    // diff = b - a - 1
    let diff = &b_fp - &a_fp - FpVar::one();

    // Allocate witness bits for diff and enforce reconstruction
    let diff_val = diff.value().unwrap_or_default();
    let mut diff_bits = Vec::with_capacity(n);
    let cs = diff.cs();
    let mut remaining = diff_val;
    let two_inv = F::from(2u64).inverse().unwrap();
    for _ in 0..n {
        // Check if LSB is 1 by testing if (remaining - 1) / 2 would be valid
        // remaining is odd iff remaining / 2 != (remaining - 1) / 2 + 1/2
        // Simpler: use into_bigint() to check LSB
        let bigint = remaining.into_bigint();
        let bit_val = bigint.is_odd();
        let bit = Boolean::new_witness(cs.clone(), || Ok(bit_val))?;
        diff_bits.push(bit);
        remaining = if bit_val {
            (remaining - F::one()) * two_inv
        } else {
            remaining * two_inv
        };
    }

    // Enforce: Σ diff_bits[i] * 2^i == diff
    let mut reconstructed = FpVar::<F>::zero();
    let mut power_of_two = F::one();
    for bit in &diff_bits {
        reconstructed += FpVar::from(bit.clone()) * power_of_two;
        power_of_two.double_in_place();
    }
    reconstructed.enforce_equal(&diff)?;

    Ok(())
}

/// Performs a bit-by-bit comparison and returns a (is_less, is_equal) tuple.
///
/// * Input: Boolean vector in Little-Endian order (e.g., result of to_bits_le())
/// * Output: (a < b, a == b)
pub fn compare_bits_raw<F: PrimeField>(
    a_bits: &[Boolean<F>],
    b_bits: &[Boolean<F>],
) -> Result<(Boolean<F>, Boolean<F>), SynthesisError> {
    assert_eq!(
        a_bits.len(),
        b_bits.len(),
        "Bit lengths must be equal for comparison"
    );

    let mut less = Boolean::constant(false);
    let mut equal = Boolean::constant(true);

    // Iterate from MSB to LSB (to_bits_le returns [LSB, ..., MSB] order)
    for (a_bit, b_bit) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        let a_is_zero = !a_bit;
        let a_is_zero_b_is_one = &a_is_zero & b_bit;
        let strict_less_at_here = &equal & &a_is_zero_b_is_one;

        less = &less | &strict_less_at_here;

        let bits_are_equal = !(a_bit ^ b_bit);
        equal = &equal & &bits_are_equal;
    }

    Ok((less, equal))
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{
        R1CSVar,
        alloc::AllocVar,
        eq::EqGadget,
        fields::{FieldVar, fp::FpVar},
    };
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    use crate::lt_bit_vector;

    type F = ark_bn254::Fr;

    #[test]
    fn test_lt_bit_vector() {
        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3))).unwrap();
        let n = 5;
        let expected = vec![
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
        ];
        let result = lt_bit_vector(&index, n).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
        expected.enforce_equal(&result).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_lt_bit_vector_index_one() {
        // index=1, n=5 → only i=0 satisfies i < 1 → [1,0,0,0,0]
        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap();
        let result = lt_bit_vector(&index, 5).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let expected = vec![
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u8))).unwrap(),
        ];
        expected.enforce_equal(&result).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_lt_bit_vector_index_last() {
        // index=5, n=5 → all i in 0..4 satisfy i < 5 → [1,1,1,1,1]
        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let result = lt_bit_vector(&index, 5).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let expected = vec![
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
            FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u8))).unwrap(),
        ];
        expected.enforce_equal(&result).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_is_less_than_equal_case() {
        use super::{compare_bits_raw, is_less_than};
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        let result = is_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(!result.value().unwrap()); // 5 is NOT less than 5
    }

    #[test]
    fn test_is_less_or_equal_equal_case() {
        use super::is_less_or_equal;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        let result = is_less_or_equal(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(result.value().unwrap()); // 5 <= 5
    }

    #[test]
    fn test_is_greater_or_equal_equal_case() {
        use super::is_greater_or_equal;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        let result = is_greater_or_equal(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(result.value().unwrap()); // 5 >= 5
    }

    #[test]
    fn test_compare_bits_raw_basic() {
        use super::compare_bits_raw;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        let (less, equal) = compare_bits_raw(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(less.value().unwrap());   // 3 < 5
        assert!(!equal.value().unwrap()); // 3 != 5
    }

    #[test]
    fn test_compare_bits_raw_equal() {
        use super::compare_bits_raw;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(7u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(7u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        let (less, equal) = compare_bits_raw(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(!less.value().unwrap());  // 7 is NOT less than 7
        assert!(equal.value().unwrap());  // 7 == 7
    }

    // =========================================================================
    // enforce_less_than tests
    // =========================================================================

    #[test]
    fn test_enforce_less_than_basic() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap()); // 3 < 5
    }

    #[test]
    fn test_enforce_less_than_zero_lt_one() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap()); // 0 < 1
    }

    #[test]
    fn test_enforce_less_than_consecutive() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(254u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(255u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap()); // 254 < 255
    }

    #[test]
    fn test_enforce_less_than_wide_gap() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(255u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(cs.is_satisfied().unwrap()); // 0 < 255
    }

    #[test]
    fn test_enforce_less_than_equal_fails() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // 5 == 5, NOT less than
    }

    #[test]
    fn test_enforce_less_than_greater_fails() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(7u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // 7 > 3
    }

    #[test]
    fn test_enforce_less_than_max_vs_zero_fails() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(255u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..8], &b_bits[..8]).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // 255 > 0
    }

    #[test]
    fn test_enforce_less_than_single_bit() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..1], &b_bits[..1]).unwrap();
        assert!(cs.is_satisfied().unwrap()); // 0 < 1 (1-bit)
    }

    #[test]
    fn test_enforce_less_than_single_bit_fails() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..1], &b_bits[..1]).unwrap();
        assert!(!cs.is_satisfied().unwrap()); // 1 > 0 (1-bit)
    }

    #[test]
    fn test_enforce_less_than_16bit() {
        use super::enforce_less_than;
        use ark_r1cs_std::prelude::ToBitsGadget;

        let cs: ConstraintSystemRef<F> = ConstraintSystem::<F>::new_ref();
        let a = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1000u64))).unwrap();
        let b = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(65535u64))).unwrap();
        let a_bits = a.to_bits_le().unwrap();
        let b_bits = b.to_bits_le().unwrap();

        enforce_less_than(&a_bits[..16], &b_bits[..16]).unwrap();
        assert!(cs.is_satisfied().unwrap()); // 1000 < 65535 (16-bit)
    }
}
