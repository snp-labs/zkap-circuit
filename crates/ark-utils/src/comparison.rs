use ark_ff::PrimeField;
use ark_r1cs_std::{
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
}
