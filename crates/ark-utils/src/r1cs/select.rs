//! R1CS gadgets for array selection and multiplexing.
//!
//! Exports: [`multi_mux`], [`single_multiplexer`], [`one_bit_vector`],
//! [`select_array_element`], [`select_array_element_be`].  These gadgets
//! implement mux / one-hot selection over `FpVar` arrays and generate R1CS
//! constraints.  Requires the `r1cs` feature (default-on).

use ark_ff::PrimeField;
use ark_r1cs_std::{
    GR1CSVar,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::Boolean,
    select::CondSelectGadget,
};
use ark_relations::gr1cs::SynthesisError;

/// Selects the column at the `selector` index from a 2D array.
///
/// Picks the element at the same index from each row to build a new vector.
///
/// Example: `[[a,b,c], [d,e,f], [g,h,i]]`, `selector=1` → `[b, e, h]`
pub fn multi_mux<F, T>(inputs: &[Vec<T>], selector: &FpVar<F>) -> Result<Vec<T>, SynthesisError>
where
    F: PrimeField,
    T: GR1CSVar<F> + Clone + CondSelectGadget<F>,
{
    let out_len = inputs.len();
    let mut output = Vec::with_capacity(out_len);

    for input_row in inputs {
        // Call single_multiplexer for each row.
        let selected = single_multiplexer(input_row, selector)?;
        output.push(selected);
    }

    Ok(output)
}
/// Selects the element at index `idx` from an array (multiplexer).
///
/// Implements `output = inp[idx]` using one-hot encoding and scalar multiplication.
pub fn single_multiplexer<F, T>(inp: &[T], idx: &FpVar<F>) -> Result<T, SynthesisError>
where
    F: PrimeField,
    T: GR1CSVar<F> + Clone + CondSelectGadget<F>,
{
    let n = inp.len();
    let eq_bits = one_bit_vector(idx, n)?;

    assert!(!inp.is_empty(), "inputs cannot be empty");

    let mut res = inp[0].clone();
    for (i, bit) in eq_bits.iter().enumerate().skip(1) {
        res = T::conditionally_select(bit, &inp[i], &res)?;
    }

    Ok(res)
}

/// Converts an index into a one-hot vector and enforces range constraints.
///
/// Produces a vector with 1 at position `index` and 0 everywhere else.
/// Enforces that the sum equals 1, guaranteeing `0 <= index < n`.
///
/// Example: `n=5, index=2` → `[0, 0, 1, 0, 0]`
pub fn one_bit_vector<F, Out>(index: &FpVar<F>, n: usize) -> Result<Vec<Out>, SynthesisError>
where
    F: PrimeField,
    Out: GR1CSVar<F> + From<Boolean<F>>,
{
    if n == 0 {
        return Ok(vec![]);
    }

    let mut eq_bits = Vec::with_capacity(n);
    let mut sum_of_bits = FpVar::<F>::zero();

    for i in 0..n {
        let i_const = FpVar::<F>::Constant(F::from(i as u64));
        let is_equal = index.is_eq(&i_const)?;
        sum_of_bits += FpVar::from(is_equal.clone());
        eq_bits.push(Out::from(is_equal));
    }

    // Enforce that the sum equals 1 (exactly one index is in range)
    sum_of_bits.enforce_equal(&FpVar::one())?;

    Ok(eq_bits)
}
/// Selects an element from an array using bit index (recursive halving).
///
/// Splits the array in half and selects left or right based on the MSB.
pub fn select_array_element<F: PrimeField>(
    input: &[FpVar<F>],
    idx_bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    assert!(!input.is_empty());

    assert_eq!(input.len(), 1 << idx_bits.len());

    if input.len() == 1 {
        Ok(input[0].clone())
    } else {
        let mid = input.len() / 2;
        let left = &input[..mid];
        let right = &input[mid..];

        let msb_index = idx_bits.len() - 1;
        let msb = idx_bits[msb_index].clone();
        let remaining_bits = &idx_bits[..msb_index];

        let left_value = select_array_element(left, remaining_bits)?;
        let right_value = select_array_element(right, remaining_bits)?;

        let selected_value = FpVar::conditionally_select(&msb, &right_value, &left_value)?;

        Ok(selected_value)
    }
}

/// Big-endian variant of [`select_array_element`] — the most significant
/// bit of `idx_bits` selects between the two halves at every level. The
/// length of `input` must equal `2.pow(idx_bits.len())` and `input` must
/// be non-empty.
pub fn select_array_element_be<F: PrimeField>(
    input: &[FpVar<F>],
    idx_bits: &[Boolean<F>],
) -> Result<FpVar<F>, SynthesisError> {
    assert!(!input.is_empty());

    assert_eq!(input.len(), 1 << idx_bits.len());

    if input.len() == 1 {
        Ok(input[0].clone())
    } else {
        let mid = input.len() / 2;
        let left = &input[..mid];
        let right = &input[mid..];

        let msb = idx_bits[0].clone();
        let remaining_bits = &idx_bits[1..];

        let left_value = select_array_element_be(left, remaining_bits)?;
        let right_value = select_array_element_be(right, remaining_bits)?;

        let selected_value = FpVar::conditionally_select(&msb, &right_value, &left_value)?;

        Ok(selected_value)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::{One, Zero};
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::gr1cs::ConstraintSystem;

    use crate::{lt_bit_vector, one_bit_vector};

    type F = ark_bn254::Fr;

    #[test]
    fn test_one_bit_vector() {
        let cs = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap();
        let n = 5;

        let expected = vec![
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
        ];

        let result = one_bit_vector(&index, n).unwrap();

        assert!(cs.is_satisfied().unwrap());
        expected.enforce_equal(&result).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_lt_bit_vector() {
        let cs = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap();
        let n = 5;

        let expected = vec![
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
        ];

        let result = lt_bit_vector(&index, n).unwrap();

        assert!(cs.is_satisfied().unwrap());

        expected.enforce_equal(&result).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_single_multiplexer_correctness() {
        use super::single_multiplexer;

        let cs = ConstraintSystem::<F>::new_ref();
        let n = 5;

        // Input array: [10, 20, 30, 40, 50]
        let inputs: Vec<FpVar<F>> = (0..n)
            .map(|i| {
                FpVar::<F>::new_witness(cs.clone(), || Ok(F::from((i + 1) as u64 * 10))).unwrap()
            })
            .collect();

        // Select index 2 -> should return 30
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(2))).unwrap();
        let result = single_multiplexer(&inputs, &index).unwrap();

        assert!(cs.is_satisfied().unwrap());
        result.enforce_equal(&FpVar::Constant(F::from(30))).unwrap();
        println!("Selected value at index 2: should be 30");
        println!("Number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_multi_mux() {
        use super::multi_mux;

        let cs = ConstraintSystem::<F>::new_ref();

        // Create 2D array: [[1,2,3], [4,5,6], [7,8,9]]
        let inputs: Vec<Vec<FpVar<F>>> = (0..3)
            .map(|row| {
                (0..3)
                    .map(|col| {
                        FpVar::<F>::new_witness(cs.clone(), || {
                            Ok(F::from((row * 3 + col + 1) as u64))
                        })
                        .unwrap()
                    })
                    .collect()
            })
            .collect();

        // Select index 1 -> should return [2, 5, 8]
        let selector = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(1))).unwrap();
        let result = multi_mux(&inputs, &selector).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 3);

        result[0]
            .enforce_equal(&FpVar::Constant(F::from(2)))
            .unwrap();
        result[1]
            .enforce_equal(&FpVar::Constant(F::from(5)))
            .unwrap();
        result[2]
            .enforce_equal(&FpVar::Constant(F::from(8)))
            .unwrap();

        println!("Multi-mux selected column 1: [2, 5, 8]");
        println!("Number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_one_bit_vector_first() {
        let cs = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let result: Vec<FpVar<F>> = one_bit_vector(&index, 4).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let expected = vec![
            FpVar::<F>::Constant(F::one()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
        ];
        expected.enforce_equal(&result).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_one_bit_vector_last() {
        let cs = ConstraintSystem::<F>::new_ref();
        let index = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3u64))).unwrap();
        let result: Vec<FpVar<F>> = one_bit_vector(&index, 4).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let expected = vec![
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::zero()),
            FpVar::<F>::Constant(F::one()),
        ];
        expected.enforce_equal(&result).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_single_multiplexer_index_zero() {
        use super::single_multiplexer;

        let cs = ConstraintSystem::<F>::new_ref();
        let inputs: Vec<FpVar<F>> = vec![
            FpVar::new_witness(cs.clone(), || Ok(F::from(10u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(20u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(30u64))).unwrap(),
        ];
        let index = FpVar::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        let result = single_multiplexer(&inputs, &index).unwrap();

        assert!(cs.is_satisfied().unwrap());
        result
            .enforce_equal(&FpVar::Constant(F::from(10u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_single_multiplexer_index_last() {
        use super::single_multiplexer;

        let cs = ConstraintSystem::<F>::new_ref();
        let inputs: Vec<FpVar<F>> = vec![
            FpVar::new_witness(cs.clone(), || Ok(F::from(10u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(20u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(30u64))).unwrap(),
        ];
        let index = FpVar::new_witness(cs.clone(), || Ok(F::from(2u64))).unwrap();
        let result = single_multiplexer(&inputs, &index).unwrap();

        assert!(cs.is_satisfied().unwrap());
        result
            .enforce_equal(&FpVar::Constant(F::from(30u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_select_array_element_le_basic() {
        use super::select_array_element;
        use ark_r1cs_std::prelude::Boolean;

        let cs = ConstraintSystem::<F>::new_ref();
        // 4 elements → 2 bits
        let input: Vec<FpVar<F>> = (1..=4u64)
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(F::from(v * 10))).unwrap())
            .collect();

        // Index 2 in LE: 2 = 0b10 → LE bits = [0, 1]
        let idx_bits = vec![
            Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(),
            Boolean::new_witness(cs.clone(), || Ok(true)).unwrap(),
        ];

        let result = select_array_element(&input, &idx_bits).unwrap();
        assert!(cs.is_satisfied().unwrap());
        result
            .enforce_equal(&FpVar::Constant(F::from(30u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_select_array_element_be_basic() {
        use super::select_array_element_be;
        use ark_r1cs_std::prelude::Boolean;

        let cs = ConstraintSystem::<F>::new_ref();
        let input: Vec<FpVar<F>> = (1..=4u64)
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(F::from(v * 10))).unwrap())
            .collect();

        // Index 2 in BE: 2 = 0b10 → BE bits = [1, 0]
        let idx_bits = vec![
            Boolean::new_witness(cs.clone(), || Ok(true)).unwrap(),
            Boolean::new_witness(cs.clone(), || Ok(false)).unwrap(),
        ];

        let result = select_array_element_be(&input, &idx_bits).unwrap();
        assert!(cs.is_satisfied().unwrap());
        result
            .enforce_equal(&FpVar::Constant(F::from(30u64)))
            .unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
