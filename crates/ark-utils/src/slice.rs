use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar},
    prelude::{Boolean, ToBitsGadget},
    select::CondSelectGadget,
    uint16::UInt16,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    is_less_than, lt_bit_vector, select_array_element,
};

pub fn slice_in_binary_tree<F: PrimeField>(
    input: &[FpVar<F>],
    offset: &UInt16<F>,
    len: &FpVar<F>,
    output_len: usize,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let input_len = input.len();

    let zero = FpVar::<F>::Constant(F::from(b'A'));

    // Pad input array
    let input_padded = pad_input(input);

    let select_bit_len = input_padded.len().next_power_of_two().trailing_zeros() as usize;
    let comp_bit_len = select_bit_len + 1;

    let input_len_bits = (0..comp_bit_len)
        .map(|k| Boolean::<F>::constant(((input_len >> k) & 1) == 1))
        .collect::<Vec<_>>();

    // Bit representation of length
    let mut length_bits = len.to_bits_le()?;
    length_bits = length_bits[..comp_bit_len].to_vec();

    let mut output = Vec::new();
    for i in 0..output_len {
        let i_fp = UInt16::<F>::constant(i as u16);

        let idx = offset.wrapping_add(&i_fp);

        // Bit representation of idx
        let mut idx_bits = idx.to_bits_le()?;
        idx_bits = idx_bits[..comp_bit_len].to_vec();

        // Bit representation of i
        let mut i_bits = i_fp.to_bits_le()?;
        i_bits = i_bits[..comp_bit_len].to_vec();

        // Check if i < length
        let i_lt_length = is_less_than(&i_bits, &length_bits)?;

        // Check if idx < input_len
        let idx_lt_input_len = is_less_than(&idx_bits, &input_len_bits)?;

        let mut idx_bits_sel = idx.to_bits_le()?;
        idx_bits_sel = idx_bits_sel[..select_bit_len].to_vec();

        // Check if the index is valid
        let valid = &i_lt_length & &idx_lt_input_len;

        // Select input[idx]
        let input_elem = select_array_element(&input_padded, &idx_bits_sel)?;

        // Select value based on valid
        let output_elem = FpVar::conditionally_select(&valid, &input_elem, &zero)?;

        output.push(output_elem);
    }
    Ok(output)
}

/// Performs ceiling division.
/// Computes ceil(n / q).
pub fn ceil(n: u64, q: u64) -> u64 {
    assert!(q != 0, "Divisor q cannot be zero");

    let quotient = n / q;
    let remainder = n % q;

    if remainder == 0 {
        quotient
    } else {
        quotient + 1
    }
}

/// Returns the first `length` elements from the input vector and fills the rest with `pad_char`.
///
/// ## Arguments
/// * `in_vec` - input vector
/// * `length` - slice length (variable inside the circuit)
/// * `out_len` - fixed length of the output vector
/// * `pad_char` - padding character
pub fn slice_from_start<F: PrimeField>(
    in_vec: &[FpVar<F>],
    length: &FpVar<F>,
    out_len: usize,
    pad_char: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let in_len = in_vec.len();

    assert!(out_len > 0, "Output length (out_len) must be greater than 0.");
    assert!(
        out_len <= in_len,
        "Output length (out_len) must be less than or equal to input length (in_len = {}).",
        in_len
    );

    let mask_vec: Vec<FpVar<F>> = lt_bit_vector(length, out_len)?;

    let out_vec: Vec<FpVar<F>> = in_vec
        .iter()
        .take(out_len)
        .zip(mask_vec.iter())
        .map(|(inp_val, mask_val)| {
            mask_val * (inp_val * mask_val) + (FpVar::Constant(F::from(1u8)) - mask_val) * pad_char
        })
        .collect();

    Ok(out_vec)
}

fn pad_input<F: PrimeField>(input: &[FpVar<F>]) -> Vec<FpVar<F>> {
    let mut input_padded = input.to_vec();
    let next_power_of_two = input.len().next_power_of_two();
    let zero = FpVar::<F>::zero();
    input_padded.resize(next_power_of_two, zero);
    input_padded
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

    #[test]
    fn test_ceil_basic() {
        assert_eq!(ceil(7, 3), 3);
        assert_eq!(ceil(10, 3), 4);
        assert_eq!(ceil(1, 1), 1);
    }

    #[test]
    fn test_ceil_exact_division() {
        assert_eq!(ceil(6, 3), 2);
        assert_eq!(ceil(9, 3), 3);
        assert_eq!(ceil(0, 5), 0);
    }

    #[test]
    #[should_panic(expected = "Divisor q cannot be zero")]
    fn test_ceil_zero_divisor_panics() {
        let _ = ceil(5, 0);
    }

    #[test]
    fn test_slice_from_start_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        // input: [65, 66, 67, 68, 69] ('A'..'E')
        let input: Vec<FpVar<F>> = [65u64, 66, 67, 68, 69]
            .iter()
            .map(|&v| FpVar::new_witness(cs.clone(), || Ok(F::from(v))).unwrap())
            .collect();

        let length = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(3u64))).unwrap();
        let pad = FpVar::<F>::zero();
        let result = slice_from_start(&input, &length, 5, &pad).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 5);

        // First 3 should be input values, last 2 should be pad (0)
        let vals: Vec<u64> = result
            .iter()
            .map(|v| v.value().unwrap().into_bigint().as_ref()[0])
            .collect();
        assert_eq!(vals[0], 65); // 'A'
        assert_eq!(vals[1], 66); // 'B'
        assert_eq!(vals[2], 67); // 'C'
    }

    #[test]
    fn test_slice_from_start_full_length() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input: Vec<FpVar<F>> = (1..=5u64)
            .map(|v| FpVar::new_witness(cs.clone(), || Ok(F::from(v))).unwrap())
            .collect();

        let length = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        let pad = FpVar::<F>::zero();
        let result = slice_from_start(&input, &length, 5, &pad).unwrap();

        assert!(cs.is_satisfied().unwrap());
        for (i, r) in result.iter().enumerate() {
            let v = r.value().unwrap().into_bigint().as_ref()[0];
            assert_eq!(v, (i + 1) as u64);
        }
    }
}
