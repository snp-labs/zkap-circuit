use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;

use crate::base64::Base64Table;
use crate::utils::select_array_element;

/// Optimized base64 decoder using witness bits
pub fn base64_decoder<F: PrimeField>(
    table: &[FpVar<F>],
    enc_asciis: &[FpVar<F>],
    bits_witness: &[[Boolean<F>; 6]],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    assert_eq!(enc_asciis.len(), bits_witness.len());
    assert!(enc_asciis.len() % 4 == 0);

    let mut result = Vec::with_capacity(enc_asciis.len() / 4 * 3);
    for (enc_chunk, bits_witness_chunk) in enc_asciis.chunks(4).zip(bits_witness.chunks(4)) {
        let out = encoded_chunk_to_decoded_chunk(table, enc_chunk, bits_witness_chunk)?;
        result.extend_from_slice(&out);
    }
    Ok(result)
}

/// Non-optimized base64 decoder that searches through the table
/// This version doesn't use witness bits, instead it searches the table for each character
pub fn base64_decoder_unopt<F: PrimeField>(
    table: &[FpVar<F>],
    enc_asciis: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    assert_eq!(table.len(), 64);
    assert!(enc_asciis.len() % 4 == 0);

    let mut result = Vec::with_capacity(enc_asciis.len() / 4 * 3);
    for enc_chunk in enc_asciis.chunks(4) {
        let out = encoded_chunk_to_decoded_chunk_unopt(table, enc_chunk)?;
        result.extend_from_slice(&out);
    }
    Ok(result)
}

fn encoded_chunk_to_decoded_chunk<F: PrimeField>(
    table: &[FpVar<F>],
    encoded_chunk: &[FpVar<F>],
    bits_witness: &[[Boolean<F>; 6]],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut all_bits = Vec::with_capacity(4 * 6);

    for (enc_ascii, value_bits_witness) in encoded_chunk.iter().zip(bits_witness.iter()) {
        verify_6bit_value_le(table, enc_ascii, value_bits_witness)?;

        let value_bits_witness_reversed =
            value_bits_witness.iter().rev().cloned().collect::<Vec<_>>();

        all_bits.extend_from_slice(&value_bits_witness_reversed);
    }

    let result = all_bits
        .chunks_mut(8)
        .map(|chunk| {
            chunk.reverse();
            Boolean::le_bits_to_fp(chunk)
        })
        .collect::<Result<Vec<FpVar<F>>, _>>()?;

    Ok(result)
}

fn encoded_chunk_to_decoded_chunk_unopt<F: PrimeField>(
    table: &[FpVar<F>],
    encoded_chunk: &[FpVar<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut all_bits = Vec::with_capacity(4 * 6);

    for enc_ascii in encoded_chunk.iter() {
        // Search through the table to find the index
        let value_bits = find_index_in_table(table, enc_ascii)?;

        let value_bits_reversed = value_bits.iter().rev().cloned().collect::<Vec<_>>();
        all_bits.extend_from_slice(&value_bits_reversed);
    }

    let result = all_bits
        .chunks_mut(8)
        .map(|chunk| {
            chunk.reverse();
            Boolean::le_bits_to_fp(chunk)
        })
        .collect::<Result<Vec<FpVar<F>>, _>>()?;

    Ok(result)
}

/// Find the index of enc_ascii in the table by checking equality with each element
/// Returns the 6-bit representation of the index
fn find_index_in_table<F: PrimeField>(
    table: &[FpVar<F>],
    enc_ascii: &FpVar<F>,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    assert_eq!(table.len(), 64);

    // Create indicator variables for each table position
    let mut indicators = Vec::with_capacity(64);
    for table_entry in table.iter() {
        let is_equal = enc_ascii.is_eq(table_entry)?;
        indicators.push(is_equal);
    }

    // Enforce that exactly one indicator is true
    let sum = indicators
        .iter()
        .fold(FpVar::Constant(F::zero()), |acc, ind| {
            acc + FpVar::from(ind.clone())
        });
    sum.enforce_equal(&FpVar::Constant(F::one()))?;

    // Compute the 6-bit index from indicators
    let mut index_bits = Vec::with_capacity(6);
    for bit_pos in 0..6 {
        let mut bit_value = Boolean::FALSE;
        for (i, indicator) in indicators.iter().enumerate() {
            if (i >> bit_pos) & 1 == 1 {
                bit_value = &bit_value | indicator;
            }
        }
        index_bits.push(bit_value);
    }

    Ok(index_bits)
}

/// Witness로 제공된 6비트 값을 검증하고, 해당 비트를 반환 (회로 내)
/// Prover는 입력 `enc_ascii`에 해당하는 올바른 6비트 값(`value_bits_witness`)을 제공해야 함
fn verify_6bit_value_le<F: PrimeField>(
    table: &[FpVar<F>],                // Base64 ASCII 테이블 (상수)
    enc_ascii: &FpVar<F>,              // 입력 Base64 문자 (ASCII)
    value_bits_witness: &[Boolean<F>], // Prover가 제공하는 6비트 값 (witness)
) -> Result<(), SynthesisError> {
    // 1. Witness로 제공된 6비트 인덱스를 사용하여 테이블에서 예상되는 ASCII 값 선택
    //    select_array_element는 테이블 크기(64)에 맞는 인덱스 비트(6개) 필요
    let expected_ascii = select_array_element(table, value_bits_witness)?;

    // 2. 입력된 ASCII 값과 테이블에서 선택된 예상 ASCII 값이 같은지 강제
    enc_ascii.enforce_equal(&expected_ascii)?;

    // 값 자체를 반환할 필요 없이, 검증만 수행하고 witness로 받은 비트를 사용
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Base64TableVar<F: PrimeField> {
    pub table: Vec<FpVar<F>>,
}

impl<F> Base64TableVar<F>
where
    F: PrimeField,
{
    pub fn decode(
        &self,
        enc_asciis: &[FpVar<F>],
        bits_witness: &[[Boolean<F>; 6]],
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        base64_decoder(&self.table, enc_asciis, bits_witness)
    }
}

impl<F> AllocVar<Base64Table, F> for Base64TableVar<F>
where
    F: PrimeField,
{
    fn new_variable<T: std::borrow::Borrow<Base64Table>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let table = val.borrow().table.iter();
            let table_vars = table
                .map(|&byte| FpVar::new_variable(cs.clone(), || Ok(F::from(byte as u64)), mode))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Self { table: table_vars })
        })
    }
}

pub fn encoded_table<F: PrimeField>() -> Vec<FpVar<F>> {
    let str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    str.bytes().map(|b| FpVar::Constant(F::from(b))).collect()
}

#[cfg(test)]
mod tests {
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};

    use crate::base64::utils::base64_to_6bit_bools;

    use super::{
        base64_decoder, base64_decoder_unopt, encoded_chunk_to_decoded_chunk, encoded_table,
        verify_6bit_value_le,
    };
    type F = ark_bn254::Fr;

    fn test_base64_decoder(enc: &str) {
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let table = encoded_table::<F>();
        let enc_bytes = enc.as_bytes();
        let input_bits = base64_to_6bit_bools(enc.as_bytes()).unwrap();

        let enc_asciis: Vec<FpVar<F>> = enc_bytes
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();
        let bits_witnesss = input_bits
            .chunks(6)
            .map(|bits| {
                bits.iter()
                    .map(|&bit| Boolean::new_witness(cs.clone(), || Ok(bit)).unwrap())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<[Boolean<F>; 6]>>();
        let result = base64_decoder(&table, &enc_asciis, &bits_witnesss).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
        // println!("result: {:?}", result.value().unwrap());
        println!("result_len: {:?}", result.len());
    }

    #[test]
    fn test_base64_decoder_opt_trivial1() {
        let enc = "TWFu";
        let enc = enc.repeat(1);
        test_base64_decoder(&enc);
    }

    fn test_base64_decoder_unopt(enc: &str) {
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let table = encoded_table::<F>();
        let enc_bytes = enc.as_bytes();

        let enc_asciis: Vec<FpVar<F>> = enc_bytes
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let result = base64_decoder_unopt(&table, &enc_asciis).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!(
            "number of constraints (unoptimized): {}",
            cs.num_constraints()
        );
        println!("result_len: {:?}", result.len());
    }

    #[test]
    fn test_base64_decoder_unopt_trivial1() {
        let enc = "TWFu";
        let enc = enc.repeat(1);
        test_base64_decoder_unopt(&enc);
    }

    #[test]
    fn test_compare_opt_vs_unopt() {
        println!("\n=== Comparing Optimized vs Unoptimized Base64 Decoder ===\n");

        let test_cases = vec![
            ("TWFu", 1), // 4 chars (1 chunk)
            ("TWFu", 2), // 8 chars (2 chunks)
            ("TWFu", 4), // 16 chars (4 chunks)
            ("TWFu", 8), // 32 chars (8 chunks)
        ];

        for (base, repeat) in test_cases {
            let enc = base.repeat(repeat);
            let num_chars = enc.len();

            println!(
                "Testing with {} characters ({} chunks):",
                num_chars,
                num_chars / 4
            );

            // Test optimized version
            let cs_opt = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
            let table = encoded_table::<F>();
            let enc_bytes = enc.as_bytes();
            let input_bits = base64_to_6bit_bools(enc.as_bytes()).unwrap();

            let enc_asciis_opt: Vec<FpVar<F>> = enc_bytes
                .iter()
                .map(|&byte| {
                    FpVar::new_witness(cs_opt.clone(), || Ok(F::from(byte as u64))).unwrap()
                })
                .collect();
            let bits_witnesss = input_bits
                .chunks(6)
                .map(|bits| {
                    bits.iter()
                        .map(|&bit| Boolean::new_witness(cs_opt.clone(), || Ok(bit)).unwrap())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap()
                })
                .collect::<Vec<[Boolean<F>; 6]>>();

            let _result_opt = base64_decoder(&table, &enc_asciis_opt, &bits_witnesss).unwrap();
            assert!(cs_opt.is_satisfied().unwrap());
            let constraints_opt = cs_opt.num_constraints();

            // Test unoptimized version
            let cs_unopt = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
            let table = encoded_table::<F>();
            let enc_asciis_unopt: Vec<FpVar<F>> = enc_bytes
                .iter()
                .map(|&byte| {
                    FpVar::new_witness(cs_unopt.clone(), || Ok(F::from(byte as u64))).unwrap()
                })
                .collect();

            let _result_unopt = base64_decoder_unopt(&table, &enc_asciis_unopt).unwrap();
            assert!(cs_unopt.is_satisfied().unwrap());
            let constraints_unopt = cs_unopt.num_constraints();

            println!("  Optimized:     {} constraints", constraints_opt);
            println!("  Unoptimized:   {} constraints", constraints_unopt);
            println!(
                "  Difference:    {} constraints",
                constraints_unopt as i64 - constraints_opt as i64
            );
            println!(
                "  Ratio:         {:.2}x\n",
                constraints_unopt as f64 / constraints_opt as f64
            );
        }
    }

    #[test]
    fn test_encoded_chunk_to_decoded_chunk1() {
        let table = encoded_table::<F>();
        let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
        let enc = "TWFu";
        let enc_bytes = enc.as_bytes();

        let input_bits: [[bool; 6]; 4] = [
            [true, true, false, false, true, false],  // T
            [false, true, true, false, true, false],  // W
            [true, false, true, false, false, false], // F
            [false, true, true, true, false, true],   // u
        ];

        let bits_witness: [[Boolean<F>; 6]; 4] = input_bits
            .iter()
            .map(|bits| {
                bits.iter()
                    .map(|&bit| Boolean::new_witness(cs.clone(), || Ok(bit)).unwrap())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        println!("bits_witness_constraints: {:?}", cs.num_constraints());
        let enc_chunk: Vec<FpVar<F>> = enc_bytes
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();
        let result = encoded_chunk_to_decoded_chunk(&table, &enc_chunk, &bits_witness).unwrap();
        assert!(cs.is_satisfied().unwrap());
        println!("number of constraints: {}", cs.num_constraints());
        println!("result: {:?}", result.value().unwrap());
        println!(
            "str: {:?}",
            // String::from_utf8([130, 66, 194].to_vec()).unwrap()
            b"ABC"
        );
    }

    #[test]
    fn test_verify_and_get_6bit_value() {
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        let table = encoded_table::<F>();

        for (i, char) in chars.iter().enumerate() {
            let cs = ark_relations::r1cs::ConstraintSystem::<F>::new_ref();
            let enc_ascii = FpVar::new_witness(cs.clone(), || Ok(F::from(*char as u64))).unwrap();
            let value_bits_witness = (0..6)
                .map(|j| Boolean::new_witness(cs.clone(), || Ok((i >> j) & 1 == 1)))
                .collect::<Result<Vec<Boolean<F>>, _>>()
                .unwrap();

            // Call the function to verify and get the 6-bit value
            verify_6bit_value_le(&table, &enc_ascii, &value_bits_witness).unwrap();
            assert!(cs.is_satisfied().unwrap());
            println!(
                "char: {:?}, bits: {:?}",
                str.chars().nth(i).unwrap(),
                value_bits_witness.value().unwrap()
            );
        }
    }
}
