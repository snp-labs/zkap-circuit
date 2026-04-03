use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean, select::CondSelectGadget,
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    base64::{
        Base64Table,
        decoder::{Base64CharBits, IndexBits},
    },
    utils::select_array_element_be,
};

#[derive(Clone, Debug)]
pub struct Base64TableVar<F: PrimeField> {
    pub table: Vec<FpVar<F>>,
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

/// Circuit variable representation of Base64CharBits. Must have exactly 6 bits.
#[derive(Clone)]
pub struct Base64CharBitsVar<F: PrimeField> {
    pub bits: Vec<Boolean<F>>,
}

pub struct IndexBitsVar<F: PrimeField> {
    pub inner: Vec<Base64CharBitsVar<F>>,
}

pub struct Base64DecoderGadget<F: PrimeField> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: PrimeField> Base64DecoderGadget<F> {
    /// Optimized base64 decoder with hard enforcement.
    ///
    /// Uses hard enforcement instead of soft validation (is_valid Boolean chain),
    /// direct enforce_equal, saving ~3 constraints per character.
    ///
    /// NULL padding handling: enc_ascii=0 is normalized to 'A'(65) before
    /// enforcement. This ensures index_bits must be 0 for padding positions
    /// (any other index_bits would produce expected != 65, failing enforce_equal).
    pub fn decode(
        table: &Base64TableVar<F>,
        enc_asciis: &[FpVar<F>],
        index_bits: &IndexBitsVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(enc_asciis.len(), index_bits.inner.len());
        assert!(enc_asciis.len().is_multiple_of(4));

        let padding_char = FpVar::Constant(F::from(65u8)); // ASCII 'A'
        let zero = FpVar::Constant(F::zero());
        let mut all_bits = Vec::with_capacity(enc_asciis.len() * 6);

        for (enc_ascii, char_bits) in enc_asciis.iter().zip(index_bits.inner.iter()) {
            let expected_ascii = Self::select_array_element_table(table, char_bits)?;

            let is_zero = enc_ascii.is_eq(&zero)?;
            let normalized =
                CondSelectGadget::conditionally_select(&is_zero, &padding_char, enc_ascii)?;

            normalized.enforce_equal(&expected_ascii)?;

            all_bits.extend_from_slice(&char_bits.bits);
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

    /// Selects an element from an array using a Big-Endian bit index.
    ///
    /// The input `idx_bits` must be in [MSB, ..., LSB] order.
    /// Recursively splits into upper half (Right) and lower half (Left) based on `idx_bits[0]` (MSB).
    fn select_array_element_table(
        table: &Base64TableVar<F>,
        idx_bits: &Base64CharBitsVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        assert_eq!(table.table.len(), 64);
        assert_eq!(idx_bits.bits.len(), 6);

        select_array_element_be(&table.table, &idx_bits.bits)
    }
}

impl<F: PrimeField> AllocVar<Base64CharBits, F> for Base64CharBitsVar<F> {
    fn new_variable<T: std::borrow::Borrow<Base64CharBits>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            assert_eq!(
                val.borrow().bits.len(),
                6,
                "Base64CharBits must have exactly 6 bits"
            );

            let bits = val
                .borrow()
                .bits
                .iter()
                .map(|b| Boolean::new_variable(cs.clone(), || Ok(*b), mode))
                .collect::<Result<Vec<Boolean<F>>, SynthesisError>>()?;

            Ok(Self { bits })
        })
    }
}

impl<F: PrimeField> AllocVar<IndexBits, F> for IndexBitsVar<F> {
    fn new_variable<T: std::borrow::Borrow<IndexBits>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        f().and_then(|val| {
            let inner = val
                .borrow()
                .inner
                .iter()
                .map(|char_bits| {
                    Base64CharBitsVar::new_variable(cs.clone(), || Ok(char_bits), mode)
                })
                .collect::<Result<Vec<Base64CharBitsVar<F>>, SynthesisError>>()?;
            Ok(Self { inner })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64::{decoder::IndexBits, get_base64_table};
    use ark_r1cs_std::{R1CSVar, prelude::AllocationMode};
    use ark_relations::r1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

    #[test]
    fn test_decode_basic() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = "TWFu";
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();
        let enc_asciis: Vec<FpVar<F>> = input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 3);

        // "Man" = [77, 97, 110]
        let expected_values = vec![77u64, 97u64, 110u64];
        for (i, (r, &expected)) in result.iter().zip(expected_values.iter()).enumerate() {
            let actual = r.value().unwrap().into_bigint().0[0];
            assert_eq!(actual, expected, "Byte {} mismatch", i);
        }
        println!("decode basic: {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_decode_longer() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = "SGVsbG8";
        let padded_len = 8;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        let mut padded_input = input.to_string();
        padded_input.push('A');
        let enc_asciis: Vec<FpVar<F>> = padded_input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 6);
        println!("decode longer: {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_decode_failure_wrong_ascii() {
        let cs = ConstraintSystem::<F>::new_ref();
        let input = "TWFu";
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // Wrong ASCII: "XXXX" instead of "TWFu"
        let wrong_input = "XXXX";
        let enc_asciis: Vec<FpVar<F>> = wrong_input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let _result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // Hard enforcement: constraint system must be unsatisfied
        assert!(!cs.is_satisfied().unwrap());
        println!("decode wrong ascii: correctly unsatisfied");
    }

    #[test]
    fn test_decode_failure_partial_mismatch() {
        let cs = ConstraintSystem::<F>::new_ref();
        let correct_input = "TWFu";
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(correct_input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // First char wrong: "XWFu"
        let partial_wrong = "XWFu";
        let enc_asciis: Vec<FpVar<F>> = partial_wrong
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let _result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(!cs.is_satisfied().unwrap());
        println!("decode partial mismatch: correctly unsatisfied");
    }

    #[test]
    fn test_decode_null_padding() {
        let cs = ConstraintSystem::<F>::new_ref();
        // "TW" with 2 NULL padding positions
        let input = "TW";
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // enc_asciis: 'T', 'W', 0 (NULL), 0 (NULL)
        let enc_bytes: Vec<u8> = vec![b'T', b'W', 0, 0];
        let enc_asciis: Vec<FpVar<F>> = enc_bytes
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // NULL padding with index_bits=0 ('A') should satisfy constraints
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 3);
        println!("decode null padding: satisfied, {} constraints", cs.num_constraints());
    }

    #[test]
    fn test_decode_null_padding_wrong_bits() {
        let cs = ConstraintSystem::<F>::new_ref();
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();

        // Manually create index_bits: first 2 valid, last 2 with non-zero bits (attack)
        let mut index_bits = IndexBits::from_base64_url("TW", padded_len).unwrap();
        // Tamper: set padding position index to 1 ('B') instead of 0 ('A')
        index_bits.inner[2] = crate::base64::decoder::Base64CharBits::from_index(1);
        index_bits.inner[3] = crate::base64::decoder::Base64CharBits::from_index(1);

        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // enc_asciis: 'T', 'W', 0 (NULL), 0 (NULL)
        let enc_bytes: Vec<u8> = vec![b'T', b'W', 0, 0];
        let enc_asciis: Vec<FpVar<F>> = enc_bytes
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let _result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // Soundness: NULL + wrong index_bits → normalized='A'(65) but expected=table[1]='B'(66)
        // enforce_equal fails → constraint system unsatisfied
        assert!(!cs.is_satisfied().unwrap());
        println!("decode null padding wrong bits: correctly unsatisfied (soundness)");
    }

    #[test]
    fn test_decode_constraint_count() {
        println!("\n=== decode constraint count measurement ===");

        for input_len in [4, 8, 16, 32] {
            let input_str = "A".repeat(input_len);

            let cs = ConstraintSystem::<F>::new_ref();
            let table = get_base64_table();
            let table_var =
                Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                    .unwrap();
            let index_bits = IndexBits::from_base64_url(&input_str, input_len).unwrap();
            let index_bits_var = IndexBitsVar::new_variable(
                cs.clone(),
                || Ok(&index_bits),
                AllocationMode::Witness,
            )
            .unwrap();
            let enc_asciis: Vec<FpVar<F>> = input_str
                .as_bytes()
                .iter()
                .map(|&byte| {
                    FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap()
                })
                .collect();
            let _result =
                Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var)
                    .unwrap();
            let constraints = cs.num_constraints();
            let per_char = constraints as f64 / input_len as f64;

            assert!(cs.is_satisfied().unwrap());
            println!("Input length: {} chars → {} constraints ({:.1}/char)", input_len, constraints, per_char);
        }
    }

    #[test]
    fn test_decode_standard_chars() {
        // Test all base64url alphabet in 4-char chunks
        let cs = ConstraintSystem::<F>::new_ref();
        let table = get_base64_table();

        // "ABCD" — first 4 chars of base64 alphabet
        for input in &["ABCD", "EFGH", "IJKL", "MNOP", "QRST", "UVWX", "YZab", "cdef",
                       "ghij", "klmn", "opqr", "stuv", "wxyz", "0123", "4567", "89-_"] {
            let cs = ConstraintSystem::<F>::new_ref();
            let table_var =
                Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                    .unwrap();
            let index_bits = IndexBits::from_base64_url(input, 4).unwrap();
            let index_bits_var =
                IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                    .unwrap();
            let enc_asciis: Vec<FpVar<F>> = input
                .as_bytes()
                .iter()
                .map(|&b| FpVar::new_witness(cs.clone(), || Ok(F::from(b as u64))).unwrap())
                .collect();
            let _result =
                Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();
            assert!(cs.is_satisfied().unwrap(), "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_decode_tampered_output_rejected() {
        use ark_r1cs_std::eq::EqGadget;

        let cs = ConstraintSystem::<F>::new_ref();
        let input = "TWFu";
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();
        let enc_asciis: Vec<FpVar<F>> = input
            .as_bytes()
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(F::from(b as u64))).unwrap())
            .collect();

        let result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Tamper: enforce result[0] == 0 (should be 77='M')
        let wrong = FpVar::new_witness(cs.clone(), || Ok(F::from(0u64))).unwrap();
        result[0].enforce_equal(&wrong).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_decode_max_length() {
        let cs = ConstraintSystem::<F>::new_ref();
        // 32 chars of valid base64url
        let input = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";
        let padded_len = 32;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();
        let enc_asciis: Vec<FpVar<F>> = input
            .as_bytes()
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(F::from(b as u64))).unwrap())
            .collect();

        let result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 24); // 32 * 6 / 8 = 24 bytes
    }

    #[test]
    fn test_decode_url_safe_chars() {
        // '-' and '_' are base64url specific (index 62 and 63)
        let cs = ConstraintSystem::<F>::new_ref();
        let table = get_base64_table();

        // Construct input that uses '-' and '_'
        // '-' is ASCII 45, '_' is ASCII 95
        let input = "AB-_"; // contains url-safe chars
        let padded_len = 4;

        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();
        let enc_asciis: Vec<FpVar<F>> = input
            .as_bytes()
            .iter()
            .map(|&b| FpVar::new_witness(cs.clone(), || Ok(F::from(b as u64))).unwrap())
            .collect();

        let _result =
            Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
