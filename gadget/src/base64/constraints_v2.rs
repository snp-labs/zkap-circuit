use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;

use crate::{
    base64::{
        Base64TableVar,
        mod_v2::{Base64CharBits, IndexBits},
    },
    utils::select_array_element_be,
};

/// Base64CharBits의 회로 변수 표현. 6bits 여야함.
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
    pub fn decode(
        table: &Base64TableVar<F>,
        enc_asciis: &[FpVar<F>],
        index_bits: &IndexBitsVar<F>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(enc_asciis.len(), index_bits.inner.len());

        let mut result = Vec::with_capacity(enc_asciis.len() / 4 * 3);

        for (enc_chunk, bits_chunk) in enc_asciis.chunks(4).zip(index_bits.inner.chunks(4)) {
            let chunk_index_bits = IndexBitsVar {
                inner: bits_chunk.to_vec(),
            };
            let (decoded, _all_valid) =
                Self::encoded_chunk_to_decoded_chunk(table, enc_chunk, &chunk_index_bits)?;

            result.extend(decoded);
        }

        Ok(result)
    }

    pub fn decode_v2(
        table: &Base64TableVar<F>,
        enc_asciis: &[FpVar<F>],
        index_bits: &IndexBitsVar<F>,
    ) -> Result<(Vec<FpVar<F>>, Boolean<F>), SynthesisError> {
        assert_eq!(enc_asciis.len(), index_bits.inner.len());

        let mut all_bits = Vec::with_capacity(enc_asciis.len() / 4 * 3);
        let mut all_valid = Boolean::constant(true);

        for (enc_chunk, bits_chunk) in enc_asciis.chunks(4).zip(index_bits.inner.chunks(4)) {
            let (decoded, chunk_valid) =
                Self::encoded_chunk_to_decoded_chunk_v2(table, enc_chunk, bits_chunk)?;

            all_bits.extend(decoded);
            all_valid = all_valid & chunk_valid;
        }

        let result = all_bits
            .chunks_mut(8)
            .map(|chunk| {
                chunk.reverse();
                Boolean::le_bits_to_fp(chunk)
            })
            .collect::<Result<Vec<FpVar<F>>, _>>()?;

        Ok((result, all_valid))
    }

    fn encoded_chunk_to_decoded_chunk_v2(
        table: &Base64TableVar<F>,
        encoded_chunk: &[FpVar<F>],
        encoded_chunk_indices: &[Base64CharBitsVar<F>],
    ) -> Result<(Vec<Boolean<F>>, Boolean<F>), SynthesisError> {
        assert_eq!(encoded_chunk.len(), encoded_chunk_indices.len());

        let mut all_bits = Vec::new();
        let mut all_valid = Boolean::constant(true);

        for (enc_ascii, value_bits_witness) in
            encoded_chunk.iter().zip(encoded_chunk_indices.iter())
        {
            let expected_ascii = Self::select_array_element_table(table, value_bits_witness)?;

            let is_valid = expected_ascii.is_eq(enc_ascii)?;

            all_bits.extend_from_slice(&value_bits_witness.bits);
            all_valid = all_valid & is_valid;
        }

        Ok((all_bits, all_valid))
    }

    fn encoded_chunk_to_decoded_chunk(
        table: &Base64TableVar<F>,
        encoded_chunk: &[FpVar<F>],
        index_bits: &IndexBitsVar<F>,
    ) -> Result<(Vec<FpVar<F>>, Boolean<F>), SynthesisError> {
        let mut all_bits = Vec::new();
        let mut all_valid = Boolean::constant(true);

        for (enc_ascii, value_bits_witness) in encoded_chunk.iter().zip(index_bits.inner.iter()) {
            let expected_ascii = Self::select_array_element_table(table, value_bits_witness)?;

            let is_valid = expected_ascii.is_eq(enc_ascii)?;

            all_bits.extend_from_slice(&value_bits_witness.bits);
            all_valid = all_valid & is_valid;
        }

        let result = all_bits
            .chunks_mut(8)
            .map(|chunk| {
                chunk.reverse();
                Boolean::le_bits_to_fp(chunk)
            })
            .collect::<Result<Vec<FpVar<F>>, _>>()?;

        Ok((result, all_valid))
    }

    /// 비트 인덱스(Big-Endian)를 사용하여 배열에서 요소를 선택합니다.
    ///
    /// 입력 `idx_bits`는 [MSB, ..., LSB] 순서여야 합니다.
    /// `idx_bits[0]`(MSB)를 기준으로 상위 절반(Right)과 하위 절반(Left)을 재귀적으로 분할합니다.
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
    use crate::base64::{get_base64_table, mod_v2::IndexBits};
    use ark_r1cs_std::{R1CSVar, prelude::AllocationMode};
    use ark_relations::r1cs::ConstraintSystem;

    type F = ark_bn254::Fr;

    #[test]
    fn test_base64_decoder_v2_basic() {
        let cs = ConstraintSystem::<F>::new_ref();

        // "TWFu" -> "Man" in base64
        let input = "TWFu";
        let padded_len = 4;

        // 1. Base64 테이블 생성
        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();

        // 2. IndexBits 생성 (witness)
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // 3. 인코딩된 ASCII 값 생성
        let enc_asciis: Vec<FpVar<F>> = input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        // 4. 디코딩 수행
        let result = Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // 5. 검증
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(result.len(), 3);

        // "Man" = [77, 97, 110]
        let expected = vec![
            FpVar::new_witness(cs.clone(), || Ok(F::from(77u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(97u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(110u64))).unwrap(),
        ];

        for (i, (r, e)) in result.iter().zip(expected.iter()).enumerate() {
            r.enforce_equal(e).unwrap();
            println!(
                "Byte {}: {} (expected {})",
                i,
                r.value().unwrap(),
                e.value().unwrap()
            );
        }

        println!("Number of constraints: {}", cs.num_constraints());
    }

    #[test]
    fn test_base64_decoder_v2_longer() {
        let cs = ConstraintSystem::<F>::new_ref();

        // "SGVsbG8=" -> "Hello" (7 chars without padding '=', but we pad to 8)
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

        // Pad the input to 8 characters
        let mut padded_input = input.to_string();
        padded_input.push('A'); // Padding with 'A' (index 0)

        let enc_asciis: Vec<FpVar<F>> = padded_input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let result = Base64DecoderGadget::decode(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(cs.is_satisfied().unwrap());

        // 8 base64 chars -> 6 bytes output
        println!("Decoded {} bytes", result.len());
        println!("Number of constraints: {}", cs.num_constraints());
    }

    // ========== decode_v2 테스트 ==========

    #[test]
    fn test_decode_v2_success_basic() {
        let cs = ConstraintSystem::<F>::new_ref();

        // "TWFu" -> "Man" in base64
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

        let (result, is_valid) =
            Base64DecoderGadget::decode_v2(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // 검증: 올바른 입력이므로 is_valid는 true여야 함
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(is_valid.value().unwrap(), true);
        assert_eq!(result.len(), 3);

        // "Man" = [77, 97, 110]
        let expected_values = vec![77u64, 97u64, 110u64];
        for (i, (r, &expected)) in result.iter().zip(expected_values.iter()).enumerate() {
            let actual = r.value().unwrap().into_bigint().0[0];
            assert_eq!(actual, expected);
            println!("Byte {}: {} (expected {})", i, actual, expected);
        }

        println!("✓ decode_v2 성공 케이스 - 제약조건 수: {}", cs.num_constraints());
    }

    #[test]
    fn test_decode_v2_success_longer() {
        let cs = ConstraintSystem::<F>::new_ref();

        // "QUJDRA==" -> "ABCD" (8 chars with padding)
        let input = "QUJDRA";
        let padded_len = 8;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();

        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // Pad to 8 characters
        let mut padded_input = input.to_string();
        while padded_input.len() < 8 {
            padded_input.push('A');
        }

        let enc_asciis: Vec<FpVar<F>> = padded_input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let (result, is_valid) =
            Base64DecoderGadget::decode_v2(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(is_valid.value().unwrap(), true);
        
        // 8 base64 chars -> 6 bytes output
        assert_eq!(result.len(), 6);
        println!("✓ decode_v2 긴 입력 성공 - 디코딩된 바이트 수: {}", result.len());
        println!("  제약조건 수: {}", cs.num_constraints());
    }

    #[test]
    fn test_decode_v2_failure_wrong_ascii() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 올바른 인덱스: "TWFu" -> [19, 22, 5, 46] (T, W, F, u)
        let input = "TWFu";
        let padded_len = 4;

        let table = get_base64_table();
        let table_var =
            Base64TableVar::new_variable(cs.clone(), || Ok(&table), AllocationMode::Constant)
                .unwrap();

        // 올바른 인덱스 비트 생성
        let index_bits = IndexBits::from_base64_url(input, padded_len).unwrap();
        let index_bits_var =
            IndexBitsVar::new_variable(cs.clone(), || Ok(&index_bits), AllocationMode::Witness)
                .unwrap();

        // 잘못된 ASCII 값 제공: "XXXX" 대신 입력
        let wrong_input = "XXXX";
        let enc_asciis: Vec<FpVar<F>> = wrong_input
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let (_result, is_valid) =
            Base64DecoderGadget::decode_v2(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // 검증: 잘못된 입력이므로 is_valid는 false여야 함
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(is_valid.value().unwrap(), false);
        
        println!("✓ decode_v2 실패 케이스 (잘못된 ASCII) - is_valid: false");
        println!("  제약조건은 여전히 만족됨 (soft validation)");
    }

    #[test]
    fn test_decode_v2_failure_partial_mismatch() {
        let cs = ConstraintSystem::<F>::new_ref();

        // "TWFu" 중 일부만 틀린 경우
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

        // 첫 번째 문자만 틀린 경우: "XWFu"
        let partial_wrong = "XWFu";
        let enc_asciis: Vec<FpVar<F>> = partial_wrong
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let (_result, is_valid) =
            Base64DecoderGadget::decode_v2(&table_var, &enc_asciis, &index_bits_var).unwrap();

        // 부분 불일치도 전체 is_valid가 false가 되어야 함
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(is_valid.value().unwrap(), false);
        
        println!("✓ decode_v2 실패 케이스 (부분 불일치) - is_valid: false");
        println!("  하나의 문자라도 틀리면 전체 검증 실패");
    }

    #[test]
    fn test_decode_v2_failure_all_wrong() {
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

        // 모든 문자가 틀린 경우
        let all_wrong = "----";
        let enc_asciis: Vec<FpVar<F>> = all_wrong
            .as_bytes()
            .iter()
            .map(|&byte| FpVar::new_witness(cs.clone(), || Ok(F::from(byte as u64))).unwrap())
            .collect();

        let (_result, is_valid) =
            Base64DecoderGadget::decode_v2(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(is_valid.value().unwrap(), false);
        
        println!("✓ decode_v2 실패 케이스 (전체 불일치) - is_valid: false");
    }

    #[test]
    fn test_decode_v2_edge_case_empty_like() {
        let cs = ConstraintSystem::<F>::new_ref();

        // 모두 'A' (index 0)로 채워진 경우 - 유효한 입력
        let input = "AAAA";
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

        let (result, is_valid) =
            Base64DecoderGadget::decode_v2(&table_var, &enc_asciis, &index_bits_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(is_valid.value().unwrap(), true);
        assert_eq!(result.len(), 3);
        
        // "AAAA" decodes to [0, 0, 0]
        for (i, r) in result.iter().enumerate() {
            let actual = r.value().unwrap().into_bigint().0[0];
            assert_eq!(actual, 0);
            println!("Byte {}: {}", i, actual);
        }
        
        println!("✓ decode_v2 엣지 케이스 (모두 A) - is_valid: true");
    }

    #[test]
    fn test_decode_v2_constraint_count_comparison() {
        // decode vs decode_v2 제약조건 비교
        println!("\n=== decode vs decode_v2 제약조건 비교 ===");
        
        for input_len in [4, 8, 16, 32] {
            let input_str = "A".repeat(input_len);
            
            // decode 테스트
            let cs1 = ConstraintSystem::<F>::new_ref();
            let table = get_base64_table();
            let table_var1 =
                Base64TableVar::new_variable(cs1.clone(), || Ok(&table), AllocationMode::Constant)
                    .unwrap();
            let index_bits = IndexBits::from_base64_url(&input_str, input_len).unwrap();
            let index_bits_var1 =
                IndexBitsVar::new_variable(cs1.clone(), || Ok(&index_bits), AllocationMode::Witness)
                    .unwrap();
            let enc_asciis1: Vec<FpVar<F>> = input_str
                .as_bytes()
                .iter()
                .map(|&byte| FpVar::new_witness(cs1.clone(), || Ok(F::from(byte as u64))).unwrap())
                .collect();
            
            let _result1 = Base64DecoderGadget::decode(&table_var1, &enc_asciis1, &index_bits_var1).unwrap();
            let constraints1 = cs1.num_constraints();
            
            // decode_v2 테스트
            let cs2 = ConstraintSystem::<F>::new_ref();
            let table_var2 =
                Base64TableVar::new_variable(cs2.clone(), || Ok(&table), AllocationMode::Constant)
                    .unwrap();
            let index_bits_var2 =
                IndexBitsVar::new_variable(cs2.clone(), || Ok(&index_bits), AllocationMode::Witness)
                    .unwrap();
            let enc_asciis2: Vec<FpVar<F>> = input_str
                .as_bytes()
                .iter()
                .map(|&byte| FpVar::new_witness(cs2.clone(), || Ok(F::from(byte as u64))).unwrap())
                .collect();
            
            let (_result2, _is_valid) = Base64DecoderGadget::decode_v2(&table_var2, &enc_asciis2, &index_bits_var2).unwrap();
            let constraints2 = cs2.num_constraints();
            
            println!("입력 길이: {} chars", input_len);
            println!("  decode:    {} constraints", constraints1);
            println!("  decode_v2: {} constraints", constraints2);
            println!("  차이:      {} constraints", constraints2 as i32 - constraints1 as i32);
        }
    }
}
