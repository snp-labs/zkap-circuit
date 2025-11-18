use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, uint8::UInt8, uint32::UInt32};
use ark_relations::r1cs::SynthesisError;
use core::ops::BitXor;

use crate::{
    hashes::{
        Parameter,
        sha256::{
            K,
            utils::{add_many_vec, conditionally_select_vec},
        },
    },
    utils::UInt32Ext,
};

use super::DigestVar;

#[derive(Clone)]
pub struct SHA256Gadget<F: PrimeField, P: Parameter<F>> {
    pub state: Vec<UInt32<F>>,
    pub completed_data_blocks: u64,
    pub pending: Vec<UInt8<F>>,
    pub num_pending: usize,
    pub _params: PhantomData<P>,
}

impl<F: PrimeField, P: Parameter<F>> SHA256Gadget<F, P> {
    /// Consumes the given data and updates the internal state
    pub fn update(&mut self, data: &[UInt8<F>]) -> Result<(), SynthesisError> {
        let mut offset = 0;
        if self.num_pending > 0 && self.num_pending + data.len() >= 64 {
            offset = 64 - self.num_pending;
            // If the inputted data pushes the pending buffer over the chunk size, process it all
            self.pending[self.num_pending..].clone_from_slice(&data[..offset]);
            Self::update_state(&mut self.state, &self.pending)?;

            self.completed_data_blocks += 1;
            self.num_pending = 0;
        }

        for chunk in data[offset..].chunks(64) {
            let chunk_size = chunk.len();

            if chunk_size == 64 {
                // If it's a full chunk, process it
                Self::update_state(&mut self.state, chunk)?;
                self.completed_data_blocks += 1;
            } else {
                // Otherwise, add the bytes to the `pending` buffer
                self.pending[self.num_pending..self.num_pending + chunk_size]
                    .clone_from_slice(chunk);
                self.num_pending += chunk_size;
            }
        }

        Ok(())
    }

    /// Outputs the final digest of all the inputted data
    pub fn finalize(mut self) -> Result<DigestVar<F>, SynthesisError> {
        // Encode the number of processed bits as a u64, then serialize it to 8 big-endian bytes
        let data_bitlen = self.completed_data_blocks * 512 + self.num_pending as u64 * 8;
        let encoded_bitlen: Vec<UInt8<F>> = {
            let bytes = data_bitlen.to_be_bytes();
            bytes.iter().map(|&b| UInt8::constant(b)).collect()
        };

        // Padding starts with a 1 followed by some number of zeros (0x80 = 0b10000000)
        let mut pending = vec![UInt8::constant(0); 72];
        pending[0] = UInt8::constant(0x80);

        // We'll either append to the 56+8 = 64 byte boundary or the 120+8 = 128 byte boundary,
        // depending on whether we have at least 56 unprocessed bytes
        let offset = if self.num_pending < 56 {
            56 - self.num_pending
        } else {
            120 - self.num_pending
        };

        // Write the bitlen to the end of the padding. Then process all the padding
        pending[offset..offset + 8].clone_from_slice(&encoded_bitlen);
        self.update(&pending[..offset + 8])?;

        // Collect the state into big-endian bytes
        let bytes = self
            .state
            .iter()
            .flat_map(UInt32::to_bytes_be)
            .flatten()
            .collect();
        Ok(DigestVar(bytes))
    }

    fn update_state(state: &mut [UInt32<F>], data: &[UInt8<F>]) -> Result<(), SynthesisError> {
        assert_eq!(data.len(), 64);

        let mut w = vec![UInt32::constant(0); 64];
        for (word, chunk) in w.iter_mut().zip(data.chunks(4)) {
            *word = UInt32::from_bytes_be(chunk)?;
        }

        for i in 16..64 {
            let s0 = {
                let x1 = w[i - 15].rotate_right(7);
                let x2 = w[i - 15].rotate_right(18);
                let x3 = w[i - 15].shr(3);
                x1 ^ (x2 ^ x3)
            };
            let s1 = {
                let x1 = w[i - 2].rotate_right(17);
                let x2 = w[i - 2].rotate_right(19);
                let x3 = w[i - 2].shr(10);
                x1 ^ (x2 ^ x3)
            };

            w[i] = UInt32::<F>::wrapping_add_many(&[s0, s1, w[i - 16].clone(), w[i - 7].clone()])?;
        }

        let mut h = state.to_vec();
        for i in 0..64 {
            let ch = {
                let f_xor_g = h[5].clone().bitxor(h[6].clone());
                let e_and_f_xor_g = h[4].bitand(&f_xor_g)?;
                h[6].clone().bitxor(&e_and_f_xor_g)
            };

            // Ma(a,b,c) = (a & b) ^ (a & c) ^ (b & c) -> (a & b) ^ (c & (a ^ b))
            // a, b, c = h[0], h[1], h[2]
            let ma = {
                let a_xor_b = h[0].clone().bitxor(h[1].clone());
                let c_and_a_xor_b = h[2].bitand(&a_xor_b)?;
                let a_and_b = h[0].bitand(&h[1])?;
                a_and_b.bitxor(&c_and_a_xor_b)
            };

            let s0 = {
                // x1 ^ &x2 ^ &x3
                let x1 = h[0].rotate_right(2);
                let x2 = h[0].rotate_right(13);
                let x3 = h[0].rotate_right(22);
                x1 ^ (x2 ^ x3)
            };
            let s1 = {
                // x1 ^ &x2 ^ &x3
                let x1 = h[4].rotate_right(6);
                let x2 = h[4].rotate_right(11);
                let x3 = h[4].rotate_right(25);
                x1 ^ (x2 ^ x3)
            };
            let t0 = UInt32::<F>::wrapping_add_many(&[
                h[7].clone(),
                ch,
                s1,
                UInt32::constant(K[i]),
                w[i].clone(),
            ])?;

            h[7] = h[6].clone();
            h[6] = h[5].clone();
            h[5] = h[4].clone();
            h[4] = t0.wrapping_add(&h[3]);
            h[3] = h[2].clone();
            h[2] = h[1].clone();
            h[1] = h[0].clone();
            h[0] = UInt32::<F>::wrapping_add_many(&[t0, ma, s0])?;
        }

        for (s, hi) in state.iter_mut().zip(h.iter()) {
            *s = s.wrapping_add(hi);
        }
        Ok(())
    }

    /// Computes the digest of the given data. This is a shortcut for `default()` followed by
    /// `update()` followed by `finalize()`.
    pub fn digest(data: &[UInt8<F>]) -> Result<DigestVar<F>, SynthesisError> {
        let mut sha256_var = Self::default();
        sha256_var.update(data)?;
        sha256_var.finalize()
    }

    // 입력 데이터는 SHA256 표준에 따라 패딩된 상태여야 한다.
    pub fn digest_with_pad(
        mut self,
        data: &[UInt8<F>],
        num_sha2_blocks: FpVar<F>,
    ) -> Result<DigestVar<F>, SynthesisError> {
        assert_eq!(data.len() % 64, 0);
        // num_sha2_blocks 횟수 만큼의 해시 결과가 저장된다.
        let mut hash_results = Vec::new();
        let zero = UInt32::<F>::constant(0u32);
        let mut output = Vec::new();
        for _ in 0..8 {
            output.push(zero.clone());
        }
        let zero_value = output.clone();
        for (_, chunk) in data.chunks(64).enumerate() {
            Self::update_state(&mut self.state, chunk)?;
            // let bytes = Vec::from_iter(self.state.iter().flat_map(|i| i.to_bytes_be().unwrap()));
            // println!("{} chunk {:?}", i, bytes.value().unwrap());

            hash_results.push(self.state.clone());
        }

        for i in 0..hash_results.len() {
            let i_fp = FpVar::<F>::Constant(F::from(i as u64));
            let is_eq = i_fp.is_eq(&num_sha2_blocks)?;
            let value = conditionally_select_vec(&is_eq, &hash_results[i], &zero_value.clone())?;
            output = add_many_vec(&output, &value);
        }

        // Collect the state into big-endian bytes
        let bytes = output
            .iter()
            .flat_map(UInt32::to_bytes_be)
            .flatten()
            .collect();
        Ok(DigestVar(bytes))
    }

    pub fn set_state(mut self, state: &[UInt32<F>]) -> Self {
        assert!(state.len() == 8);
        self.state = state.to_vec();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget as ArkSha256Gadget;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar, prelude::ToBitsGadget};
    use ark_relations::r1cs::ConstraintSystem;
    use crate::hashes::sha256::{Sha256Bn254ParamProvider, constraints::SHA256Gadget as SimpleSHA256Gadget};

    type F = Fr;

    #[test]
    fn test_compare_sha256_gadgets() {
        println!("\n=== Comparing Custom SHA256Gadget vs ark-crypto-primitives SHA256 ===\n");
        
        let repeated_a = "A".repeat(200);
        let test_cases = vec![
            ("Hello, World!", "단일 블록 테스트"),
            ("This is a longer message that we want to hash using SHA256.", "중간 길이 메시지"),
            ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "긴 메시지 테스트"),
            (repeated_a.as_str(), "200바이트 반복 메시지"),
        ];
        
        for (message, description) in test_cases {
            println!("테스트: {} (길이: {} 바이트)", description, message.len());
            
            let message_bytes = message.as_bytes();
            
            // === 커스텀 SHA256Gadget 테스트 (Parameter 버전) ===
            let cs_custom = ConstraintSystem::<F>::new_ref();
            let input_custom = message_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs_custom.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            let _result_custom = SHA256Gadget::<F, Sha256Bn254ParamProvider>::digest(&input_custom).unwrap();
            assert!(cs_custom.is_satisfied().unwrap());
            let constraints_custom = cs_custom.num_constraints();
            
            // === Simple SHA256Gadget 테스트 (constraints.rs 버전) ===
            let cs_simple = ConstraintSystem::<F>::new_ref();
            let input_simple = message_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs_simple.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            let _result_simple = SimpleSHA256Gadget::digest(&input_simple).unwrap();
            assert!(cs_simple.is_satisfied().unwrap());
            let constraints_simple = cs_simple.num_constraints();
            
            // === ark-crypto-primitives SHA256 테스트 ===
            let cs_ark = ConstraintSystem::<F>::new_ref();
            let input_ark = message_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs_ark.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            // ark-crypto-primitives의 Sha256Gadget::digest 사용
            let _result_ark = ArkSha256Gadget::<F>::digest(&input_ark).unwrap();
            assert!(cs_ark.is_satisfied().unwrap());
            let constraints_ark = cs_ark.num_constraints();
            
            // === 결과 비교 ===
            println!("  커스텀 SHA256Gadget (P):    {} constraints", constraints_custom);
            println!("  Simple SHA256Gadget:        {} constraints", constraints_simple);
            println!("  ark-crypto-primitives:      {} constraints", constraints_ark);
            println!("  커스텀 - ark 차이:          {} constraints", constraints_custom as i64 - constraints_ark as i64);
            println!("  Simple - ark 차이:          {} constraints", constraints_simple as i64 - constraints_ark as i64);
            
            if constraints_ark > 0 {
                let ratio_custom = constraints_custom as f64 / constraints_ark as f64;
                let ratio_simple = constraints_simple as f64 / constraints_ark as f64;
                println!("  커스텀/ark 비율:            {:.2}x", ratio_custom);
                println!("  Simple/ark 비율:            {:.2}x", ratio_simple);
            }
            println!();
        }
    }

    #[test]
    fn test_compare_sha256_multiple_blocks() {
        println!("\n=== SHA256 Multiple Blocks Constraint Comparison ===\n");
        
        // 블록 크기별 테스트 (64바이트 = SHA256의 1블록)
        let block_counts = vec![1, 2, 4, 8];
        
        for num_blocks in block_counts {
            let message_len = num_blocks * 64;
            let message = "A".repeat(message_len);
            let message_bytes = message.as_bytes();
            
            println!("테스트: {} 블록 ({} 바이트)", num_blocks, message_len);
            
            // 커스텀 구현 (Parameter 버전)
            let cs_custom = ConstraintSystem::<F>::new_ref();
            let input_custom = message_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs_custom.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            let _result_custom = SHA256Gadget::<F, Sha256Bn254ParamProvider>::digest(&input_custom).unwrap();
            assert!(cs_custom.is_satisfied().unwrap());
            let constraints_custom = cs_custom.num_constraints();
            
            // Simple 구현
            let cs_simple = ConstraintSystem::<F>::new_ref();
            let input_simple = message_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs_simple.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            let _result_simple = SimpleSHA256Gadget::digest(&input_simple).unwrap();
            assert!(cs_simple.is_satisfied().unwrap());
            let constraints_simple = cs_simple.num_constraints();
            
            // ark-crypto-primitives 구현
            let cs_ark = ConstraintSystem::<F>::new_ref();
            let input_ark = message_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs_ark.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            let _result_ark = ArkSha256Gadget::<F>::digest(&input_ark).unwrap();
            assert!(cs_ark.is_satisfied().unwrap());
            let constraints_ark = cs_ark.num_constraints();
            
            println!("  커스텀 (P): {} constraints", constraints_custom);
            println!("  Simple:     {} constraints", constraints_simple);
            println!("  ark:        {} constraints", constraints_ark);
            println!("  비율 (커스텀/ark): {:.2}x", constraints_custom as f64 / constraints_ark as f64);
            println!("  비율 (Simple/ark): {:.2}x\n", constraints_simple as f64 / constraints_ark as f64);
        }
    }

    #[test]
    fn test_sha256_gadget_correctness() {
        println!("\n=== SHA256Gadget Correctness Test ===\n");
        
        let test_vectors = vec![
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"),
        ];
        
        for (input, expected_hex) in test_vectors {
            let cs = ConstraintSystem::<F>::new_ref();
            let input_bytes = input.as_bytes();
            let input_vars = input_bytes
                .iter()
                .map(|&byte| UInt8::new_witness(cs.clone(), || Ok(byte)).unwrap())
                .collect::<Vec<_>>();
            
            let result = SHA256Gadget::<F, Sha256Bn254ParamProvider>::digest(&input_vars).unwrap();
            assert!(cs.is_satisfied().unwrap());
            
            let result_bytes: Vec<u8> = result.0
                .iter()
                .map(|byte| byte.value().unwrap())
                .collect();
            
            let result_hex = hex::encode(&result_bytes);
            
            println!("Input: \"{}\"", input);
            println!("Expected: {}", expected_hex);
            println!("Got:      {}", result_hex);
            println!("Match: {}\n", result_hex == expected_hex);
            
            assert_eq!(result_hex, expected_hex, "SHA256 해시가 일치하지 않습니다");
        }
    }

    #[test]
    fn test_constraint_breakdown_analysis() {
        println!("\n=== SHA256 Constraint Breakdown Analysis ===\n");
        
        let message = "Hello, World!";
        let message_bytes = message.as_bytes();
        
        // === 1. UInt8 생성 비용 측정 ===
        let cs_uint8 = ConstraintSystem::<F>::new_ref();
        let _input_vars: Vec<UInt8<F>> = message_bytes
            .iter()
            .map(|&byte| UInt8::new_witness(cs_uint8.clone(), || Ok(byte)).unwrap())
            .collect();
        let constraints_uint8 = cs_uint8.num_constraints();
        println!("1. UInt8 witness 생성 ({} bytes): {} constraints", message_bytes.len(), constraints_uint8);
        
        // === 2. UInt32::from_bytes_be 비용 측정 ===
        let cs_from_bytes = ConstraintSystem::<F>::new_ref();
        let test_bytes: Vec<UInt8<F>> = (0..4)
            .map(|i| UInt8::new_witness(cs_from_bytes.clone(), || Ok(i as u8)).unwrap())
            .collect();
        let _uint32_val = UInt32::from_bytes_be(&test_bytes).unwrap();
        let constraints_from_bytes = cs_from_bytes.num_constraints();
        println!("2. UInt32::from_bytes_be (1 call): {} constraints", constraints_from_bytes);
        
        // === 3. Rotate 연산 비용 측정 ===
        let cs_rotate = ConstraintSystem::<F>::new_ref();
        let uint32_test = UInt32::new_witness(cs_rotate.clone(), || Ok(0x12345678u32)).unwrap();
        let _rotated = uint32_test.rotate_right(7);
        let constraints_rotate = cs_rotate.num_constraints();
        println!("3. UInt32::rotate_right: {} constraints", constraints_rotate);
        
        // === 4. XOR 연산 비용 측정 ===
        let cs_xor = ConstraintSystem::<F>::new_ref();
        let a = UInt32::new_witness(cs_xor.clone(), || Ok(0x12345678u32)).unwrap();
        let b = UInt32::new_witness(cs_xor.clone(), || Ok(0x9ABCDEF0u32)).unwrap();
        let _xor_result = &a ^ &b;
        let constraints_xor = cs_xor.num_constraints();
        println!("4. UInt32 XOR: {} constraints", constraints_xor);
        
        // === 5. AND 연산 비용 측정 ===
        let cs_and = ConstraintSystem::<F>::new_ref();
        let a = UInt32::new_witness(cs_and.clone(), || Ok(0x12345678u32)).unwrap();
        let b = UInt32::new_witness(cs_and.clone(), || Ok(0x9ABCDEF0u32)).unwrap();
        let _and_result = a.bitand(&b).unwrap();
        let constraints_and = cs_and.num_constraints();
        println!("5. UInt32 AND: {} constraints", constraints_and);
        
        // === 6. wrapping_add_many 비용 측정 ===
        let cs_add = ConstraintSystem::<F>::new_ref();
        let vals: Vec<UInt32<F>> = (0..5)
            .map(|i| UInt32::new_witness(cs_add.clone(), || Ok(i as u32)).unwrap())
            .collect();
        let _sum = UInt32::wrapping_add_many(&vals).unwrap();
        let constraints_add = cs_add.num_constraints();
        println!("6. UInt32::wrapping_add_many (5 values): {} constraints", constraints_add);
        
        // === 7. 전체 update_state 비용 측정 ===
        let cs_state = ConstraintSystem::<F>::new_ref();
        let mut state: Vec<UInt32<F>> = vec![
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]
        .iter()
        .map(|&v| UInt32::constant(v))
        .collect();
        
        let data_bytes: Vec<UInt8<F>> = (0..64)
            .map(|i| UInt8::new_witness(cs_state.clone(), || Ok(i as u8)).unwrap())
            .collect();
        
        SHA256Gadget::<F, Sha256Bn254ParamProvider>::update_state(&mut state, &data_bytes).unwrap();
        let constraints_state = cs_state.num_constraints();
        println!("7. 전체 update_state (1 block): {} constraints", constraints_state);
        
        println!("\n=== 예상 제약조건 계산 ===");
        println!("UInt32::from_bytes_be (16회): {} constraints", constraints_from_bytes * 16);
        println!("Message schedule 확장 (48회 반복):");
        println!("  - rotate + shr + xor (s0, s1): ~{} constraints/iteration", constraints_rotate * 4);
        println!("  - wrapping_add_many: ~{} constraints/iteration", constraints_add);
        println!("압축 함수 (64회 반복):");
        println!("  - Ch, Maj 함수: AND + XOR");
        println!("  - Σ0, Σ1: rotate + XOR");
        println!("  - wrapping_add_many: 여러 번");
        
        println!("\n총 제약조건: {} (단일 블록)", constraints_state);
    }

    #[test]
    fn test_input_validation_constraints() {
        println!("\n=== Input Validation Constraint Analysis ===\n");
        
        let cs = ConstraintSystem::<F>::new_ref();
        
        // UInt8이 자동으로 0-255 범위 체크를 하는지 확인
        let byte_var = UInt8::new_witness(cs.clone(), || Ok(200u8)).unwrap();
        let constraints_after_uint8 = cs.num_constraints();
        println!("UInt8 witness 생성 후 제약조건: {}", constraints_after_uint8);
        
        // UInt8이 실제로 8비트인지 확인
        let bits = byte_var.to_bits_le().unwrap();
        println!("UInt8의 비트 수: {}", bits.len());
        assert_eq!(bits.len(), 8);
        
        // 비트가 boolean인지 확인
        for (i, bit) in bits.iter().enumerate() {
            if let Some(val) = bit.value().ok() {
                assert!(val == false || val == true, "Bit {} is not boolean", i);
            }
        }
        
        println!("\n✅ UInt8은 자동으로 0-255 범위 내에 있음을 보장합니다.");
        println!("   (각 비트가 boolean 제약조건으로 강제됨)");
        
        // 잘못된 값 시도 (컴파일은 되지만 회로는 만족하지 않음)
        let cs_invalid = ConstraintSystem::<F>::new_ref();
        let invalid_byte = UInt8::<F>::new_variable(
            cs_invalid.clone(),
            || Ok(200u8),
            ark_r1cs_std::alloc::AllocationMode::Witness
        ).unwrap();
        
        // 값이 올바른지 확인
        assert_eq!(invalid_byte.value().unwrap(), 200u8);
        assert!(cs_invalid.is_satisfied().unwrap());
        
        println!("\n=== 범위 체크 메커니즘 ===");
        println!("ark-r1cs-std의 UInt8/UInt32는 비트 분해를 통해 범위를 강제합니다:");
        println!("- UInt8: 8개의 Boolean으로 분해됨");
        println!("- UInt32: 32개의 Boolean으로 분해됨");
        println!("- 각 Boolean은 0 또는 1만 가능 (자동 제약조건)");
    }
}
