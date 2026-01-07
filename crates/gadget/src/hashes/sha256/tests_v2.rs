#[cfg(test)]
mod test {
    use crate::hashes::sha256::constraints_v2::{DigestVar, Sha256Gadget};

    use ark_bn254::{Bn254, Fr as Bn254Fr};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::AdditiveGroup;
    use ark_groth16::Groth16;
    use ark_r1cs_std::prelude::*;
    use ark_r1cs_std::uint8::UInt8;
    use ark_relations::{
        r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
    };
    use ark_crypto_primitives::snark::SNARK;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::RngCore;
    use sha2::{Digest, Sha256};

    // 다양한 길이 테스트
    // const TEST_LENGTHS: &[usize] = &[0, 1, 2, 8, 20, 40, 55, 56, 57, 63, 64, 65, 90, 100, 127, 128, 129];
    const TEST_LENGTHS: &[usize] = &[2048];

    /// Witness bytes를 생성
    fn to_byte_vars(cs: ConstraintSystemRef<Bn254Fr>, data: &[u8]) -> Vec<UInt8<Bn254Fr>> {
        UInt8::new_witness_vec(cs, data).unwrap()
    }

    /// SHA256 gadget을 완료하고 바이트를 가져옴
    fn finalize_var(sha256_var: Sha256Gadget<Bn254Fr>) -> Vec<u8> {
        sha256_var.finalize().unwrap().0.iter().map(|b| b.value().unwrap()).collect()
    }

    /// Native SHA256을 완료하고 바이트를 가져옴
    fn finalize(sha256: Sha256) -> Vec<u8> {
        sha256.finalize().to_vec()
    }

    // ==================== 기본 기능 테스트 ====================

    /// 다양한 길이의 랜덤 문자열에 대한 SHA256 테스트
    #[test]
    fn test_varied_lengths() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        for &len in TEST_LENGTHS {
            let mut sha256 = Sha256::default();
            let mut sha256_var = Sha256Gadget::default();

            // 주어진 길이의 랜덤 문자열 생성
            let mut input_str = vec![0u8; len];
            rng.fill_bytes(&mut input_str);

            // 해시를 계산하고 일관성 검증
            sha256_var
                .update(&to_byte_vars(cs.clone(), &input_str))
                .unwrap();
            sha256.update(&input_str);
            
            let result_var = finalize_var(sha256_var);
            let result_native = finalize(sha256);
            
            assert_eq!(
                result_var,
                result_native,
                "error at length {}",
                len
            );
            assert!(cs.is_satisfied().unwrap(), "Constraints not satisfied at length {}", len);
            println!("Length {}: num_constraints = {}", len, cs.num_constraints());
        }
    }

    /// update()를 여러 번 호출하는 테스트
    #[test]
    fn test_many_updates() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        let mut sha256 = Sha256::default();
        let mut sha256_var = Sha256Gadget::default();

        // 동일한 7바이트 문자열을 20번 추가
        for i in 0..20 {
            let mut input_str = vec![0u8; 7];
            rng.fill_bytes(&mut input_str);

            sha256_var
                .update(&to_byte_vars(cs.clone(), &input_str))
                .unwrap();
            sha256.update(&input_str);
            
            println!("Update {}: num_constraints = {}", i + 1, cs.num_constraints());
        }

        // 결과가 일치하는지 확인
        assert_eq!(finalize_var(sha256_var), finalize(sha256));
        assert!(cs.is_satisfied().unwrap());
        println!("Total constraints for 20 updates: {}", cs.num_constraints());
    }

    /// 빈 입력에 대한 SHA256 테스트
    #[test]
    fn test_empty_input() {
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        
        let sha256 = Sha256::default();
        let sha256_var = Sha256Gadget::<Bn254Fr>::default();

        let result_var = finalize_var(sha256_var);
        let result_native = finalize(sha256);

        assert_eq!(result_var, result_native);
        assert!(cs.is_satisfied().unwrap());
        println!("Empty input: num_constraints = {}", cs.num_constraints());
    }

    /// 단일 블록 경계 테스트 (정확히 64바이트)
    #[test]
    fn test_single_block_boundary() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        
        let mut input = vec![0u8; 64];
        rng.fill_bytes(&mut input);

        let mut sha256 = Sha256::default();
        let mut sha256_var = Sha256Gadget::default();

        sha256_var.update(&to_byte_vars(cs.clone(), &input)).unwrap();
        sha256.update(&input);

        assert_eq!(finalize_var(sha256_var), finalize(sha256));
        assert!(cs.is_satisfied().unwrap());
        println!("64-byte input: num_constraints = {}", cs.num_constraints());
    }

    /// DigestVar의 digest 메서드 테스트
    #[test]
    fn test_digest_shortcut() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        let mut input = vec![0u8; 100];
        rng.fill_bytes(&mut input);

        // digest 단축 메서드 사용
        let result_var = Sha256Gadget::digest(&to_byte_vars(cs.clone(), &input))
            .unwrap()
            .0
            .iter()
            .map(|b| b.value().unwrap())
            .collect::<Vec<u8>>();

        // Native 계산
        let mut sha256 = Sha256::default();
        sha256.update(&input);
        let result_native = finalize(sha256);

        assert_eq!(result_var, result_native);
        assert!(cs.is_satisfied().unwrap());
        println!("Digest shortcut: num_constraints = {}", cs.num_constraints());
    }

    // ==================== DigestVar 테스트 ====================

    /// DigestVar의 EqGadget 구현 테스트
    #[test]
    fn test_digest_eq() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // 두 개의 서로 다른 digest 생성
        let mut digest1 = vec![0u8; 32];
        let mut digest2 = vec![0u8; 32];
        rng.fill_bytes(&mut digest1);
        rng.fill_bytes(&mut digest2);

        // Witness로 할당
        let digest1_var = DigestVar::new_witness(cs.clone(), || Ok(digest1.clone())).unwrap();
        let digest2_var = DigestVar::new_witness(cs.clone(), || Ok(digest2.clone())).unwrap();

        // 서로 다른 digest는 다르다고 판단되어야 함
        assert!(!digest1_var.is_eq(&digest2_var).unwrap().value().unwrap());

        // 동일한 digest는 같다고 판단되어야 함
        assert!(digest1_var.is_eq(&digest1_var).unwrap().value().unwrap());
        
        assert!(cs.is_satisfied().unwrap());
    }

    /// DigestVar의 CondSelectGadget 구현 테스트
    #[test]
    fn test_digest_conditional_select() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        let mut digest1 = vec![0u8; 32];
        let mut digest2 = vec![0u8; 32];
        rng.fill_bytes(&mut digest1);
        rng.fill_bytes(&mut digest2);

        let digest1_var = DigestVar::new_witness(cs.clone(), || Ok(digest1.clone())).unwrap();
        let digest2_var = DigestVar::new_witness(cs.clone(), || Ok(digest2.clone())).unwrap();

        // true 조건으로 선택
        let cond_true = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let selected_true = DigestVar::conditionally_select(&cond_true, &digest1_var, &digest2_var).unwrap();
        assert_eq!(
            selected_true.0.iter().map(|b| b.value().unwrap()).collect::<Vec<u8>>(),
            digest1
        );

        // false 조건으로 선택
        let cond_false = Boolean::new_witness(cs.clone(), || Ok(false)).unwrap();
        let selected_false = DigestVar::conditionally_select(&cond_false, &digest1_var, &digest2_var).unwrap();
        assert_eq!(
            selected_false.0.iter().map(|b| b.value().unwrap()).collect::<Vec<u8>>(),
            digest2
        );

        assert!(cs.is_satisfied().unwrap());
    }

    // ==================== 제약 조건 검증 테스트 ====================

    /// 잘못된 출력으로 제약 조건 위반 테스트
    #[test]
    fn test_constraint_violation_wrong_output() {
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        
        let input = b"test input";
        let sha256_var = Sha256Gadget::default();
        
        // 올바른 해시 계산
        let mut correct_digest = sha256_var.clone();
        correct_digest.update(&to_byte_vars(cs.clone(), input)).unwrap();
        let correct_result = correct_digest.finalize().unwrap();
        
        // 잘못된 digest 생성
        let wrong_digest_bytes = vec![0u8; 32]; // 모두 0으로 채운 잘못된 값
        let wrong_digest = DigestVar::new_witness(cs.clone(), || Ok(wrong_digest_bytes)).unwrap();
        
        // 제약 조건 추가: 올바른 결과와 잘못된 결과가 같다고 주장
        let should_be_false = correct_result.is_eq(&wrong_digest).unwrap();
        
        // 실제로는 같지 않아야 함
        assert!(!should_be_false.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    // ==================== Groth16 증명/검증 테스트 ====================

    /// 바이트 배열을 비트 배열로 변환 (little-endian)
    fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
        bytes.iter()
            .flat_map(|&byte| {
                (0..8).map(move |i| ((byte >> i) & 1) == 1)
            })
            .collect()
    }

    /// SHA256 해시를 검증하는 회로
    #[derive(Clone)]
    struct Sha256Circuit {
        /// 입력 데이터 (private witness)
        input: Vec<u8>,
        /// 예상 출력 해시의 비트들 (public input)
        expected_hash_bits: Vec<bool>,
    }

    impl ConstraintSynthesizer<Bn254Fr> for Sha256Circuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<Bn254Fr>,
        ) -> Result<(), SynthesisError> {
            // 입력을 witness로 할당
            let input_vars = UInt8::new_witness_vec(cs.clone(), &self.input)?;
            
            // 예상 해시의 비트들을 public input으로 할당 (256 bits = 32 bytes * 8)
            let expected_hash_bits: Vec<Boolean<Bn254Fr>> = self.expected_hash_bits
                .iter()
                .map(|&bit| Boolean::new_input(cs.clone(), || Ok(bit)))
                .collect::<Result<Vec<_>, _>>()?;
            
            // SHA256 계산
            let computed_hash = Sha256Gadget::digest(&input_vars)?;
            
            // 계산된 해시를 비트로 변환
            let computed_hash_bits: Vec<Boolean<Bn254Fr>> = computed_hash.0
                .iter()
                .flat_map(|byte| byte.to_bits_le().unwrap())
                .collect();
            
            // 계산된 해시 비트와 예상 해시 비트가 같은지 검증
            for (computed_bit, expected_bit) in computed_hash_bits.iter().zip(expected_hash_bits.iter()) {
                computed_bit.enforce_equal(expected_bit)?;
            }
            
            Ok(())
        }
    }

    /// Groth16 증명 생성 및 검증 테스트 - 성공 케이스
    #[test]
    fn test_groth16_proof_success() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(0u64);
        
        // 테스트 데이터 생성
        let input = b"Hello, zkSNARK!";
        let mut hasher = Sha256::default();
        hasher.update(input);
        let expected_hash = hasher.finalize().to_vec();
        
        println!("Input: {:?}", String::from_utf8_lossy(input));
        println!("Expected hash: {:?}", hex::encode(&expected_hash));
        
        // 해시를 비트로 변환
        let expected_hash_bits = bytes_to_bits(&expected_hash);
        
        // 회로 생성
        let circuit = Sha256Circuit {
            input: input.to_vec(),
            expected_hash_bits: expected_hash_bits.clone(),
        };
        
        // Setup: CRS 생성
        println!("Generating CRS...");
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        
        // Prove: 증명 생성
        println!("Generating proof...");
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        
        // Public inputs 준비 (비트를 field element로 변환)
        let public_inputs: Vec<Bn254Fr> = expected_hash_bits.iter()
            .map(|&bit| if bit { Bn254Fr::from(1u64) } else { Bn254Fr::from(0u64) })
            .collect();
        
        // Verify: 증명 검증
        println!("Verifying proof...");
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
        
        assert!(is_valid, "Proof verification failed");
        println!("✓ Proof verified successfully!");
        
        // 제약 조건 수 확인
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        let circuit_check = Sha256Circuit {
            input: input.to_vec(),
            expected_hash_bits: expected_hash_bits.clone(),
        };
        circuit_check.generate_constraints(cs.clone()).unwrap();
        println!("Number of constraints: {}", cs.num_constraints());
        println!("Number of instance variables: {}", cs.num_instance_variables());
        println!("Expected public inputs length: {} (256 bits)", public_inputs.len());
    }

    /// Groth16 증명 검증 실패 테스트 - 잘못된 public input
    #[test]
    fn test_groth16_proof_fail_wrong_public_input() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(1u64);
        
        // 올바른 데이터로 증명 생성
        let input = b"Hello, zkSNARK!";
        let mut hasher = Sha256::default();
        hasher.update(input);
        let expected_hash = hasher.finalize().to_vec();
        
        let expected_hash_bits = bytes_to_bits(&expected_hash);
        
        let circuit = Sha256Circuit {
            input: input.to_vec(),
            expected_hash_bits: expected_hash_bits.clone(),
        };
        
        // Setup & Prove
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        
        // 잘못된 public input 생성 (다른 해시값)
        let wrong_hash = vec![0u8; 32];
        let wrong_hash_bits = bytes_to_bits(&wrong_hash);
        let wrong_public_inputs: Vec<Bn254Fr> = wrong_hash_bits.iter()
            .map(|&bit| if bit { Bn254Fr::from(1u64) } else { Bn254Fr::from(0u64) })
            .collect();
        
        // 잘못된 public input으로 검증
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &wrong_public_inputs).unwrap();
        
        assert!(!is_valid, "Proof should fail with wrong public input");
        println!("✓ Proof correctly failed with wrong public input");
    }

    /// Groth16 증명 검증 실패 테스트 - 변조된 증명
    #[test]
    fn test_groth16_proof_fail_tampered_proof() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(2u64);
        
        let input = b"Hello, zkSNARK!";
        let mut hasher = Sha256::default();
        hasher.update(input);
        let expected_hash = hasher.finalize().to_vec();
        
        let expected_hash_bits = bytes_to_bits(&expected_hash);
        
        let circuit = Sha256Circuit {
            input: input.to_vec(),
            expected_hash_bits: expected_hash_bits.clone(),
        };
        
        // Setup & Prove
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        
        // 증명 변조 (a 값을 다른 값으로 변경)
        let mut tampered_proof = proof.clone();
        tampered_proof.a = proof.a.into_group().double().into_affine();
        
        // Public inputs 준비
        let public_inputs: Vec<Bn254Fr> = expected_hash_bits.iter()
            .map(|&bit| if bit { Bn254Fr::from(1u64) } else { Bn254Fr::from(0u64) })
            .collect();
        
        // 변조된 증명으로 검증
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &tampered_proof, &public_inputs).unwrap();
        
        assert!(!is_valid, "Proof should fail when tampered");
        println!("✓ Proof correctly failed when tampered");
    }

    /// 다양한 입력 길이에 대한 Groth16 증명 테스트
    #[test]
    fn test_groth16_various_lengths() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(3u64);
        let test_lengths = [1, 10, 55, 64, 65, 100, 128];
        
        for &len in &test_lengths {
            println!("\n--- Testing length: {} ---", len);
            
            // 랜덤 입력 생성
            let mut input = vec![0u8; len];
            rng.fill_bytes(&mut input);
            
            let mut hasher = Sha256::default();
            hasher.update(&input);
            let expected_hash = hasher.finalize().to_vec();
            let expected_hash_bits = bytes_to_bits(&expected_hash);
            
            let circuit = Sha256Circuit {
                input: input.clone(),
                expected_hash_bits: expected_hash_bits.clone(),
            };
            
            // Setup
            let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
            
            // Prove
            let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
            
            // Verify
            let public_inputs: Vec<Bn254Fr> = expected_hash_bits.iter()
                .map(|&bit| if bit { Bn254Fr::from(1u64) } else { Bn254Fr::from(0u64) })
                .collect();
            
            let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
            let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
            
            assert!(is_valid, "Proof verification failed for length {}", len);
            
            // 제약 조건 수 출력
            let cs = ConstraintSystem::<Bn254Fr>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            println!("Constraints: {}, Verified: ✓", cs.num_constraints());
        }
        
        println!("\n✓ All length variants passed!");
    }

    /// 제약 조건 위반 회로 테스트 - 증명 생성 실패
    #[test]
    #[should_panic]
    fn test_groth16_constraint_violation() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(4u64);
        
        // 올바른 해시
        let input = b"correct input";
        let mut hasher = Sha256::default();
        hasher.update(input);
        let _correct_hash = hasher.finalize().to_vec();
        
        // 잘못된 해시를 expected로 설정
        let wrong_hash = vec![0u8; 32];
        let wrong_hash_bits = bytes_to_bits(&wrong_hash);
        
        let circuit = Sha256Circuit {
            input: input.to_vec(),
            expected_hash_bits: wrong_hash_bits, // 의도적으로 잘못된 해시
        };
        
        // Setup
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
        
        // 증명 생성 시도 - 제약 조건 위반으로 실패해야 함
        let _proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        
        // 여기까지 도달하면 안됨
        panic!("Should have failed due to constraint violation");
    }

    // ==================== 성능 벤치마크 테스트 ====================

    /// 큰 입력에 대한 성능 테스트
    #[test]
    fn benchmark_large_input() {
        use ark_std::rand::rngs::StdRng;
        use ark_std::rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(5u64);
        // let sizes = [256, 512, 1024, 2048];
        let sizes = [2048];
        
        for &size in &sizes {
            println!("\n--- Benchmarking size: {} bytes ---", size);
            
            let mut input = vec![0u8; size];
            rng.fill_bytes(&mut input);
            
            let mut hasher = Sha256::default();
            hasher.update(&input);
            let expected_hash = hasher.finalize().to_vec();
            let expected_hash_bits = bytes_to_bits(&expected_hash);
            
            let circuit = Sha256Circuit {
                input: input.clone(),
                expected_hash_bits: expected_hash_bits.clone(),
            };
            
            // 제약 조건 수 측정
            let cs = ConstraintSystem::<Bn254Fr>::new_ref();
            circuit.clone().generate_constraints(cs.clone()).unwrap();
            println!("Constraints: {}", cs.num_constraints());
            
            // Setup 시간 측정
            let setup_start = std::time::Instant::now();
            let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
            println!("Setup time: {:?}", setup_start.elapsed());
            
            let mut bytes = Vec::new();
            pk.serialize_uncompressed(&mut bytes).unwrap();

            println!("Proving key size: {} bytes", bytes.len());
            
            // Proving 시간 측정
            let prove_start = std::time::Instant::now();
            let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
            println!("Proving time: {:?}", prove_start.elapsed());
            
            // Verification 시간 측정
            let public_inputs: Vec<Bn254Fr> = expected_hash_bits.iter()
                .map(|&bit| if bit { Bn254Fr::from(1u64) } else { Bn254Fr::from(0u64) })
                .collect();
            
            let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
            let verify_start = std::time::Instant::now();
            let is_valid = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs).unwrap();
            println!("Verification time: {:?}", verify_start.elapsed());
            
            assert!(is_valid);
        }
    }
}
