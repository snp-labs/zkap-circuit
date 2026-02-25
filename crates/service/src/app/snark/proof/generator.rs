#![allow(dead_code)]

use std::path::PathBuf;

use ark_crypto_primitives::snark::SNARK;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, ProvingKey};
use circuit::{
    baerae::BaeraeLightWeightCircuit,
    AnchorWitnessData, AudienceWitnessData, BaeraeCircuitInput, CircuitConstants,
    CircuitPublicInputs, JwtWitnessData, MerkleWitnessData, MiscWitnessData,
};
use common::constants::{BN254, BNP, CG, F, ZkPasskeyConfig};
use common::io::load_key_uncompressed;
use rand::rngs::OsRng;

use crate::app::snark::context::CircuitInput;
use crate::app::snark::types::CircuitContext;
use crate::error::ApplicationError;

/// 증명 생성 결과
pub struct ProofOutput {
    /// 생성된 증명들
    pub proofs: Vec<Proof<BN254>>,

    /// 각 증명의 공개 입력
    pub public_inputs: Vec<Vec<F>>,
}

/// 증명 생성기
///
/// CircuitInput들을 받아 Groth16 증명을 생성합니다.
pub struct ProofGenerator<Config: ZkPasskeyConfig> {
    pk_path: PathBuf,
    circuit_ctx: CircuitContext<Config>,
}

impl<Config: ZkPasskeyConfig> ProofGenerator<Config> {
    /// 새로운 ProofGenerator 생성
    pub fn new(pk_path: PathBuf, circuit_ctx: CircuitContext<Config>) -> Self {
        Self { pk_path, circuit_ctx }
    }

    /// 모든 CircuitInput에 대해 증명 생성 (기본 모드)
    pub fn generate(&self, inputs: &[CircuitInput]) -> Result<ProofOutput, ApplicationError> {
        log::info!("[ProofGenerator] Starting proof generation for {} inputs...", inputs.len());

        let pk = self.load_proving_key()?;
        let mut rng = OsRng;
        
        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_inputs = Vec::with_capacity(inputs.len());

        for (i, input) in inputs.iter().enumerate() {
            log::info!("[ProofGenerator] Generating proof {}/{}...", i + 1, inputs.len());

            let circuit = self.build_circuit(input);
            public_inputs.push(input.extract_public_inputs());

            let proof = Groth16::<BN254>::prove(&pk, circuit, &mut rng)
                .map_err(|e| ApplicationError::InvalidFormat(format!("Proof generation failed: {}", e)))?;

            proofs.push(proof);
        }

        log::info!("[ProofGenerator] All proofs generated successfully");
        Ok(ProofOutput { proofs, public_inputs })
    }

    /// 스트리밍 모드로 증명 생성 (메모리 최적화)
    #[cfg(feature = "use-optimized")]
    pub fn generate_streaming(&self, inputs: &[CircuitInput]) -> Result<ProofOutput, ApplicationError> {
        log::info!("[ProofGenerator] Starting streaming proof generation...");

        let pk = self.load_proving_key()?;
        let mut rng = OsRng;

        let mut proofs = Vec::with_capacity(inputs.len());
        let mut public_inputs = Vec::with_capacity(inputs.len());

        for (i, input) in inputs.iter().enumerate() {
            log::info!("[ProofGenerator] Streaming proof {}/{}...", i + 1, inputs.len());

            // Phase A: Witness + H 계산
            let circuit_factory = self.make_circuit_factory(input);
            let (h, instance, w) = Groth16::<BN254>::create_proof_part1_witness_h(circuit_factory)
                .map_err(|e| ApplicationError::InvalidFormat(format!("Part 1 failed: {}", e)))?;

            public_inputs.push(instance[1..].to_vec());

            // Phase B: MSM
            let r = F::rand(&mut rng);
            let s = F::rand(&mut rng);

            let proof = Groth16::<BN254>::create_proof_part2_msm(&pk, r, s, &h, &instance, &w)
                .map_err(|e| ApplicationError::InvalidFormat(format!("Part 2 failed: {}", e)))?;

            proofs.push(proof);
        }

        log::info!("[ProofGenerator] Streaming generation completed");
        Ok(ProofOutput { proofs, public_inputs })
    }

    /// ProvingKey 로드
    fn load_proving_key(&self) -> Result<ProvingKey<BN254>, ApplicationError> {
        load_key_uncompressed::<ProvingKey<BN254>>(&self.pk_path)
            .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to load proving key: {}", e)))
    }

    /// CircuitInput에서 회로 생성 (새 API 사용)
    fn build_circuit(&self, input: &CircuitInput) -> BaeraeLightWeightCircuit<CG, BNP, Config> {
        let circuit_input = self.to_baerae_circuit_input(input);
        BaeraeLightWeightCircuit::<CG, BNP, Config>::from_input(circuit_input)
    }

    /// CircuitInput을 BaeraeCircuitInput으로 변환
    fn to_baerae_circuit_input(&self, input: &CircuitInput) -> BaeraeCircuitInput<F> {
        BaeraeCircuitInput {
            constants: CircuitConstants {
                vandermonde_matrix: self.circuit_ctx.vandermonde_matrix.clone(),
                poseidon_param: self.circuit_ctx.poseidon_params.clone(),
                base64_table: self.circuit_ctx.base64_table.clone(),
            },
            public_inputs: CircuitPublicInputs {
                hanchor: input.public.hanchor,
                h_a: input.public.h_a,
                root: input.public.root,
                h_sign_user_op: input.public.h_sign_user_op,
                jwt_exp: input.public.jwt_exp,
                partial_rhs: input.public.partial_rhs,
                lhs: input.public.lhs,
                h_aud_list: input.public.h_aud_list,
            },
            jwt: JwtWitnessData {
                midstate: input.jwt.state.clone(),
                nblocks: input.jwt.nblocks,
                token_claim: input.jwt.claim_indices.clone(),
                payload_offset_b64: input.jwt.pay_offset_b64,
                payload_len_b64: input.jwt.pay_len_b64,
                sha_pad_payload_b64: input.jwt.sha_pad_payload_b64.clone(),
                index_bits: input.jwt.index_bits.clone(),
                pk_op: input.jwt.pk.clone(),
                signature_op: input.jwt.sig.clone(),
                total_len: input.jwt.total_len,
                pre_hash_block_len: input.jwt.pre_hash_block_len,
                pad_start_in_suffix: input.jwt.pad_start_in_suffix,
            },
            anchor: AnchorWitnessData {
                anchor: input.anchor.anchor.clone(),
                a: input.anchor.a.clone(),
                indices: input.anchor.selector.clone(),
                current_idx: input.anchor.current_idx,
            },
            merkle: MerkleWitnessData {
                path: input.merkle.path.clone(),
                leaf_idx: input.merkle.leaf_idx,
            },
            audience: AudienceWitnessData {
                aud_list: input.aud_list.clone(),
            },
            misc: MiscWitnessData {
                random: input.random,
            },
        }
    }

    /// 스트리밍용 회로 팩토리 생성
    #[cfg(feature = "use-optimized")]
    fn make_circuit_factory(
        &self,
        input: &CircuitInput,
    ) -> impl FnMut() -> BaeraeLightWeightCircuit<CG, BNP, Config> {
        let circuit_input = self.to_baerae_circuit_input(input);

        move || {
            BaeraeLightWeightCircuit::<CG, BNP, Config>::from_input(circuit_input.clone())
        }
    }
}
