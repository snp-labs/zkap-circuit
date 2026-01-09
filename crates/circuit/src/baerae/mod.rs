#![allow(unused_variables)]

use ark_crypto_primitives::{
    crh::{
        CRHSchemeGadget,
        poseidon::{self, constraints::CRHGadget as PoseidonCRHGadget},
    },
    merkle_tree::{Path, constraints::PathVar},
    sponge::{Absorb, poseidon::PoseidonConfig},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBitsGadget, ToBytesGadget},
    uint8::UInt8,
    uint16::UInt16,
};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::*;
use std::marker::PhantomData;

use crate::{
    ExposesPublicInputs,
    token::{
        ClaimIndices,
        claimverifier::claim_extractor_v2,
        constraints::{ClaimIndicesVar, RSA2048VerifyGadget},
    },
};
use common::constants::ZkPasskeyConfig;
use gadget::{
    anchor::poseidon::{
        PoseidonAnchor,
        constraints::{PoseidonAnchorSchemeGadget, PoseidonAnchorVar},
    },
    base64::{
        Base64Table, Base64TableVar,
        constraints_v2::{Base64DecoderGadget, IndexBitsVar},
        get_base64_table,
        mod_v2::IndexBits,
    },
    bigint::constraints::BigNatCircuitParams,
    hashes::{
        poseidon::{constraints::chain_hash_gadget, get_poseidon_params},
        sha256::constraints::SHA256Gadget,
    },
    matrix::{VandermondeMatrix, constraints_v2::VandermondeMatrixVar},
    mekletree::tree_config::{Empty, MerkleTreeParams, MerkleTreeParamsVar},
    signature::rsa::{
        gadget::{PublicKeyVar, SignatureVar},
        native::{PublicKey, Signature},
    },
    utils::{
        bit_bytes_v2::pack_decompose_bytes_unchecked,
        comparison_v2::is_less_than,
        single_multiplexer, slice_v2,
        string_v2::{jwt_exp_to_field, jwt_nonce_hex_to_field},
    },
};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    // constants
    pub vandermonde_matrix: VandermondeMatrix<C::BaseField>,
    pub poseidon_param: PoseidonConfig<C::BaseField>,
    pub base64_table: Base64Table,

    // public inputs
    pub hanchor: C::BaseField,
    pub h_ctx: C::BaseField,
    pub root: C::BaseField,
    pub h_sign_user_op: C::BaseField,
    pub block_timestamp: C::BaseField,
    pub partial_rhs: C::BaseField,
    pub lhs: C::BaseField,
    pub h_aud_list: C::BaseField,

    // witnesses
    pub random: C::BaseField,
    pub leaf_idx: usize,
    pub path: Path<MerkleTreeParams<C::BaseField>>,
    pub anchor: PoseidonAnchor<C::BaseField>,
    pub midstate: Vec<u32>,
    pub nblocks: usize,
    pub token_claim: Vec<ClaimIndices>,
    pub payload_offset_b64: usize,
    pub payload_len_b64: usize,
    pub sha_pad_payload_b64: Vec<u8>,
    pub index_bits: IndexBits,
    pub pk_op: PublicKey,
    pub signature_op: Signature,
    pub a: Vec<C::BaseField>,
    pub indices: Vec<u8>,
    pub current_idx: usize,
    pub aud_list: Vec<C::BaseField>,

    // phantom
    _phantom: PhantomData<(BNP, Config)>,
}

impl<C, BNP, Config> ConstraintSynthesizer<C::BaseField>
    for BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> ark_relations::r1cs::Result<()> {
        assert!(self.indices.len() == Config::N);
        // Implement the constraint generation logic here

        let initial_constraints = cs.num_constraints();
        let vandermonde_matrix = VandermondeMatrixVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.vandermonde_matrix,
        )?;

        let poseidon_param = poseidon::constraints::CRHParametersVar::<C::BaseField>::new_constant(
            cs.clone(),
            self.poseidon_param,
        )?;

        let base64_table =
            Base64TableVar::<C::BaseField>::new_constant(cs.clone(), self.base64_table)?;

        let hanchor = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.hanchor))?;

        let h_ctx = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.h_ctx))?;

        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.root))?;

        let h_sign_user_op =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.h_sign_user_op))?;

        let block_timestamp =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.block_timestamp))?;

        let partial_rhs = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.partial_rhs))?;

        let lhs = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.lhs))?;

        let h_aud_list = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.h_aud_list))?;

        let random = FpVar::<C::BaseField>::new_witness(cs.clone(), || Ok(self.random))?;

        let leaf_idx =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.leaf_idx as u16))?;

        let mut path = PathVar::<
            MerkleTreeParams<C::BaseField>,
            C::BaseField,
            MerkleTreeParamsVar<C::BaseField>,
        >::new_witness(cs.clone(), || Ok(self.path))?;

        let anchor =
            PoseidonAnchorVar::<C::BaseField>::new_witness(cs.clone(), || Ok(self.anchor))?;

        let mut midstate =
            SHA256Gadget::<C::BaseField>::new_witness(cs.clone(), || Ok(self.midstate))?;

        let nblocks = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(C::BaseField::from(self.nblocks as u64))
        })?;

        let token_claim =
            Vec::<ClaimIndicesVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.token_claim))?;

        let payload_offset_b64 =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.payload_offset_b64 as u16))?;

        let payload_len_b64 =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.payload_len_b64 as u16))?;

        let sha_pad_payload_b64 = Vec::<UInt8<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self
                .sha_pad_payload_b64
                .iter()
                .map(|&b| b)
                .collect::<Vec<u8>>())
        })?;

        let index_bits =
            IndexBitsVar::<C::BaseField>::new_witness(cs.clone(), || Ok(self.index_bits))?;

        let pk_op = PublicKeyVar::<C::BaseField, BNP>::new_witness(cs.clone(), || Ok(self.pk_op))?;

        let signature_op =
            SignatureVar::<C::BaseField, BNP>::new_witness(cs.clone(), || Ok(self.signature_op))?;

        let a = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.a))?;

        let indices = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || {
            Ok(self
                .indices
                .iter()
                .map(|&i| C::BaseField::from(i as u64))
                .collect::<Vec<C::BaseField>>())
        })?;

        let current_idx = FpVar::<C::BaseField>::new_witness(cs.clone(), || {
            Ok(C::BaseField::from(self.current_idx as u64))
        })?;

        let aud_list = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || Ok(self.aud_list))?;

        let after_allocation = cs.num_constraints();

        #[cfg(feature = "num-cs-logging")]
        {
            println!("=== Baerae Circuit Constraint Analysis ===");
            println!("Initial constraints: {}", initial_constraints);
            println!(
                "\n[Setup] Variable allocation: {} constraints",
                after_allocation - initial_constraints
            );
        }

        // [Phase 1: Integrity] JWT 서명 검증 (RSA Verification)
        let phase1_start = cs.num_constraints();
        let rsa_start = cs.num_constraints();
        let mut digest = midstate
            .digest_with_pad(&sha_pad_payload_b64, nblocks)?
            .to_bytes_le()?;
        let result = RSA2048VerifyGadget::verify(&mut digest, &signature_op, &pk_op)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "RSA Verification",
            &[result.clone()],
            &[Boolean::constant(true)],
        );

        result.enforce_equal(&Boolean::constant(true))?;

        #[cfg(feature = "num-cs-logging")]
        {
            let rsa_end = cs.num_constraints();
            println!("  - RSA Verification: {} constraints", rsa_end - rsa_start);
        }

        // [Phase 1] Payload 슬라이싱 및 Base64 디코딩
        let base64_start = cs.num_constraints();
        let sha_pad_payload_b64_to_fp = sha_pad_payload_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<ark_relations::r1cs::Result<Vec<_>>>()?;
        let payload_b64 = slice_v2::slice_efficient(
            &sha_pad_payload_b64_to_fp,
            &payload_offset_b64,
            &payload_len_b64,
            Config::MAX_PAYLOAD_B64_LEN,
        )?;

        let (payload, valid) = Base64DecoderGadget::<C::BaseField>::decode_v2(
            &base64_table,
            &payload_b64,
            &index_bits,
        )?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Base64 Decoding Valid",
            &[valid.clone()],
            &[Boolean::constant(true)],
        );

        valid.enforce_equal(&Boolean::constant(true))?;

        #[cfg(feature = "num-cs-logging")]
        {
            let base64_end = cs.num_constraints();
            println!(
                "  - Base64 Decoding: {} constraints",
                base64_end - base64_start
            );
        }

        // [Phase 1] Claims 값 추출 (Extraction)
        let claims_start = cs.num_constraints();
        let aud_bytes = claim_extractor_v2("aud", &payload, &token_claim[0], Config::MAX_AUD_LEN)?;
        let exp_bytes = claim_extractor_v2("exp", &payload, &token_claim[1], Config::MAX_EXP_LEN)?;
        let iss_bytes = claim_extractor_v2("iss", &payload, &token_claim[2], Config::MAX_ISS_LEN)?;
        let nonce_bytes =
            claim_extractor_v2("nonce", &payload, &token_claim[3], Config::MAX_NONCE_LEN)?;
        let sub_bytes = claim_extractor_v2("sub", &payload, &token_claim[4], Config::MAX_SUB_LEN)?;
        // [Phase 1] Field Element로 변환 및 패킹 (Packing)
        let aud = pack_decompose_bytes_unchecked(&aud_bytes)?;
        let exp = jwt_exp_to_field(&exp_bytes)?;
        let iss = pack_decompose_bytes_unchecked(&iss_bytes)?;

        let last_quote_index = token_claim[3]
            .value_len
            .wrapping_add(&UInt16::constant(u16::MAX));
        let nonce = jwt_nonce_hex_to_field(&nonce_bytes, &last_quote_index)?;
        let sub = pack_decompose_bytes_unchecked(&sub_bytes)?;

        #[cfg(feature = "num-cs-logging")]
        {
            let claims_end = cs.num_constraints();
            println!(
                "  - Claims Extraction: {} constraints",
                claims_end - claims_start
            );
        }

        #[cfg(feature = "num-cs-logging")]
        {
            let phase1_end = cs.num_constraints();
            println!(
                "[Phase 1] JWT Integrity Total: {} constraints",
                phase1_end - phase1_start
            );
        }

        // [Phase 2: Validation] OP Key가 유효한지 Merkle Proof로 검증
        let phase2_start = cs.num_constraints();
        let merkle_start = cs.num_constraints();
        let leaf_inputs = vec![iss.clone(), pk_op.n.limbs.clone()].concat();
        let leaf = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &leaf_inputs)?;
        path.set_leaf_position(leaf_idx.to_bits_le()?);
        let result = path.verify_membership(&poseidon_param, &poseidon_param, &root, &[leaf])?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Merkle Proof Verification",
            &[result.clone()],
            &[Boolean::constant(true)],
        );

        result.enforce_equal(&Boolean::constant(true))?;

        #[cfg(feature = "num-cs-logging")]
        {
            let merkle_end = cs.num_constraints();
            println!(
                "  - Merkle Proof: {} constraints",
                merkle_end - merkle_start
            );
        }
        // [Phase 2] 토큰 만료 시간 확인 (block_timer < exp)
        // ark-r1cs-std의 비교 함수 버그로 인해, a_le_b를 사용합니다.
        let expiry_start = cs.num_constraints();
        let result = is_less_than(
            &block_timestamp.to_bits_le_with_top_bits_zero(64)?.0,
            &exp.to_bits_le_with_top_bits_zero(64)?.0,
        )?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Expiry Check",
            &[result.clone()],
            &[Boolean::constant(true)],
        );

        result.enforce_equal(&Boolean::constant(true))?;

        #[cfg(feature = "num-cs-logging")]
        {
            let expiry_end = cs.num_constraints();
            println!(
                "  - Expiry Check: {} constraints",
                expiry_end - expiry_start
            );
        }

        // [Phase 2] Nonce 바인딩 확인 (nonce == Poseidon(SignUserOpHash, random))
        let nonce_start = cs.num_constraints();
        let mut nonce_inputs = Vec::<FpVar<C::BaseField>>::new();
        nonce_inputs.push(h_sign_user_op);
        nonce_inputs.push(random.clone());
        let target_nonce =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &nonce_inputs)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq("Nonce Binding", &[target_nonce.clone()], &[nonce.clone()]);

        target_nonce.enforce_equal(&nonce)?;

        #[cfg(feature = "num-cs-logging")]
        {
            let nonce_end = cs.num_constraints();
            println!("  - Nonce Binding: {} constraints", nonce_end - nonce_start);
            let phase2_end = cs.num_constraints();
            println!(
                "[Phase 2] Validation Total: {} constraints",
                phase2_end - phase2_start
            );
        }

        // [Phase 3: Binding] Anchor 무결성 확인 (hanchor == Poseidon(anchor))
        let phase3_start = cs.num_constraints();
        let anchor_start = cs.num_constraints();
        let target_hanchor = chain_hash_gadget(cs.clone(), &poseidon_param, &anchor.anchor)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Anchor Integrity",
            &[target_hanchor.clone()],
            &[hanchor.clone()],
        );

        target_hanchor.enforce_equal(&hanchor)?;
        #[cfg(feature = "num-cs-logging")]
        {
            let anchor_end = cs.num_constraints();
            println!(
                "  - Anchor Integrity: {} constraints",
                anchor_end - anchor_start
            );
        }

        // [Phase 3: Membership] 토큰의 aud가 aud_list에 포함되는지 검증
        let aud_start = cs.num_constraints();
        let target_aud = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud)?;
        let mut product = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));
        for valid_aud in aud_list.iter() {
            let diff = target_aud.clone() - valid_aud.clone();
            product *= diff;
        }
        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Aud Membership",
            &[product.clone()],
            &[FpVar::<C::BaseField>::Constant(C::BaseField::from(0u64))],
        );

        product.enforce_equal(&FpVar::<C::BaseField>::Constant(C::BaseField::from(0u64)))?;

        #[cfg(feature = "num-cs-logging")]
        {
            let aud_end = cs.num_constraints();
            println!("  - Aud Membership: {} constraints", aud_end - aud_start);
        }

        // [Phase 3] Context 바인딩 확인 (h_ctx == Poseidon(a_vector, random))
        let context_start = cs.num_constraints();
        let mut ctx_inputs = a.clone();
        ctx_inputs.push(random.clone());
        let target_h_ctx =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &ctx_inputs)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq("Context Binding", &[target_h_ctx.clone()], &[h_ctx.clone()]);

        target_h_ctx.enforce_equal(&h_ctx)?;

        // [Phase 3: Binding] aud_list 바인딩 확인 (h_aud_list == Poseidon(aud_list, random))
        let target_h_aud_list =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud_list)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Aud List Binding",
            &[target_h_aud_list.clone()],
            &[h_aud_list.clone()],
        );

        target_h_aud_list.enforce_equal(&h_aud_list)?;

        #[cfg(feature = "num-cs-logging")]
        {
            let context_end = cs.num_constraints();
            println!(
                "  - Context Binding: {} constraints",
                context_end - context_start
            );
            let phase3_end = cs.num_constraints();
            println!(
                "[Phase 3] Binding Total: {} constraints",
                phase3_end - phase3_start
            );
        }

        // [Phase 4: Logic] a_vector가 0이 아님을 확인
        let phase4_start = cs.num_constraints();
        let vandermonde_start = cs.num_constraints();
        let result = PoseidonAnchorSchemeGadget::<C::BaseField>::is_a_nonzero(&a)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "A Vector Nonzero",
            &[result.clone()],
            &[Boolean::constant(true)],
        );

        result.enforce_equal(&Boolean::constant(true))?;

        // [Phase 4] 변환 수행 (b = a * Matrix)
        let b = vandermonde_matrix.vector_mul_matrix(&a)?;

        #[cfg(feature = "num-cs-logging")]
        {
            let vandermonde_end = cs.num_constraints();
            println!(
                "  - Vandermonde Transform: {} constraints",
                vandermonde_end - vandermonde_start
            );
        }
        // [Phase 4] b_vector의 Sparsity(희소성) 검증
        let sparsity_start = cs.num_constraints();
        let result = PoseidonAnchorSchemeGadget::<C::BaseField>::is_b_sparsity(&b, &indices)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Sparsity Check",
            &[result.clone()],
            &[Boolean::constant(true)],
        );

        result.enforce_equal(&Boolean::constant(true))?;

        // [Phase 4] Index Range Check (current_idx < N)
        let n =
            FpVar::<C::BaseField>::new_constant(cs.clone(), C::BaseField::from(Config::N as u8))?;
        let result = is_less_than(
            &current_idx.to_bits_le_with_top_bits_zero(8)?.0,
            &n.to_bits_le_with_top_bits_zero(8)?.0,
        )?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "Index Range Check",
            &[result.clone()],
            &[Boolean::constant(true)],
        );

        result.enforce_equal(&Boolean::constant(true))?;

        #[cfg(feature = "num-cs-logging")]
        {
            let sparsity_end = cs.num_constraints();
            println!(
                "  - Sparsity Check: {} constraints",
                sparsity_end - sparsity_start
            );

            let phase4_end = cs.num_constraints();
            println!(
                "[Phase 4] Logic Total: {} constraints",
                phase4_end - phase4_start
            );
        }

        // [Phase 5] Identity Hash 생성 (aud, iss, sub, curr_index 포함)
        let phase5_start = cs.num_constraints();
        let identity_start = cs.num_constraints();
        let mut h_id_inputs = Vec::<FpVar<C::BaseField>>::new();
        // h_id_inputs.push(current_idx.clone());
        h_id_inputs.extend_from_slice(&aud);
        h_id_inputs.extend_from_slice(&iss);
        h_id_inputs.extend_from_slice(&sub);
        let h_id_ = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs)?;
        let mut h_id_inputs_with_index = Vec::<FpVar<C::BaseField>>::new();
        h_id_inputs_with_index.push(current_idx.clone());
        h_id_inputs_with_index.push(h_id_.clone());
        let h_id =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs_with_index)?;

        #[cfg(feature = "num-cs-logging")]
        {
            let identity_end = cs.num_constraints();
            println!(
                "  - Identity Hash: {} constraints",
                identity_end - identity_start
            );
        }

        // [Phase 5] Partial RHS 계산 및 Blinding 적용 (beta * h_id * random)
        let rhs_lhs_start = cs.num_constraints();
        let beta = single_multiplexer(&b, &current_idx)?;
        let calc_rhs = beta * h_id.clone() * random.clone();

        // [Phase 5] LHS 계산 및 Blinding 적용 (<a, anchor> * random)
        let lhs_ = PoseidonAnchorSchemeGadget::<C::BaseField>::inner_product(&anchor.anchor, &a)?;
        let calc_lhs = lhs_ * random.clone();

        // [Phase 5] 최종 출력값 검증 (Output Consistency Check)
        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq(
            "RHS Calculation",
            &[calc_rhs.clone()],
            &[partial_rhs.clone()],
        );

        calc_rhs.enforce_equal(&partial_rhs)?;

        #[cfg(feature = "constraints-logging")]
        gadget::debug::log_r1cs_eq("LHS Calculation", &[calc_lhs.clone()], &[lhs.clone()]);

        calc_lhs.enforce_equal(&lhs)?;
        #[cfg(feature = "num-cs-logging")]
        {
            let rhs_lhs_end = cs.num_constraints();
            println!(
                "  - RHS/LHS Calculation: {} constraints",
                rhs_lhs_end - rhs_lhs_start
            );
        }

        #[cfg(feature = "num-cs-logging")]
        {
            let phase5_end = cs.num_constraints();
            println!(
                "[Phase 5] Output Total: {} constraints",
                phase5_end - phase5_start
            );

            let total_constraints = cs.num_constraints();
            println!("\n=== Summary ===");
            println!("Total constraints: {}", total_constraints);
            println!("==========================================\n");
        }
        println!("\n");

        Ok(())
    }
}

impl<C, BNP, Config> BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    pub fn generate_mock_circuit() -> Self {
        let vandermonde_matrix = VandermondeMatrix::new(Config::N, Config::K);

        let poseidon_param = get_poseidon_params();

        let base64_table = get_base64_table();

        Self {
            vandermonde_matrix,
            poseidon_param,
            base64_table,

            hanchor: C::BaseField::default(),
            h_ctx: C::BaseField::default(),
            root: C::BaseField::default(),
            h_sign_user_op: C::BaseField::default(),
            block_timestamp: C::BaseField::default(),
            partial_rhs: C::BaseField::default(),
            lhs: C::BaseField::default(),
            h_aud_list: C::BaseField::default(),

            random: C::BaseField::default(),
            leaf_idx: 0,
            path: Path::empty(Config::TREE_HEIGHT),
            anchor: PoseidonAnchor::empty(Config::N - Config::K + 1),
            midstate: vec![0u32; 8],
            nblocks: 0,
            token_claim: vec![ClaimIndices::default(); Config::CLAIMS.len()],
            payload_offset_b64: 0,
            payload_len_b64: 0,
            sha_pad_payload_b64: vec![0; Config::MAX_JWT_B64_LEN],
            index_bits: IndexBits::empty(Config::MAX_PAYLOAD_B64_LEN),
            pk_op: PublicKey::empty(),
            signature_op: Signature::default(),
            a: vec![C::BaseField::default(); Config::N - Config::K + 1],
            indices: vec![0; Config::N],
            current_idx: 0,
            aud_list: vec![C::BaseField::default(); Config::NUM_AUDIENCE_LIMIT],
            _phantom: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vandermonde_matrix: VandermondeMatrix<C::BaseField>,
        poseidon_param: PoseidonConfig<C::BaseField>,
        base64_table: Base64Table,
        hanchor: C::BaseField,
        h_ctx: C::BaseField,
        root: C::BaseField,
        h_sign_user_op: C::BaseField,
        block_timestamp: C::BaseField,
        partial_rhs: C::BaseField,
        lhs: C::BaseField,
        h_aud_list: C::BaseField,
        random: C::BaseField,
        leaf_idx: usize,
        path: Path<MerkleTreeParams<C::BaseField>>,
        anchor: PoseidonAnchor<C::BaseField>,
        midstate: Vec<u32>,
        nblocks: usize,
        token_claim: Vec<ClaimIndices>,
        payload_offset_b64: usize,
        payload_len_b64: usize,
        sha_pad_payload_b64: Vec<u8>,
        index_bits: IndexBits,
        pk_op: PublicKey,
        signature_op: Signature,
        a: Vec<C::BaseField>,
        indices: Vec<u8>,
        current_idx: usize,
        aud_list: Vec<C::BaseField>,
    ) -> Self {
        Self {
            vandermonde_matrix,
            poseidon_param,
            base64_table,
            hanchor,
            h_ctx,
            root,
            h_sign_user_op,
            block_timestamp,
            partial_rhs,
            lhs,
            h_aud_list,
            random,
            leaf_idx,
            path,
            anchor,
            midstate,
            nblocks,
            token_claim,
            payload_offset_b64,
            payload_len_b64,
            sha_pad_payload_b64,
            index_bits,
            pk_op,
            signature_op,
            a,
            indices,
            current_idx,
            aud_list,
            _phantom: PhantomData,
        }
    }
}

impl<C, BNP, Config> ExposesPublicInputs<C::BaseField> for BaeraeLightWeightCircuit<C, BNP, Config>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    BNP: BigNatCircuitParams + Send + Sync,
    Config: ZkPasskeyConfig + Send + Sync,
{
    fn public_inputs(&self) -> Vec<C::BaseField> {
        vec![
            self.hanchor,
            self.h_ctx,
            self.root,
            self.h_sign_user_op,
            self.block_timestamp,
            self.partial_rhs,
            self.lhs,
            self.h_aud_list,
        ]
    }
}
