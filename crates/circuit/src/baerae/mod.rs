#![allow(unused_variables)]
#![allow(unused_mut)]

pub mod input;

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
use crate::constants::ZkPasskeyConfig;
use gadget::{
    anchor::poseidon::{
        PoseidonAnchor,
        constraints::{
            PoseidonAnchorSchemeGadget, PoseidonAnchorVar, enforce_boolean_selector_debug,
            enforce_selector_cardinality_debug,
        },
    },
    base64::{
        Base64Table, Base64TableVar,
        constraints_v2::{Base64DecoderGadget, IndexBitsVar},
        get_base64_table,
        mod_v2::IndexBits,
    },
    bigint::{
        constraints::{BigNatCircuitParams, BigNatVar},
        utils::BigNat,
    },
    hashes::{
        poseidon::{constraints::chain_hash_gadget, get_poseidon_params},
        sha256::constraints::SHA256Gadget,
    },
    matrix::{VandermondeMatrix, constraints_v2::VandermondeMatrixVar},
    merkletree::tree_config::{Empty, MerkleTreeParams, MerkleTreeParamsVar},
    signature::rsa::{
        PublicKey, Signature,
        constraints::{PublicKeyVar, SignatureVar},
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
    pub h_a: C::BaseField,
    pub root: C::BaseField,
    pub h_sign_user_op: C::BaseField,
    pub jwt_exp: C::BaseField,
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
    pub total_len: usize,
    pub pre_hash_block_len: usize,
    pub pad_start_in_suffix: usize,

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
        let mut cs_last = initial_constraints;

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

        let h_a = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.h_a))?;

        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.root))?;

        let h_sign_user_op =
            FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.h_sign_user_op))?;

        let jwt_exp = FpVar::<C::BaseField>::new_input(cs.clone(), || Ok(self.jwt_exp))?;

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

        // [ZKAPCIR-001] RSA e=65537 강제
        let expected_e = BigNatVar::<C::BaseField, BNP>::constant(&BigNat::from(gadget::constants::RSA_DEFAULT_EXPONENT))?;
        pk_op.e.enforce_equal_when_carried(&expected_e)?;

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

        let total_len =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.total_len as u16))?;

        let pre_hash_block_len =
            UInt16::<C::BaseField>::new_witness(cs.clone(), || Ok(self.pre_hash_block_len as u16))?;

        let pad_start_in_suffix =
            UInt16::<C::BaseField>::new_witness(
                cs.clone(),
                || Ok(self.pad_start_in_suffix as u16),
            )?;

        let zero = FpVar::<C::BaseField>::Constant(C::BaseField::from(0u64));
        let one = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));

        gadget::dbg_cs_total!(&cs, "Initial constraints");
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "[Setup] Variable allocation");

        // ============================================================
        // [Phase 1] JWT Authenticity & Claim Extraction
        // ============================================================
        let phase1_start = cs.num_constraints();
        let mut phase1_total_last = phase1_start;

        // [1.1] RSA-2048 서명 검증
        let mut digest = midstate
            .digest_with_pad_checked(
                &sha_pad_payload_b64,
                nblocks,
                &pre_hash_block_len,
                &total_len,
                &pad_start_in_suffix,
            )?
            .to_bytes_le()?;

        let result = RSA2048VerifyGadget::verify_opt(&mut digest, &signature_op, &pk_op)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!("RSA Verification", result, Boolean::constant(true));
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - RSA Verification");

        // [1.2] Base64 디코딩 및 Claim 추출
        let sha_pad_payload_b64_to_fp = sha_pad_payload_b64
            .iter()
            .map(|u8| u8.to_fp())
            .collect::<ark_relations::r1cs::Result<Vec<_>>>()?;

        // [ZKAPCIR-002] JWT payload 경계를 '.' 구분자와 바인딩
        // payload_offset_b64/payload_len_b64가 실제 JWT '.' 위치와 무관하면
        // 공격자가 header 등 임의 구간을 payload로 지정하여 클레임을 위조할 수 있음.
        let dot_char = FpVar::<C::BaseField>::Constant(C::BaseField::from(b'.' as u64));
        let payload_offset_fp = Boolean::le_bits_to_fp(&payload_offset_b64.to_bits_le()?)?;
        let payload_len_fp = Boolean::le_bits_to_fp(&payload_len_b64.to_bits_le()?)?;

        // 방어 심층: payload_offset >= 1 (offset=0이면 필드 underflow 발생)
        let offset_ge_1 = is_less_than(
            &zero.to_bits_le_with_top_bits_zero(16)?.0,
            &payload_offset_fp.to_bits_le_with_top_bits_zero(16)?.0,
        )?;

        gadget::dbg_r1cs_eq!("Payload Offset >= 1", offset_ge_1, Boolean::constant(true));
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Payload Offset >= 1");

        offset_ge_1.enforce_equal(&Boolean::constant(true))?;

        // 방어 심층: payload_offset + payload_len < buffer_len (버퍼 범위 초과 방지)
        let buf_len = FpVar::<C::BaseField>::Constant(C::BaseField::from(
            sha_pad_payload_b64_to_fp.len() as u64,
        ));
        let second_dot_idx = &payload_offset_fp + &payload_len_fp;
        let idx_in_range = is_less_than(
            &second_dot_idx.to_bits_le_with_top_bits_zero(16)?.0,
            &buf_len.to_bits_le_with_top_bits_zero(16)?.0,
        )?;

        gadget::dbg_r1cs_eq!(
            "Payload Index Range Check",
            idx_in_range,
            Boolean::constant(true)
        );
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Payload Index Range Check");

        idx_in_range.enforce_equal(&Boolean::constant(true))?;

        // 첫 번째 '.' : payload 시작 바로 전 (header.payload 사이)
        let first_dot_idx = &payload_offset_fp - &one;
        let first_dot_char = single_multiplexer(&sha_pad_payload_b64_to_fp, &first_dot_idx)?;

        gadget::dbg_r1cs_eq!("Payload Boundary Binding", first_dot_char, dot_char);

        first_dot_char.enforce_equal(&dot_char)?;

        // ZKAPCIR-002: payload 끝 위치 == SHA-256 패딩 시작 위치 구조적 바인딩
        // SHA-256 gadget(constraints.rs:L403)이 이미 buffer[pad_start_in_suffix] == 0x80을 검증하므로
        // 여기서는 위치만 바인딩하면 충분
        let pad_start_fp = pad_start_in_suffix.to_fp()?;
        second_dot_idx.enforce_equal(&pad_start_fp)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Payload Boundary Check");

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
        valid.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!("Base64 Decoding Valid", valid, Boolean::constant(true));
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Base64 Decoding");

        let aud_bytes = claim_extractor_v2("aud", &payload, &token_claim[0], Config::MAX_AUD_LEN)?;
        let exp_bytes = claim_extractor_v2("exp", &payload, &token_claim[1], Config::MAX_EXP_LEN)?;
        let iss_bytes = claim_extractor_v2("iss", &payload, &token_claim[2], Config::MAX_ISS_LEN)?;
        let nonce_bytes =
            claim_extractor_v2("nonce", &payload, &token_claim[3], Config::MAX_NONCE_LEN)?;
        let sub_bytes = claim_extractor_v2("sub", &payload, &token_claim[4], Config::MAX_SUB_LEN)?;
        // Field Element로 변환 및 패킹 (Packing)
        let aud = pack_decompose_bytes_unchecked(&aud_bytes)?;
        let exp = jwt_exp_to_field(&exp_bytes)?;
        let iss = pack_decompose_bytes_unchecked(&iss_bytes)?;

        let last_quote_index = token_claim[3]
            .value_len
            .wrapping_add(&UInt16::constant(u16::MAX));
        let nonce = jwt_nonce_hex_to_field(&nonce_bytes, &last_quote_index)?;
        let sub = pack_decompose_bytes_unchecked(&sub_bytes)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Claims Extraction");
        gadget::dbg_cs_delta!(
            &cs,
            &mut phase1_total_last,
            "[Phase 1] JWT Authenticity & Claim Extraction Total"
        );

        // ============================================================
        // [Phase 2] Issuer Validation and Execution Binding
        // ============================================================
        let phase2_start = cs.num_constraints();
        let mut phase2_total_last = phase2_start;

        // [2.1] Issuer-Public Key 검증
        let leaf_inputs = vec![iss.clone(), pk_op.n.limbs.clone()].concat();
        let leaf = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &leaf_inputs)?;

        path.set_leaf_position(leaf_idx.to_bits_le()?);
        let result = path.verify_membership(&poseidon_param, &poseidon_param, &root, &[leaf])?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!("MerkleVerify", result, Boolean::constant(true));
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Issuer-PublicKey MerkleVerify");

        // [2.2] expiry check: jwt_exp == exp
        let result = exp.is_eq(&jwt_exp)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!(
            "Expiry Check (jwt_exp == exp)",
            result,
            Boolean::constant(true)
        );
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Expiry Check");

        gadget::dbg_cs_delta!(&cs, &mut phase2_total_last, "[Phase 2] Validation Total");

        // ============================================================
        // [Phase 3] Threshold Membership and Anchor Binding (Binding)
        // ============================================================
        let phase3_start = cs.num_constraints();
        let mut phase3_total_last = phase3_start;

        // h_anchor == Poseidon(anchor)
        let target_hanchor = chain_hash_gadget(cs.clone(), &poseidon_param, &anchor.anchor)?;
        target_hanchor.enforce_equal(&hanchor)?;

        gadget::dbg_r1cs_eq!("Anchor Binding", target_hanchor, hanchor);
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Anchor Binding");

        // Nonce binding: nonce == Poseidon(h_sign_userop, random)
        let mut nonce_inputs = Vec::<FpVar<C::BaseField>>::new();
        nonce_inputs.push(h_sign_user_op);
        nonce_inputs.push(random.clone());
        let target_nonce =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &nonce_inputs)?;
        target_nonce.enforce_equal(&nonce)?;

        gadget::dbg_r1cs_eq!("Nonce Binding", target_nonce, nonce);
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Nonce Binding");

        // aud membership: Poseidon(aud) ∈ aud_list (product trick)
        let target_aud = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud)?;
        let mut product = FpVar::<C::BaseField>::Constant(C::BaseField::from(1u64));
        for valid_aud in aud_list.iter() {
            let diff = target_aud.clone() - valid_aud.clone();
            product *= diff;
        }
        product.enforce_equal(&zero)?;

        gadget::dbg_r1cs_eq!("Aud Membership", product, zero);
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Aud Membership");

        // h_a == Poseidon(a, random)
        let mut a_inputs = a.clone();
        a_inputs.push(random.clone());
        let target_h_a = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &a_inputs)?;
        target_h_a.enforce_equal(&h_a)?;

        gadget::dbg_r1cs_eq!("Context Binding", target_h_a, h_a);
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Context Binding");

        // h_aud_list == Poseidon(aud_list)
        let target_h_aud_list =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &aud_list)?;
        target_h_aud_list.enforce_equal(&h_aud_list)?;

        gadget::dbg_r1cs_eq!("Aud List Binding", target_h_aud_list, h_aud_list);

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Aud List Binding");
        gadget::dbg_cs_delta!(&cs, &mut phase3_total_last, "[Phase 3] Binding Total");

        // ============================================================
        // [Phase 4] Threshold logic (Vandermonde + indices constraints)
        // ============================================================
        let phase4_start = cs.num_constraints();
        let mut phase4_total_last = phase4_start;

        let result = PoseidonAnchorSchemeGadget::<C::BaseField>::is_a_nonzero(&a)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - A Vector Nonzero");

        let b = vandermonde_matrix.vector_mul_matrix(&a)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Vandermonde Transform");

        // indices constraints:
        //  1) boolean
        //  2) Σ indices = k
        //  3) indices[current_idx] = 1
        //  4) b sparsity helper
        let result = enforce_boolean_selector_debug(&indices)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Boolean Selectors");

        let result = PoseidonAnchorSchemeGadget::<C::BaseField>::is_b_sparsity(&b, &indices)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!("Sparsity Check", result, Boolean::constant(true));

        let k_fp = FpVar::<C::BaseField>::Constant(C::BaseField::from(Config::K as u64));
        let result = enforce_selector_cardinality_debug(&indices, &k_fp)?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!("Selector Cardinality", result, Boolean::constant(true));
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Selector Cardinality");

        let is_one = single_multiplexer(&indices, &current_idx)?;
        is_one.enforce_equal(&one)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Current Idx One-hot");

        // random != 0
        random.enforce_not_equal(&zero)?;
        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Random Nonzero");

        // current_idx < N
        let n =
            FpVar::<C::BaseField>::new_constant(cs.clone(), C::BaseField::from(Config::N as u8))?;
        let result = is_less_than(
            &current_idx.to_bits_le_with_top_bits_zero(8)?.0,
            &n.to_bits_le_with_top_bits_zero(8)?.0,
        )?;
        result.enforce_equal(&Boolean::constant(true))?;

        gadget::dbg_r1cs_eq!("Index Range Check", result, Boolean::constant(true));

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Index Range Check");
        gadget::dbg_cs_delta!(&cs, &mut phase4_total_last, "[Phase 4] Logic Total");

        // ============================================================
        // [Phase 5] Output binding (h_id, partial_rhs, lhs)
        // ============================================================
        let phase5_start = cs.num_constraints();
        let mut phase5_total_last = phase5_start;

        // h_id = Poseidon(current_idx, Poseidon(aud, iss, sub))
        let mut h_id_inputs = Vec::<FpVar<C::BaseField>>::new();
        h_id_inputs.extend_from_slice(&aud);
        h_id_inputs.extend_from_slice(&iss);
        h_id_inputs.extend_from_slice(&sub);
        let h_id_ = PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs)?;
        let mut h_id_inputs_with_index = Vec::<FpVar<C::BaseField>>::new();
        h_id_inputs_with_index.push(current_idx.clone());
        h_id_inputs_with_index.push(h_id_.clone());

        let h_id =
            PoseidonCRHGadget::<C::BaseField>::evaluate(&poseidon_param, &h_id_inputs_with_index)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - Identity Hash");

        // partial_rhs[current_idx] = b[current_idx] * h_id * random
        // lhs = <a, anchor> * random
        let beta = single_multiplexer(&b, &current_idx)?;
        let calc_rhs = beta * h_id.clone() * random.clone();
        calc_rhs.enforce_equal(&partial_rhs)?;

        gadget::dbg_r1cs_eq!("RHS Calculation", calc_rhs, partial_rhs);

        let lhs_ = PoseidonAnchorSchemeGadget::<C::BaseField>::inner_product(&anchor.anchor, &a)?;
        let calc_lhs = lhs_ * random.clone();
        calc_lhs.enforce_equal(&lhs)?;

        gadget::dbg_cs_delta!(&cs, &mut cs_last, "  - RHS/LHS Calculation");

        gadget::dbg_cs_delta!(&cs, &mut phase5_total_last, "[Phase 5] Output Total");
        gadget::dbg_cs_total!(&cs, "Total constraints");

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
            h_a: C::BaseField::default(),
            root: C::BaseField::default(),
            h_sign_user_op: C::BaseField::default(),
            jwt_exp: C::BaseField::default(),
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
            total_len: 0,
            pre_hash_block_len: 0,
            pad_start_in_suffix: 0,

            _phantom: PhantomData,
        }
    }

    /// 구조화된 입력으로부터 회로 생성 (권장)
    pub fn from_input(input: input::BaeraeCircuitInput<C::BaseField>) -> Self {
        Self {
            vandermonde_matrix: input.constants.vandermonde_matrix,
            poseidon_param: input.constants.poseidon_param,
            base64_table: input.constants.base64_table,
            hanchor: input.public_inputs.hanchor,
            h_a: input.public_inputs.h_a,
            root: input.public_inputs.root,
            h_sign_user_op: input.public_inputs.h_sign_user_op,
            jwt_exp: input.public_inputs.jwt_exp,
            partial_rhs: input.public_inputs.partial_rhs,
            lhs: input.public_inputs.lhs,
            h_aud_list: input.public_inputs.h_aud_list,
            random: input.misc.random,
            leaf_idx: input.merkle.leaf_idx,
            path: input.merkle.path,
            anchor: input.anchor.anchor,
            midstate: input.jwt.state,
            nblocks: input.jwt.nblocks,
            token_claim: input.jwt.claim_indices,
            payload_offset_b64: input.jwt.pay_offset_b64,
            payload_len_b64: input.jwt.pay_len_b64,
            sha_pad_payload_b64: input.jwt.sha_pad_payload_b64,
            index_bits: input.jwt.index_bits,
            pk_op: input.jwt.pk,
            signature_op: input.jwt.sig,
            a: input.anchor.a,
            indices: input.anchor.selector,
            current_idx: input.anchor.current_idx,
            aud_list: input.audience.aud_list,
            total_len: input.jwt.total_len,
            pre_hash_block_len: input.jwt.pre_hash_block_len,
            pad_start_in_suffix: input.jwt.pad_start_in_suffix,
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
            self.h_a,
            self.root,
            self.h_sign_user_op,
            self.jwt_exp,
            self.partial_rhs,
            self.lhs,
            self.h_aud_list,
        ]
    }
}
