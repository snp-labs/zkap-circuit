//! 회로 입력 구조체
//!
//! BaeraeLightWeightCircuit에 전달되는 모든 입력을 그룹화합니다.

#![allow(dead_code)]

use ark_crypto_primitives::merkle_tree::Path;
use circuit::constants::F;
use gadget::{
    anchor::poseidon::PoseidonAnchor,
    mekletree::tree_config::MerkleTreeParams,
    signature::rsa::{PublicKey, Signature},
};

use crate::app::jwt::builder::JwtCircuitWitness;

/// 공개 입력 (Public Inputs)
///
/// 검증자에게 공개되는 값들입니다.
#[derive(Clone)]
pub struct PublicInputs {
    /// H(anchor)
    pub hanchor: F,

    /// H(a, random)
    pub h_a: F,

    /// 머클 루트
    pub root: F,

    /// H(sign_user_op)
    pub h_sign_user_op: F,

    /// JWT Exp (Expiration timestamp)
    pub jwt_exp: F,

    /// partial_rhs[current_idx]
    pub partial_rhs: F,

    /// <a, anchor> * random
    pub lhs: F,

    /// H(aud_list)
    pub h_aud_list: F,
}

/// JWT 관련 Witness
#[derive(Clone)]
pub struct JwtWitness {
    /// SHA256 중간 상태
    pub state: Vec<u32>,

    /// SHA256 블록 수
    pub nblocks: usize,

    /// Claim 인덱스들
    pub claim_indices: Vec<circuit::token::ClaimIndices>,

    /// Payload Base64 오프셋
    pub pay_offset_b64: usize,

    /// Payload Base64 길이
    pub pay_len_b64: usize,

    /// SHA 패딩된 Payload
    pub sha_pad_payload_b64: Vec<u8>,

    /// Base64 인덱스 비트
    pub index_bits: gadget::base64::mod_v2::IndexBits,

    /// RSA 공개키
    pub pk: PublicKey,

    /// RSA 서명
    pub sig: Signature,

    /// 전체 JWT 길이
    pub total_len: usize,

    /// Pre-hash 블록 길이
    pub pre_hash_block_len: usize,

    /// Suffix 내 패딩 시작 위치
    pub pad_start_in_suffix: usize,
}

impl From<JwtCircuitWitness> for JwtWitness {
    fn from(w: JwtCircuitWitness) -> Self {
        Self {
            state: w.state,
            nblocks: w.nblocks,
            claim_indices: w.claim_indices,
            pay_offset_b64: w.pay_offset_b64,
            pay_len_b64: w.pay_len_b64,
            sha_pad_payload_b64: w.sha_pad_payload_b64,
            index_bits: w.index_bits,
            pk: w.pk,
            sig: w.sig,
            total_len: w.total_len,
            pre_hash_block_len: w.pre_hash_block_len,
            pad_start_in_suffix: w.pad_start_in_suffix,
        }
    }
}

/// 앵커 관련 Witness
#[derive(Clone)]
pub struct AnchorWitness {
    /// 앵커 값
    pub anchor: PoseidonAnchor<F>,

    /// A 벡터
    pub a: Vec<F>,

    /// 선택자 벡터
    pub selector: Vec<u8>,

    /// 현재 인덱스
    pub current_idx: usize,
}

/// 머클 트리 Witness
#[derive(Clone)]
pub struct MerkleWitness {
    /// 머클 경로
    pub path: Path<MerkleTreeParams<F>>,

    /// 리프 인덱스
    pub leaf_idx: usize,
}

/// 단일 증명을 위한 완전한 회로 입력
#[derive(Clone)]
pub struct CircuitInput {
    /// 공개 입력
    pub public: PublicInputs,

    /// JWT Witness
    pub jwt: JwtWitness,

    /// 앵커 Witness
    pub anchor: AnchorWitness,

    /// 머클 Witness
    pub merkle: MerkleWitness,

    /// 패딩된 Audience 목록
    pub aud_list: Vec<F>,

    /// 랜덤 값
    pub random: F,
}

impl CircuitInput {
    /// 공개 입력만 추출
    pub fn extract_public_inputs(&self) -> Vec<F> {
        vec![
            self.public.hanchor,
            self.public.h_a,
            self.public.root,
            self.public.h_sign_user_op,
            self.public.jwt_exp,
            self.public.partial_rhs,
            self.public.lhs,
            self.public.h_aud_list,
        ]
    }
}
