use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb, sponge::poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_serialize::*;

use gadget::{
    anchor::poseidon::PoseidonAnchor,
    base64::{Base64Table, mod_v2::IndexBits},
    matrix::VandermondeMatrix,
    mekletree::tree_config::MerkleTreeParams,
    signature::rsa::{PublicKey, Signature},
};

use crate::token::ClaimIndices;

/// 회로 상수 (Setup 시점에 결정)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitConstants<F: PrimeField> {
    pub vandermonde_matrix: VandermondeMatrix<F>,
    pub poseidon_param: PoseidonConfig<F>,
    pub base64_table: Base64Table,
}

/// 공개 입력 (검증자에게 공개)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitPublicInputs<F: PrimeField> {
    /// H(anchor)
    pub hanchor: F,
    /// H(a, random)
    pub h_a: F,
    /// 머클 루트
    pub root: F,
    /// H(sign_user_op)
    pub h_sign_user_op: F,
    /// 블록 타임스탬프
    pub block_timestamp: F,
    /// partial_rhs[current_idx]
    pub partial_rhs: F,
    /// <a, anchor> * random
    pub lhs: F,
    /// H(aud_list)
    pub h_aud_list: F,
}

impl<F: PrimeField> CircuitPublicInputs<F> {
    /// 공개 입력을 벡터로 변환
    pub fn to_vec(&self) -> Vec<F> {
        vec![
            self.hanchor,
            self.h_a,
            self.root,
            self.h_sign_user_op,
            self.block_timestamp,
            self.partial_rhs,
            self.lhs,
            self.h_aud_list,
        ]
    }
}

/// JWT 관련 Witness (SHA256 + Base64 + RSA)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct JwtWitnessData {
    /// SHA256 중간 상태
    pub midstate: Vec<u32>,
    /// SHA256 블록 수
    pub nblocks: usize,
    /// Claim 인덱스들
    pub token_claim: Vec<ClaimIndices>,
    /// Payload Base64 오프셋
    pub payload_offset_b64: usize,
    /// Payload Base64 길이
    pub payload_len_b64: usize,
    /// SHA 패딩된 Payload
    pub sha_pad_payload_b64: Vec<u8>,
    /// Base64 인덱스 비트
    pub index_bits: IndexBits,
    /// RSA 공개키
    pub pk_op: PublicKey,
    /// RSA 서명
    pub signature_op: Signature,
    /// 전체 JWT 길이
    pub total_len: usize,
    /// Pre-hash 블록 길이
    pub pre_hash_block_len: usize,
    /// Suffix 내 패딩 시작 위치
    pub pad_start_in_suffix: usize,
}

/// 앵커/Threshold 관련 Witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AnchorWitnessData<F: PrimeField> {
    /// 앵커 값
    pub anchor: PoseidonAnchor<F>,
    /// A 벡터
    pub a: Vec<F>,
    /// 선택자 벡터
    pub indices: Vec<u8>,
    /// 현재 인덱스
    pub current_idx: usize,
}

/// 머클 트리 Witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleWitnessData<F: PrimeField + Absorb> {
    /// 머클 경로
    pub path: Path<MerkleTreeParams<F>>,
    /// 리프 인덱스
    pub leaf_idx: usize,
}

/// Audience Witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AudienceWitnessData<F: PrimeField> {
    /// 패딩된 Audience 목록
    pub aud_list: Vec<F>,
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MiscWitnessData<F: PrimeField> {
    /// 랜덤 값
    pub random: F,
}

/// 전체 회로 입력을 묶는 구조체
#[derive(Clone)]
pub struct BaeraeCircuitInput<F: PrimeField + Absorb> {
    /// 회로 상수
    pub constants: CircuitConstants<F>,
    /// 공개 입력
    pub public_inputs: CircuitPublicInputs<F>,
    /// JWT Witness
    pub jwt: JwtWitnessData,
    /// 앵커 Witness
    pub anchor: AnchorWitnessData<F>,
    /// 머클 Witness
    pub merkle: MerkleWitnessData<F>,
    /// Audience Witness
    pub audience: AudienceWitnessData<F>,
    /// 기타 Witness
    pub misc: MiscWitnessData<F>,
}

impl<F: PrimeField + Absorb> BaeraeCircuitInput<F> {
    /// 공개 입력만 추출
    pub fn extract_public_inputs(&self) -> Vec<F> {
        self.public_inputs.to_vec()
    }
}
