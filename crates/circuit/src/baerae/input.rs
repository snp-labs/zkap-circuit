use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb, sponge::poseidon::PoseidonConfig};
use ark_ff::PrimeField;
use ark_serialize::*;

use gadget::{
    anchor::poseidon::PoseidonAnchor,
    base64::{Base64Table, IndexBits},
    matrix::VandermondeMatrix,
    merkletree::tree_config::MerkleTreeParams,
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
    /// JWT 만료 시간
    pub jwt_exp: F,
    /// partial_rhs at current_idx
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
            self.jwt_exp,
            self.partial_rhs,
            self.lhs,
            self.h_aud_list,
        ]
    }
}

/// JWT 관련 Witness (SHA256 + Base64 + RSA)
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct JwtWitness {
    /// SHA256 블록 수 (final block index, 0-indexed)
    pub nblocks: usize,
    /// Claim 인덱스들
    pub claim_indices: Vec<ClaimIndices>,
    /// Payload Base64 오프셋
    pub pay_offset_b64: usize,
    /// Payload Base64 길이
    pub pay_len_b64: usize,
    /// SHA 패딩된 Full JWT (header.payload with SHA256 padding)
    pub sha_pad_jwt_b64: Vec<u8>,
    /// Base64 인덱스 비트
    pub index_bits: IndexBits,
    /// RSA 공개키
    pub pk: PublicKey,
    /// RSA 서명
    pub sig: Signature,
    /// 전체 JWT 길이 (padding 전)
    pub total_len: usize,
    /// 패딩 시작 바이트 인덱스 (절대 위치)
    pub pad_start_byte_idx: usize,
}

/// 앵커/Threshold 관련 Witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AnchorWitness<F: PrimeField> {
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
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleWitness<F: PrimeField + Absorb> {
    /// 머클 경로
    pub path: Path<MerkleTreeParams<F>>,
    /// 리프 인덱스
    pub leaf_idx: usize,
}

/// Audience Witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct AudienceWitness<F: PrimeField> {
    /// 패딩된 Audience 목록
    pub aud_list: Vec<F>,
}

/// 기타 Witness
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MiscWitness<F: PrimeField> {
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
    pub jwt: JwtWitness,
    /// 앵커 Witness
    pub anchor: AnchorWitness<F>,
    /// 머클 Witness
    pub merkle: MerkleWitness<F>,
    /// Audience Witness
    pub audience: AudienceWitness<F>,
    /// 기타 Witness
    pub misc: MiscWitness<F>,
}

impl<F: PrimeField + Absorb> BaeraeCircuitInput<F> {
    /// 공개 입력만 추출
    pub fn extract_public_inputs(&self) -> Vec<F> {
        self.public_inputs.to_vec()
    }
}
