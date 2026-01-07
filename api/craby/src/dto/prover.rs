use ark_groth16::Proof;
use common::constants::{BN254, F, ZkapConfig, ZkPasskeyConfig};
use serde::{Deserialize, Serialize};
use zkpasskey_service::utils::solidity::Solidity;

#[derive(Clone, Serialize, Deserialize)]
pub struct GenerateProofReq {
    pub pk_path: String,
    pub jwts: Vec<String>,
    pub pk_ops: Vec<String>,

    pub merkle_paths: Vec<String>, // JSON strings representing Vec<String>

    pub leaf_indices: Vec<u32>,

    pub root: String,
    pub anchor: Vec<String>,
    pub h_sign_user_op: String,
    pub block_timestamp: String,
    pub random: String,
    pub aud_list: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GenerateProofRes {
    pub proofs: Vec<Vec<String>>,
    pub shared_inputs: Vec<String>,
    pub partial_rhs_list: Vec<String>,
}

// // === JWT Constraints ===
// const MAX_JWT_B64_LEN: usize;
// const MAX_PAYLOAD_B64_LEN: usize;
// const MAX_AUD_LEN: usize;
// const MAX_EXP_LEN: usize;
// const MAX_ISS_LEN: usize;
// const MAX_NONCE_LEN: usize;
// const MAX_SUB_LEN: usize;

// // === Logic Constraints ===
// const N: usize;
// const K: usize;
// const TREE_HEIGHT: usize;
// const CLAIMS: &'static [&'static str];
// const NUM_AUDIENCE_LIMIT: usize;
// const FORBIDDEN_STRING: &'static str;
// const PAD_CHAR: char;
#[derive(Clone, Serialize, Deserialize)]
pub struct GetConfigRes {
    pub max_jwt_b64_len: usize,
    pub max_payload_b64_len: usize,
    pub max_aud_len: usize,
    pub max_exp_len: usize,
    pub max_iss_len: usize,
    pub max_nonce_len: usize,
    pub max_sub_len: usize,

    pub n: usize,
    pub k: usize,
    pub tree_height: usize,
    pub claims: Vec<String>,
    pub num_audience_limit: usize,
    pub forbidden_string: String,
    pub pad_char: char,
}

pub struct ProofBundle {
    pub proof: Vec<String>,
    pub public_inputs: Vec<String>,
}
impl From<(Vec<Proof<BN254>>, Vec<Vec<F>>)> for GenerateProofRes {
    fn from(data: (Vec<Proof<BN254>>, Vec<Vec<F>>)) -> Self {
        let (raw_proofs, raw_inputs) = data;

        // 1. Proofs 변환
        // 각 Proof 객체를 Solidity 호환 String 벡터로 변환
        let proofs: Vec<Vec<String>> = raw_proofs
            .into_iter()
            .map(|proof| {
                let proof_a = proof.a.to_solidity();
                let proof_b = proof.b.to_solidity();
                let proof_c = proof.c.to_solidity();
                [proof_a, proof_b, proof_c].concat()
            })
            .collect();

        // 입력 데이터가 비어있을 경우에 대한 안전 처리
        if raw_inputs.is_empty() {
            return Self {
                proofs,
                shared_inputs: vec![],
                partial_rhs_list: vec![],
            };
        }

        // 인덱스 정의 (가독성을 위해)
        // 0: hanchor, 1: h_ctx, 2: root, 3: h_sign_userop, 4: block_timestamp,
        // 5: partial_rhs, 6: lhs, 7: h_aud_list
        const PARTIAL_RHS_INDEX: usize = 5;

        // 2. Partial RHS List 추출 (각 요청마다 다른 값)
        let partial_rhs_list: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| inputs[PARTIAL_RHS_INDEX].to_string())
            .collect();

        // 3. Shared Inputs 추출 (모든 요청이 공유하는 값)
        let shared_inputs: Vec<String> = raw_inputs[0]
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != PARTIAL_RHS_INDEX)
            .map(|(_, input)| input.to_string())
            .collect();

        Self {
            proofs,
            shared_inputs,
            partial_rhs_list,
        }
    }
}

impl From<ZkapConfig> for GetConfigRes {
    fn from(_config: ZkapConfig) -> Self {
        Self {
            max_jwt_b64_len: <ZkapConfig as ZkPasskeyConfig>::MAX_JWT_B64_LEN,
            max_payload_b64_len: <ZkapConfig as ZkPasskeyConfig>::MAX_PAYLOAD_B64_LEN,
            max_aud_len: <ZkapConfig as ZkPasskeyConfig>::MAX_AUD_LEN,
            max_exp_len: <ZkapConfig as ZkPasskeyConfig>::MAX_EXP_LEN,
            max_iss_len: <ZkapConfig as ZkPasskeyConfig>::MAX_ISS_LEN,
            max_nonce_len: <ZkapConfig as ZkPasskeyConfig>::MAX_NONCE_LEN,
            max_sub_len: <ZkapConfig as ZkPasskeyConfig>::MAX_SUB_LEN,
            n: <ZkapConfig as ZkPasskeyConfig>::N,
            k: <ZkapConfig as ZkPasskeyConfig>::K,
            tree_height: <ZkapConfig as ZkPasskeyConfig>::TREE_HEIGHT,
            claims: <ZkapConfig as ZkPasskeyConfig>::CLAIMS.iter().map(|s| s.to_string()).collect(),
            num_audience_limit: <ZkapConfig as ZkPasskeyConfig>::NUM_AUDIENCE_LIMIT,
            forbidden_string: <ZkapConfig as ZkPasskeyConfig>::FORBIDDEN_STRING.to_string(),
            pad_char: <ZkapConfig as ZkPasskeyConfig>::PAD_CHAR,
        }
    }
}