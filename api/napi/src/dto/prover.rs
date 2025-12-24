use ark_groth16::Proof;
use common::constants::{BN254, F};
use napi_derive::napi;
use zkpasskey_service::utils::solidity::Solidity;

#[napi(object)]
pub struct GenerateProofReq {
  pub pk_path: String,

  pub jwts: Vec<String>,
  pub pk_ops: Vec<String>,

  /// 예: merkle path를 레벨별 string 배열로 표현한다면 Vec<Vec<String>>
  pub merkle_paths: Vec<Vec<String>>,

  /// JS number는 안전정수 범위가 있으니 보통 u32/u64 권장
  pub leaf_indices: Vec<u32>,

  pub root: String,
  pub anchor: Vec<String>,
  pub h_sign_user_op: String,
  pub block_timestamp: String,
  pub random: String,
  pub aud_list: Vec<String>,
}

#[napi(object)]
pub struct GenerateProofRes {
  pub proofs: Vec<Vec<String>>,
  pub shared_inputs: Vec<String>,
  pub partial_rhs_list: Vec<String>,
}

#[napi(object)]
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
