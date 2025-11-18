use ark_groth16::Proof;
use napi_derive::napi;
use zkpasskey_service::{
  service::constants::{AppField, BN254},
  utils::solidity::Solidity,
};

#[napi(object)]
pub struct GenerateProofReq {
  pub pk_path: String,

  pub jwts: Vec<String>,
  pub pk_ops: Vec<String>,

  /// 예: merkle path를 레벨별 string 배열로 표현한다면 Vec<Vec<String>>
  pub mp: Vec<Vec<String>>,

  /// JS number는 안전정수 범위가 있으니 보통 u32/u64 권장
  pub leaf_index: Vec<u32>,

  pub root: String,
  pub anchor_parts: Vec<String>,
  pub h_sign_userop: String,
  pub block_timestamp: String,
  pub random: String,
  pub aud_list: Vec<String>,
}

#[napi(object)]
pub struct GenerateProofRes {
  pub result: Vec<ProofBundle>,
}

#[napi(object)]
pub struct ProofBundle {
  pub proof: Vec<String>,
  pub public_inputs: Vec<String>,
}

impl From<(Vec<Proof<BN254>>, Vec<Vec<AppField>>)> for GenerateProofRes {
  fn from(data: (Vec<Proof<BN254>>, Vec<Vec<AppField>>)) -> Self {
    let (raw_proofs, raw_inputs) = data;

    let result: Vec<ProofBundle> = raw_proofs
      .into_iter()
      .zip(raw_inputs.into_iter())
      .map(|(proof, inputs)| {
        // 1. Proof -> Vec<String> 변환
        let proof_strings = {
          let proof_a = proof.a.to_solidity();
          let proof_b = proof.b.to_solidity();
          let proof_c = proof.c.to_solidity();
          [proof_a, proof_b, proof_c].concat()
        };

        // 2. Inputs -> Vec<String> 변환
        let input_strings: Vec<String> = inputs.iter().map(|input| input.to_string()).collect();

        // 3. Bundle 생성
        ProofBundle {
          proof: proof_strings,
          public_inputs: input_strings,
        }
      })
      .collect();

    Self { result }
  }
}
