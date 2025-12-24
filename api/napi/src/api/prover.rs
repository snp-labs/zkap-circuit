use std::path::PathBuf;

use common::constants::ZkapConfig;
use napi_derive::napi;
use zkpasskey_service::service::snark::zkap::generate_baerae_proof;

use crate::dto::prover::{GenerateProofReq, GenerateProofRes};

#[napi]
pub fn napi_generate_proof(req: GenerateProofReq) -> napi::Result<GenerateProofRes> {
  let pk_path: PathBuf = req.pk_path.into();
  let leaf_indices: Vec<usize> = req.leaf_indices.into_iter().map(|i| i as usize).collect();

  let result = generate_baerae_proof::<ZkapConfig>(
    &pk_path,
    req.jwts,
    req.pk_ops,
    req.merkle_paths,
    leaf_indices,
    &req.root,
    &req.anchor,
    &req.h_sign_user_op,
    &req.block_timestamp,
    &req.random,
    &req.aud_list,
  )
  .map_err(|e| napi::Error::from_reason(format!("Failed to generate proof: {}", e)))?;

  Ok(result.into())
}
