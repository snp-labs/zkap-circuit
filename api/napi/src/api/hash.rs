use ark_ff::PrimeField;
use napi_derive::napi;
use zkpasskey_service::service::hash::poseidon_hash;

use crate::dto::hash::{GeneratePoseidonHashReq, GeneratePoseidonHashRes};

#[napi]
pub fn napi_generate_poseidon_hash(
  req: GeneratePoseidonHashReq,
) -> napi::Result<GeneratePoseidonHashRes> {
  let h = poseidon_hash(req.inputs)
    .map_err(|e| napi::Error::from_reason(format!("Failed to compute Poseidon hash: {}", e)))?;

  Ok(GeneratePoseidonHashRes {
    hash: format!("0x{:X}", h.into_bigint()),
  })
}
