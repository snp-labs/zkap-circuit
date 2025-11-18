use napi_derive::napi;
use zkpasskey_service::service::anchor::anchor::create_poseidon_anchor;

use crate::dto::anchor::{GenerateAnchorReq, GenerateAnchorRes};

#[napi]
pub fn napi_generate_anchor(req: GenerateAnchorReq) -> napi::Result<GenerateAnchorRes> {
  let anchor = create_poseidon_anchor(req.secrets.into_iter().map(|s| s.into()).collect())
    .map_err(|e| napi::Error::from_reason(format!("Failed to create anchor: {}", e)))?;
  Ok(GenerateAnchorRes { anchor })
}
