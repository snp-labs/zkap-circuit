use common::constants::ZkapConfig;
use napi_derive::napi;
use zkpasskey_service::service::anchor::anchor::create_poseidon_anchor;

use crate::dto::anchor::{GenerateAnchorReq, GenerateAnchorRes};

#[napi]
pub fn napi_generate_anchor(req: GenerateAnchorReq) -> napi::Result<GenerateAnchorRes> {
  let anchor = create_poseidon_anchor::<ZkapConfig>(req.secrets.into_iter().map(|s| s.into()).collect())
    .map_err(|e| napi::Error::from_reason(format!("Failed to create anchor: {}", e)))?;

  let out = anchor.0.iter().map(|x| x.to_string()).collect();

  Ok(GenerateAnchorRes { anchor: out })
}
