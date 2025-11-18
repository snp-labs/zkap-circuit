use anyhow::Context;
use flutter_rust_bridge::frb;

use crate::dto::schnorr::{GenerateSchnorrSignatureReq, GenerateSchnorrSignatureRes};

#[frb]
pub fn frb_generate_schnorr_signature(
    req: GenerateSchnorrSignatureReq,
) -> Result<GenerateSchnorrSignatureRes, String> {
    fn inner(req: GenerateSchnorrSignatureReq) -> anyhow::Result<GenerateSchnorrSignatureRes> {
        let signature =
            zkpasskey_service::service::signature::schnorr_sign(req.schnorr_key_path, req.root)
                .context("service::schnorr::generate_schnorr_signature failed")?;

        Ok(GenerateSchnorrSignatureRes { signature: signature.signature })
    }

    inner(req).map_err(|e| e.to_string())
}
