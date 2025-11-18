use anyhow::Context;
use flutter_rust_bridge::frb;

use crate::dto::hash::{GeneratePoseidonHashReq, GeneratePoseidonHashRes};

#[frb]
pub fn frb_poseidon_hash(req: GeneratePoseidonHashReq) -> Result<GeneratePoseidonHashRes, String> {
    fn inner(req: GeneratePoseidonHashReq) -> anyhow::Result<GeneratePoseidonHashRes> {
        let hash = zkpasskey_service::service::hash::poseidon_hash(req.inputs)
            .context("service::hash::poseidon_hash failed")?;

        Ok(GeneratePoseidonHashRes { hash: hash.hash })
    }

    inner(req).map_err(|e| e.to_string())
}
