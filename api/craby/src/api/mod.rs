use std::path::PathBuf;

use common::constants::ZkapConfig;
use zkpasskey_service::service::{
    anchor::anchor::create_poseidon_anchor, snark::zkap::generate_baerae_proof,
};

use crate::dto::{
    anchor::{GenerateAnchorReq, GenerateAnchorRes},
    prover::{GenerateProofReq, GenerateProofRes},
};

pub fn craby_generate_poseidon_anchor(req: GenerateAnchorReq) -> anyhow::Result<GenerateAnchorRes> {
    let anchor = create_poseidon_anchor::<ZkapConfig>(req.into())
        .map_err(|e| anyhow::anyhow!("Failed to create anchor: {}", e))?;

    let out = anchor.0.iter().map(|x| x.to_string()).collect();

    Ok(GenerateAnchorRes { anchor: out })
}

pub fn craby_generate_proof(req: GenerateProofReq) -> anyhow::Result<GenerateProofRes> {
    let pk_path: PathBuf = req.pk_path.into();
    let leaf_indices: Vec<usize> = req.leaf_indices.into_iter().map(|i| i as usize).collect();
    let mps = req
        .merkle_paths
        .into_iter()
        .map(|mp_str| {
            serde_json::from_str::<Vec<String>>(&mp_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse merkle path JSON: {}", e))
        })
        .collect::<Result<Vec<Vec<String>>, _>>()?;

    let result = generate_baerae_proof::<ZkapConfig>(
        &pk_path,
        req.jwts,
        req.pk_ops,
        mps,
        leaf_indices,
        &req.root,
        &req.anchor,
        &req.h_sign_user_op,
        &req.block_timestamp,
        &req.random,
        &req.aud_list,
    )
    .map_err(|e| anyhow::anyhow!("Failed to generate proof: {}", e))?;

    Ok(GenerateProofRes::from(result))
}
