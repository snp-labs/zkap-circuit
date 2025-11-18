use anyhow::Context;
use flutter_rust_bridge::frb;

use crate::dto::proof::{GenerateProofReq, GenerateProofRes};
use zkpasskey_service::utils::solidity::Solidity;

#[frb]
pub fn frb_generate_proof(req: GenerateProofReq) -> Result<Vec<GenerateProofRes>, String> {
    fn inner(req: GenerateProofReq) -> anyhow::Result<Vec<GenerateProofRes>> {
        let selected_secrets = req.selected_secrets.into_iter().map(|s| s.into()).collect();

        let (proofs, public_inputs) =
            zkpasskey_service::service::snark::snark_v2::generate_proof_v2(
                req.pk_path,
                req.anchor_key_path,
                req.schnorr_key_path,
                req.anchor_parts,
                selected_secrets,
                req.jwts,
                req.pks,
                req.mps,
                req.root,
                req.signature,
                req.leaf_index,
                req.selector,
                req.counter,
                req.random,
                req.h_userop,
                req.slot,
            )
            .context("service::proof::generate_proof failed")?;

        let mut result = Vec::new();

        for (proof, public_inputs) in proofs.into_iter().zip(public_inputs.into_iter()) {
            let proof_a = proof.a.to_solidity();
            let proof_b = proof.b.to_solidity();
            let proof_c = proof.c.to_solidity();
            let proof_solidity = [proof_a, proof_b, proof_c].concat();

            let public_inputs_solidity: Vec<String> = public_inputs
                .iter()
                .map(|input| input.to_string())
                .collect();
            result.push(GenerateProofRes {
                proof: proof_solidity,
                public_inputs: public_inputs_solidity,
            });
        }

        Ok(result)
    }

    inner(req).map_err(|e| format!("{:?}", e))
}
