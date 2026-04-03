//! Proof generation DTOs

use ark_groth16::Proof;
use circuit::constants::{BN254, F};
use ark_utils::evm::solidity_types::Solidity;

/// Proof generation request (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GenerateProofReqCore {
    pub pk_path: String,
    pub jwts: Vec<String>,
    pub pk_ops: Vec<String>,
    pub merkle_paths: Vec<Vec<String>>,
    pub leaf_indices: Vec<u32>,
    pub root: String,
    pub anchor: Vec<String>,
    pub h_sign_user_op: String,
    pub random: String,
    pub aud_list: Vec<String>,
}

/// Proof generation response (platform-agnostic core type)
#[derive(Debug, Clone)]
pub struct GenerateProofResCore {
    pub proofs: Vec<Vec<String>>,
    pub shared_inputs: Vec<String>,
    pub partial_rhs_list: Vec<String>,
    pub jwt_exp_list: Vec<String>,
}

impl From<(Vec<Proof<BN254>>, Vec<Vec<F>>)> for GenerateProofResCore {
    fn from(data: (Vec<Proof<BN254>>, Vec<Vec<F>>)) -> Self {
        let (raw_proofs, raw_inputs) = data;

        // Convert each Proof to Solidity-compatible String vector
        let proofs: Vec<Vec<String>> = raw_proofs
            .into_iter()
            .map(|proof| {
                let proof_a = proof.a.to_solidity();
                let proof_b = proof.b.to_solidity();
                let proof_c = proof.c.to_solidity();
                [proof_a, proof_b, proof_c].concat()
            })
            .collect();

        // Handle empty input case
        if raw_inputs.is_empty() {
            return Self {
                proofs,
                shared_inputs: vec![],
                partial_rhs_list: vec![],
                jwt_exp_list: vec![],
            };
        }

        // Index definitions for readability
        // 0: hanchor, 1: h_ctx, 2: root, 3: h_sign_userop, 4: jwt_exp,
        // 5: partial_rhs, 6: lhs, 7: h_aud_list
        const JWT_EXP_INDEX: usize = 4;
        const PARTIAL_RHS_INDEX: usize = 5;

        // Extract values that differ per request
        let jwt_exp_list: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| inputs[JWT_EXP_INDEX].to_string())
            .collect();

        let partial_rhs_list: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| inputs[PARTIAL_RHS_INDEX].to_string())
            .collect();

        // Extract shared inputs (values common to all requests)
        let shared_inputs: Vec<String> = raw_inputs[0]
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != JWT_EXP_INDEX && *i != PARTIAL_RHS_INDEX)
            .map(|(_, input)| input.to_string())
            .collect();

        Self {
            proofs,
            shared_inputs,
            partial_rhs_list,
            jwt_exp_list,
        }
    }
}
