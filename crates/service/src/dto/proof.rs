//! Proof generation DTOs

use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::Proof;
use ark_utils::hex_decimal_to_field;
use circuit::constants::{BN254, F};

use crate::evm::solidity_types::Solidity;

/// Groth16 proof components in Solidity-compatible hex string format.
///
/// - `a`, `c`: BN254 G1 affine points — `[x, y]` (2 strings each)
/// - `b`: BN254 G2 affine point — `[bx_c1, bx_c0, by_c1, by_c0]` (4 strings)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofComponents {
    pub a: [String; 2],
    pub b: [String; 4],
    pub c: [String; 2],
}

impl From<&Proof<BN254>> for ProofComponents {
    fn from(proof: &Proof<BN254>) -> Self {
        let a = proof.a.to_solidity();
        let b = proof.b.to_solidity();
        let c = proof.c.to_solidity();
        ProofComponents {
            a: [a[0].clone(), a[1].clone()],
            b: [b[0].clone(), b[1].clone(), b[2].clone(), b[3].clone()],
            c: [c[0].clone(), c[1].clone()],
        }
    }
}

impl ProofComponents {
    /// Reconstruct a [`Proof<BN254>`] from string components.
    ///
    /// Used internally by [`crate::proof::verify`] to convert back to arkworks types
    /// without requiring callers to depend on `ark_groth16` directly.
    pub(crate) fn to_ark_proof(&self) -> Result<Proof<BN254>, crate::error::ApplicationError> {
        let parse = |s: &str| -> Result<Fq, crate::error::ApplicationError> {
            hex_decimal_to_field::<Fq>(s)
                .map_err(|e| crate::error::ApplicationError::ParseError(e.to_string()))
        };

        // Parse a (G1Affine): [ax, ay]
        let a = G1Affine::new(parse(&self.a[0])?, parse(&self.a[1])?);

        // Parse b (G2Affine): [bx_c1, bx_c0, by_c1, by_c0]
        // to_solidity() on Fp2 outputs [c1, c0], so index 0 = c1, index 1 = c0
        let bx = Fq2::new(parse(&self.b[1])?, parse(&self.b[0])?); // new(c0, c1)
        let by = Fq2::new(parse(&self.b[3])?, parse(&self.b[2])?);
        let b = G2Affine::new(bx, by);

        // Parse c (G1Affine): [cx, cy]
        let c = G1Affine::new(parse(&self.c[0])?, parse(&self.c[1])?);

        Ok(Proof { a, b, c })
    }
}

/// Proof generation response: Groth16 proofs with public inputs in Solidity-compatible format.
///
/// The `shared_inputs` field holds the 6 public input values common to all proofs in this batch:
/// `[hanchor, h_a, root, h_sign_user_op, lhs, h_aud_list]`.
/// Use [`ZkapProofResult::public_inputs_for`] to reconstruct the full 8-element public input
/// vector required for on-chain verification of proof at a given index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZkapProofResult {
    pub proofs: Vec<ProofComponents>,
    /// Public inputs shared across all proofs: `[hanchor, h_a, root, h_sign_user_op, lhs, h_aud_list]`
    pub shared_inputs: Vec<String>,
    /// Per-proof JWT expiration timestamps (one per credential)
    pub jwt_exp_list: Vec<String>,
    /// Per-proof verification RHS values (one per credential)
    pub verification_rhs_list: Vec<String>,
}

impl ZkapProofResult {
    /// Reconstruct the full 8-element public inputs vector for proof at `index`.
    ///
    /// Layout required by the Groth16 verifier:
    /// `[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]`
    ///
    /// Panics if `index >= proofs.len()` or `shared_inputs.len() < 6`.
    pub fn public_inputs_for(&self, index: usize) -> Vec<String> {
        // shared_inputs = [hanchor(0), h_a(1), root(2), h_sign_user_op(3), lhs(4), h_aud_list(5)]
        vec![
            self.shared_inputs[0].clone(), // hanchor
            self.shared_inputs[1].clone(), // h_a
            self.shared_inputs[2].clone(), // root
            self.shared_inputs[3].clone(), // h_sign_user_op
            self.jwt_exp_list[index].clone(),
            self.verification_rhs_list[index].clone(),
            self.shared_inputs[4].clone(), // lhs
            self.shared_inputs[5].clone(), // h_aud_list
        ]
    }
}

impl From<(Vec<Proof<BN254>>, Vec<Vec<F>>)> for ZkapProofResult {
    fn from(data: (Vec<Proof<BN254>>, Vec<Vec<F>>)) -> Self {
        let (raw_proofs, raw_inputs) = data;

        let proofs: Vec<ProofComponents> = raw_proofs.iter().map(ProofComponents::from).collect();

        if raw_inputs.is_empty() {
            return Self {
                proofs,
                shared_inputs: vec![],
                jwt_exp_list: vec![],
                verification_rhs_list: vec![],
            };
        }

        // Index definitions for public inputs:
        // 0: hanchor, 1: h_a, 2: root, 3: h_sign_userop, 4: jwt_exp,
        // 5: verification_rhs (partial_rhs), 6: lhs, 7: h_aud_list
        const JWT_EXP_INDEX: usize = 4;
        const VERIFICATION_RHS_INDEX: usize = 5;

        let jwt_exp_list: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| crate::field_to_hex(inputs[JWT_EXP_INDEX]))
            .collect();

        let verification_rhs_list: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| crate::field_to_hex(inputs[VERIFICATION_RHS_INDEX]))
            .collect();

        // Shared inputs: all indices except per-proof ones, taken from first proof's inputs
        let shared_inputs: Vec<String> = raw_inputs[0]
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != JWT_EXP_INDEX && *i != VERIFICATION_RHS_INDEX)
            .map(|(_, input)| crate::field_to_hex(*input))
            .collect();

        Self {
            proofs,
            shared_inputs,
            jwt_exp_list,
            verification_rhs_list,
        }
    }
}
