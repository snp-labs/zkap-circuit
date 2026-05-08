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
            hex_decimal_to_field::<Fq>(s).map_err(crate::error::ApplicationError::from)
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

/// Public inputs that are shared across all proofs in a batch.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SharedPublicInputs {
    pub hanchor: String,
    pub h_a: String,
    pub root: String,
    pub h_sign_user_op: String,
    pub lhs: String,
    pub h_aud_list: String,
}

/// Per-proof public inputs (one per credential in the batch).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerProofPublicInputs {
    pub jwt_exp: String,
    pub verification_rhs: String,
}

/// Proof generation response: Groth16 proofs + public inputs split into shared + per-proof parts.
///
/// Use [`ZkapProofResult::public_inputs_for`] to reconstruct the full 8-element public input
/// vector required for on-chain verification of the proof at a given index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZkapProofResult {
    pub proofs: Vec<ProofComponents>,
    pub shared: SharedPublicInputs,
    pub per_proof: Vec<PerProofPublicInputs>,
}

impl ZkapProofResult {
    /// Reconstruct the full 8-element public inputs vector for proof at `index`.
    ///
    /// Layout required by the Groth16 verifier:
    /// `[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]`
    ///
    /// Panics if `index >= per_proof.len()`.
    pub fn public_inputs_for(&self, index: usize) -> Vec<String> {
        let p = &self.per_proof[index];
        vec![
            self.shared.hanchor.clone(),
            self.shared.h_a.clone(),
            self.shared.root.clone(),
            self.shared.h_sign_user_op.clone(),
            p.jwt_exp.clone(),
            p.verification_rhs.clone(),
            self.shared.lhs.clone(),
            self.shared.h_aud_list.clone(),
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
                shared: SharedPublicInputs::default(),
                per_proof: vec![],
            };
        }

        // arwtns instance layout (8 elements per proof):
        //   [hanchor(0), h_a(1), root(2), h_sign_user_op(3),
        //    jwt_exp(4), verification_rhs(5), lhs(6), h_aud_list(7)]
        // shared values are taken from the first proof — they are constant across the batch.
        let first = &raw_inputs[0];
        let shared = SharedPublicInputs {
            hanchor: crate::field_to_hex(first[0]),
            h_a: crate::field_to_hex(first[1]),
            root: crate::field_to_hex(first[2]),
            h_sign_user_op: crate::field_to_hex(first[3]),
            lhs: crate::field_to_hex(first[6]),
            h_aud_list: crate::field_to_hex(first[7]),
        };

        let per_proof: Vec<PerProofPublicInputs> = raw_inputs
            .iter()
            .map(|inputs| PerProofPublicInputs {
                jwt_exp: crate::field_to_hex(inputs[4]),
                verification_rhs: crate::field_to_hex(inputs[5]),
            })
            .collect();

        Self {
            proofs,
            shared,
            per_proof,
        }
    }
}
