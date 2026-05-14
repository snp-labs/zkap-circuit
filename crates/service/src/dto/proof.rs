//! Proof generation DTOs

use ark_groth16::Proof;
use circuit::types::{BN254, F};

use zkap_evm_verifier::Solidity;

/// Groth16 proof components in Solidity-compatible hex string format.
///
/// - `a`, `c`: BN254 G1 affine points — `[x, y]` (2 strings each)
/// - `b`: BN254 G2 affine point — `[bx_c1, bx_c0, by_c1, by_c0]` (4 strings)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofComponents {
    /// `[a.x, a.y]` — first G1 component of the Groth16 proof, in
    /// hex strings matching the Solidity verifier's word ordering.
    pub a: [String; 2],
    /// `[b.x.c1, b.x.c0, b.y.c1, b.y.c0]` — G2 component with each
    /// Fp2 coordinate emitted in Solidity's reversed `(c1, c0)` order.
    pub b: [String; 4],
    /// `[c.x, c.y]` — third G1 component of the Groth16 proof.
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

/// Public inputs that are shared across all proofs in a batch.
///
/// Field names mirror the canonical 8-element instance vector emitted by
/// [`ZkapProofResult::public_inputs_for`]; see that method for the exact
/// index-to-name mapping the on-chain verifier consumes.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SharedPublicInputs {
    /// `H(anchor)` — Poseidon hash of the threshold anchor, instance index 0.
    /// Pins the proof to a specific anchor without revealing it.
    pub hanchor: String,
    /// `H(a)` — Poseidon hash of the per-batch `a` value, instance index 1.
    /// Common to all proofs because `a` is fixed per batch.
    pub h_a: String,
    /// Merkle root of the per-batch identity tree, instance index 2.
    pub root: String,
    /// `H(sign_user_op)` — Poseidon hash of the user-operation signature
    /// digest, instance index 3. Pins the proof to a specific tx without
    /// exposing its contents.
    pub h_sign_user_op: String,
    /// Pairing-equation LHS commitment, instance index 6. Decoupled from
    /// the per-proof `verification_rhs` so a single LHS verifies the full
    /// batch.
    pub lhs: String,
    /// `H(aud_list)` — Poseidon hash of the audience allow-list, instance
    /// index 7. Pins the proof to a specific aud-list shape without
    /// disclosing the contents.
    pub h_aud_list: String,
}

/// Per-proof public inputs (one per credential in the batch).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerProofPublicInputs {
    /// JWT `exp` (expiry, seconds-since-epoch) bound to this proof,
    /// instance index 4. Per-proof so each credential's expiry is checked
    /// independently.
    pub jwt_exp: String,
    /// Pairing-equation RHS commitment for this proof, instance index 5.
    /// Per-proof counterpart to the batch-level [`SharedPublicInputs::lhs`].
    pub verification_rhs: String,
}

/// Proof generation response: Groth16 proofs + public inputs split into shared + per-proof parts.
///
/// Use [`ZkapProofResult::public_inputs_for`] to reconstruct the full 8-element public input
/// vector required for on-chain verification of the proof at a given index.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ZkapProofResult {
    /// One Groth16 proof per JWT in the batch. Indexed in the same order
    /// as [`Self::per_proof`].
    pub proofs: Vec<ProofComponents>,
    /// Public inputs that are constant across the batch (anchor, root,
    /// audience hash, etc.) — split out so they don't need to be repeated
    /// per proof in transit.
    pub shared: SharedPublicInputs,
    /// Per-proof public inputs (jwt_exp + RHS commitment). Length matches
    /// [`Self::proofs`]; entry `i` pairs with `proofs[i]`.
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
