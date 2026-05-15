//! Proof generation response DTOs.

use ark_groth16::Proof;
use circuit::types::{BN254, F};

use zkap_evm_verifier::Solidity;

/// Groth16 proof components in Solidity-compatible hex string format.
///
/// - `a`, `c`: BN254 G1 affine points — `[x, y]` (2 strings each).
/// - `b`: BN254 G2 affine point — `[bx_c1, bx_c0, by_c1, by_c0]` (4 strings).
///
/// All strings are `0x`-prefixed lowercase big-endian hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
/// [`ProveResponse::public_inputs_for`]; see that method for the exact
/// index-to-name mapping the on-chain verifier consumes.
///
/// All strings are `0x`-prefixed lowercase big-endian hex BN254 Fr values.
///
/// `h_aud_list` is truly shared across the batch: the audience-list hash
/// is computed by [`crate::generate_audience_hashes`] over the
/// `k` credentials' `aud` values plus any padded `forbidden_string`
/// slots, so the same list necessarily applies to every proof in a
/// batch (different audience lists cannot share a batch).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SharedPublicInputs {
    /// `H(anchor)` — Poseidon chain hash of the threshold anchor,
    /// instance index 0. Pins the proof to a specific anchor without
    /// revealing it. Computed internally from
    /// [`crate::ProveRequest::anchor`].
    pub hanchor: String,
    /// `H(a)` — Poseidon hash of the per-batch `a` value,
    /// instance index 1.
    pub h_a: String,
    /// Merkle root of the per-batch identity tree, instance index 2.
    pub root: String,
    /// `H(sign_user_op)` — Poseidon hash of the user-operation
    /// signature digest, instance index 3.
    pub h_sign_user_op: String,
    /// Pairing-equation LHS commitment, instance index 6.
    pub lhs: String,
    /// `H(aud_list)` — Poseidon hash of the audience allow-list,
    /// instance index 7.
    pub h_aud_list: String,
}

/// Response from [`crate::Prover::prove`].
///
/// Per-credential public inputs are exposed as parallel `Vec`s
/// (`jwt_exp[i]` and `verification_rhs[i]` belong to the proof at
/// position `i`). All field-element strings in the response are
/// `0x`-prefixed lowercase big-endian hex.
///
/// **Length invariants** (always satisfied by a successful
/// [`crate::Prover::prove`] call):
/// - `proofs.len() == jwt_exp.len() == verification_rhs.len() == config.k`.
///
/// Use [`Self::public_inputs_for`] to reconstruct the ordered 8-element
/// instance vector required by the on-chain or in-process Groth16
/// verifier for any proof in the batch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProveResponse {
    /// One Groth16 proof per credential, in the same order as the
    /// per-credential entries of the originating
    /// [`crate::ProveRequest::credentials`].
    pub proofs: Vec<ProofComponents>,
    /// Public inputs shared across every proof in the batch.
    pub shared_public_inputs: SharedPublicInputs,
    /// Per-credential JWT `exp` claim packed into a BN254 Fr, instance
    /// index 4. `jwt_exp[i]` pairs with `proofs[i]`.
    pub jwt_exp: Vec<String>,
    /// Per-credential RHS of the threshold-scheme pairing equation,
    /// instance index 5. `verification_rhs[i]` pairs with `proofs[i]`.
    pub verification_rhs: Vec<String>,
}

impl ProveResponse {
    /// Reconstruct the ordered 8-element public-input vector for the
    /// proof at `index`, in the order expected by the Groth16 verifier:
    ///
    /// `[hanchor, h_a, root, h_sign_user_op, jwt_exp[index],
    ///   verification_rhs[index], lhs, h_aud_list]`
    ///
    /// Panics if `index >= self.jwt_exp.len()`.
    pub fn public_inputs_for(&self, index: usize) -> Vec<String> {
        vec![
            self.shared_public_inputs.hanchor.clone(),
            self.shared_public_inputs.h_a.clone(),
            self.shared_public_inputs.root.clone(),
            self.shared_public_inputs.h_sign_user_op.clone(),
            self.jwt_exp[index].clone(),
            self.verification_rhs[index].clone(),
            self.shared_public_inputs.lhs.clone(),
            self.shared_public_inputs.h_aud_list.clone(),
        ]
    }
}

impl From<(Vec<Proof<BN254>>, Vec<Vec<F>>)> for ProveResponse {
    fn from(data: (Vec<Proof<BN254>>, Vec<Vec<F>>)) -> Self {
        let (raw_proofs, raw_inputs) = data;

        let proofs: Vec<ProofComponents> = raw_proofs.iter().map(ProofComponents::from).collect();

        if raw_inputs.is_empty() {
            return Self {
                proofs,
                shared_public_inputs: SharedPublicInputs::default(),
                jwt_exp: vec![],
                verification_rhs: vec![],
            };
        }

        // Canonical 8-element instance layout (per proof):
        //   [hanchor(0), h_a(1), root(2), h_sign_user_op(3),
        //    jwt_exp(4), verification_rhs(5), lhs(6), h_aud_list(7)]
        // Shared values come from the first proof — they are constant
        // across the batch.
        let first = &raw_inputs[0];
        let shared_public_inputs = SharedPublicInputs {
            hanchor: crate::field_to_hex(first[0]),
            h_a: crate::field_to_hex(first[1]),
            root: crate::field_to_hex(first[2]),
            h_sign_user_op: crate::field_to_hex(first[3]),
            lhs: crate::field_to_hex(first[6]),
            h_aud_list: crate::field_to_hex(first[7]),
        };

        let jwt_exp: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| crate::field_to_hex(inputs[4]))
            .collect();
        let verification_rhs: Vec<String> = raw_inputs
            .iter()
            .map(|inputs| crate::field_to_hex(inputs[5]))
            .collect();

        Self {
            proofs,
            shared_public_inputs,
            jwt_exp,
            verification_rhs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof_components() -> ProofComponents {
        ProofComponents {
            a: ["0x01".into(), "0x02".into()],
            b: [
                "0x03".into(),
                "0x04".into(),
                "0x05".into(),
                "0x06".into(),
            ],
            c: ["0x07".into(), "0x08".into()],
        }
    }

    fn sample_shared() -> SharedPublicInputs {
        SharedPublicInputs {
            hanchor: "0xaa".into(),
            h_a: "0xbb".into(),
            root: "0xcc".into(),
            h_sign_user_op: "0xdd".into(),
            lhs: "0xee".into(),
            h_aud_list: "0xff".into(),
        }
    }

    fn sample_response() -> ProveResponse {
        ProveResponse {
            proofs: vec![sample_proof_components(), sample_proof_components()],
            shared_public_inputs: sample_shared(),
            jwt_exp: vec!["0x11".into(), "0x12".into()],
            verification_rhs: vec!["0x21".into(), "0x22".into()],
        }
    }

    #[test]
    fn public_inputs_for_emits_canonical_layout() {
        let resp = sample_response();
        let v0 = resp.public_inputs_for(0);
        assert_eq!(
            v0,
            vec![
                "0xaa".to_string(), // hanchor
                "0xbb".into(),      // h_a
                "0xcc".into(),      // root
                "0xdd".into(),      // h_sign_user_op
                "0x11".into(),      // jwt_exp[0]
                "0x21".into(),      // verification_rhs[0]
                "0xee".into(),      // lhs
                "0xff".into(),      // h_aud_list
            ]
        );
        let v1 = resp.public_inputs_for(1);
        assert_eq!(v1[4], "0x12");
        assert_eq!(v1[5], "0x22");
    }

    #[test]
    fn prove_response_serde_round_trip() {
        let resp = sample_response();
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: ProveResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(resp, back);
    }
}
