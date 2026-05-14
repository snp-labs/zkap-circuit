//! Native-path [`ProofRequest`] — host-facing surface for the
//! post-migration prove flow.
//!
//! Lands as part of Commit 3 of the 2026-05 ark-ar1cs boundary
//! migration. The request carries **no** artifact paths — every
//! pre-migration field that pointed at on-disk bytes is gone.
//! Post-migration call sites pass the artifact bundle (e.g. via
//! `ArtifactSet`) to the prover separately, so a [`ProofRequest`]
//! is a pure description of the credentials being proven and the
//! field elements that compose the public-input vector.

use ark_utils::wire::ZkapInputV1;
use circuit::types::CircuitConfig;

use crate::witness::error::ZkapWitnessError;

/// Fields shared across every JWT in a K-credential batch.
#[derive(Debug, Clone)]
pub struct SharedFields {
    /// Big-endian field encoding of the proof's blinding `random` scalar.
    pub random_be: [u8; 32],
    /// Big-endian field encoding of `h_sign_user_op` (public input).
    pub h_sign_user_op_be: [u8; 32],
    /// Anchor scalar list — length = `n - k + 1`.
    pub anchor_values_be: Vec<[u8; 32]>,
    /// Known-secret list — length = `k`.
    pub anchor_known_x_be: Vec<[u8; 32]>,
    /// Selector vector — boolean values in `0/1`. Length = `n`,
    /// cardinality = `k`.
    pub anchor_selector: Vec<u8>,
    /// Merkle root (public input `root`).
    pub merkle_root_be: [u8; 32],
}

/// Per-credential fields (one entry per JWT in the batch).
#[derive(Debug, Clone)]
pub struct PerJwtFields {
    /// Full JWT bytes.
    pub jwt_bytes: Vec<u8>,
    /// RSA-2048 modulus N as the natural big-endian byte string — exactly
    /// 256 bytes.
    pub rsa_modulus_be: Vec<u8>,
    /// PKCS#1 v1.5 SHA-256 RSA-2048 signature, big-endian.
    pub rsa_signature_be: Vec<u8>,
    /// Anchor selector position this JWT claims.
    pub anchor_current_idx: u64,
    /// Merkle first-level sibling hash.
    pub merkle_leaf_sibling_hash_be: [u8; 32],
    /// Merkle inner-node sibling hashes — length = `tree_height - 1`.
    pub merkle_auth_path_be: Vec<[u8; 32]>,
    /// Merkle leaf index.
    pub merkle_leaf_idx: u64,
}

impl PerJwtFields {
    /// Compose this per-JWT slice with the batch-shared fields and the
    /// wire-format circuit config into a single [`ZkapInputV1`] payload.
    pub fn to_zkap_input_v1(&self, shared: &SharedFields, cfg: &CircuitConfig) -> ZkapInputV1 {
        ZkapInputV1 {
            jwt_bytes: self.jwt_bytes.clone(),
            rsa_modulus_be: self.rsa_modulus_be.clone(),
            rsa_signature_be: self.rsa_signature_be.clone(),
            random_be: shared.random_be,
            h_sign_user_op_be: shared.h_sign_user_op_be,
            anchor_values_be: shared.anchor_values_be.clone(),
            anchor_known_x_be: shared.anchor_known_x_be.clone(),
            anchor_selector: shared.anchor_selector.clone(),
            anchor_current_idx: self.anchor_current_idx,
            merkle_root_be: shared.merkle_root_be,
            merkle_leaf_sibling_hash_be: self.merkle_leaf_sibling_hash_be,
            merkle_auth_path_be: self.merkle_auth_path_be.clone(),
            merkle_leaf_idx: self.merkle_leaf_idx,
            circuit_config: cfg.clone(),
        }
    }
}

/// Native-path proof request: no artifact paths, ready for in-process
/// witness shaping.
///
/// Shape invariants (re-checked by [`Self::validate`] and the deeper
/// [`crate::witness::input::into_circuit_input`] conversion):
///
/// * `shared.anchor_values_be.len() == n - k + 1`
/// * `shared.anchor_known_x_be.len() == k`
/// * `shared.anchor_selector.len() == n`, cardinality = `k`
/// * `per_jwt.len() == k`
#[derive(Debug, Clone)]
pub struct ProofRequest {
    /// Fields constant across all K credentials in this request.
    pub shared: SharedFields,
    /// Per-credential fields, one entry per JWT.
    pub per_jwt: Vec<PerJwtFields>,
}

impl ProofRequest {
    /// Number of JWT credentials (`k`).
    pub fn token_count(&self) -> usize {
        self.per_jwt.len()
    }

    /// Validate the shared and per-JWT shapes against `params.k` /
    /// `params.n`. Catches host-side dimension bugs before the heavier
    /// `ZkapCircuitInput` conversion runs.
    pub fn validate(&self, k: usize, n: usize) -> Result<(), ZkapWitnessError> {
        let expected_anchor_values = n - k + 1;
        if self.shared.anchor_values_be.len() != expected_anchor_values {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "shared.anchor_values_be.len()={} but n - k + 1 = {}",
                self.shared.anchor_values_be.len(),
                expected_anchor_values
            )));
        }
        if self.shared.anchor_known_x_be.len() != k {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "shared.anchor_known_x_be.len()={} but k={}",
                self.shared.anchor_known_x_be.len(),
                k
            )));
        }
        if self.shared.anchor_selector.len() != n {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "shared.anchor_selector.len()={} but n={}",
                self.shared.anchor_selector.len(),
                n
            )));
        }
        if self.per_jwt.len() != k {
            return Err(ZkapWitnessError::DimensionMismatch(format!(
                "per_jwt.len()={} but k={}",
                self.per_jwt.len(),
                k
            )));
        }
        Ok(())
    }
}

/// Build a `Vec<ZkapInputV1>` from a [`ProofRequest`] and circuit config.
///
/// Validates the request shape against `(cfg.k, cfg.n)`, then composes
/// one [`ZkapInputV1`] per JWT. Each output payload is ready to feed
/// into [`crate::witness::input::into_circuit_input`] (native prove
/// path) without any further preprocessing.
pub fn build_input(
    req: &ProofRequest,
    cfg: &CircuitConfig,
) -> Result<Vec<ZkapInputV1>, ZkapWitnessError> {
    let k = cfg.k as usize;
    let n = cfg.n as usize;
    req.validate(k, n)?;
    Ok(req
        .per_jwt
        .iter()
        .map(|jwt| jwt.to_zkap_input_v1(&req.shared, cfg))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_per_jwt() -> PerJwtFields {
        PerJwtFields {
            jwt_bytes: Vec::new(),
            rsa_modulus_be: Vec::new(),
            rsa_signature_be: Vec::new(),
            anchor_current_idx: 0,
            merkle_leaf_sibling_hash_be: [0u8; 32],
            merkle_auth_path_be: Vec::new(),
            merkle_leaf_idx: 0,
        }
    }

    fn empty(k: usize, n: usize) -> ProofRequest {
        ProofRequest {
            shared: SharedFields {
                random_be: [0u8; 32],
                h_sign_user_op_be: [0u8; 32],
                anchor_values_be: vec![[0u8; 32]; n - k + 1],
                anchor_known_x_be: vec![[0u8; 32]; k],
                anchor_selector: vec![0u8; n],
                merkle_root_be: [0u8; 32],
            },
            per_jwt: (0..k).map(|_| empty_per_jwt()).collect(),
        }
    }

    #[test]
    fn validate_accepts_consistent_shape() {
        let req = empty(3, 6);
        assert!(req.validate(3, 6).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_anchor_values() {
        let mut req = empty(3, 6);
        req.shared.anchor_values_be.pop();
        let err = req.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("anchor_values_be"));
    }

    #[test]
    fn validate_rejects_wrong_per_jwt_count() {
        let mut req = empty(3, 6);
        req.per_jwt.pop();
        let err = req.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("per_jwt"));
    }

    #[test]
    fn validate_rejects_wrong_selector() {
        let mut req = empty(3, 6);
        req.shared.anchor_selector.pop();
        let err = req.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("anchor_selector"));
    }
}
