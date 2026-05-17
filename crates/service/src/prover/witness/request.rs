//! Native-path [`WitnessRequest`] — host-facing surface for the
//! post-migration prove flow.
//!
//! Lands as part of Commit 3 of the 2026-05 ark-ar1cs boundary
//! migration. The request carries **no** artifact paths — every
//! pre-migration field that pointed at on-disk bytes is gone.
//! Post-migration call sites pass the artifact bundle (e.g. via
//! `ArtifactSet`) to the prover separately, so a [`WitnessRequest`]
//! is a pure description of the credentials being proven and the
//! field elements that compose the public-input vector.

use crate::prover::witness::error::ZkapWitnessError;

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

/// Native-path proof request: no artifact paths, ready for in-process
/// witness shaping.
///
/// Shape invariants (re-checked by [`Self::validate`] and the deeper
/// [`crate::prover::witness::input::into_circuit_input`] conversion):
///
/// * `shared.anchor_values_be.len() == n - k + 1`
/// * `shared.anchor_known_x_be.len() == k`
/// * `shared.anchor_selector.len() == n`, cardinality = `k`
/// * `per_jwt.len() == k`
#[derive(Debug, Clone)]
pub struct WitnessRequest {
    /// Fields constant across all K credentials in this request.
    pub shared: SharedFields,
    /// Per-credential fields, one entry per JWT.
    pub per_jwt: Vec<PerJwtFields>,
}

impl WitnessRequest {
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

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::types::CircuitConfig;

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

    fn empty(k: usize, n: usize) -> WitnessRequest {
        WitnessRequest {
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

    fn cfg_n6_k3() -> CircuitConfig {
        CircuitConfig {
            max_jwt_b64_len: 1024,
            max_payload_b64_len: 640,
            max_aud_len: 155,
            max_exp_len: 20,
            max_iss_len: 93,
            max_nonce_len: 93,
            max_sub_len: 93,
            n: 6,
            k: 3,
            tree_height: 4,
            num_audience_limit: 5,
            claims: vec![
                "aud".into(),
                "exp".into(),
                "iss".into(),
                "nonce".into(),
                "sub".into(),
            ],
            forbidden_string: "forbidden".into(),
        }
    }

    fn populated_per_jwt(cfg: &CircuitConfig) -> PerJwtFields {
        PerJwtFields {
            jwt_bytes: Vec::new(),
            rsa_modulus_be: vec![0u8; 256],
            rsa_signature_be: vec![0u8; 256],
            anchor_current_idx: 0,
            merkle_leaf_sibling_hash_be: [0u8; 32],
            merkle_auth_path_be: vec![[0u8; 32]; (cfg.tree_height - 1) as usize],
            merkle_leaf_idx: 0,
        }
    }

    fn populated_request(cfg: &CircuitConfig) -> WitnessRequest {
        let n = cfg.n as usize;
        let k = cfg.k as usize;
        WitnessRequest {
            shared: SharedFields {
                random_be: [0u8; 32],
                h_sign_user_op_be: [0u8; 32],
                anchor_values_be: vec![[0u8; 32]; n - k + 1],
                anchor_known_x_be: vec![[0u8; 32]; k],
                anchor_selector: {
                    let mut s = vec![0u8; n];
                    for slot in s.iter_mut().take(k) {
                        *slot = 1;
                    }
                    s
                },
                merkle_root_be: [0u8; 32],
            },
            per_jwt: (0..k).map(|_| populated_per_jwt(cfg)).collect(),
        }
    }

    /// Compile-time check: [`WitnessRequest`] exposes only `shared` and
    /// `per_jwt` — no artifact-path fields slipped through the
    /// post-migration rename. If any such field reappears the
    /// destructure below stops compiling.
    #[test]
    fn witness_request_carries_no_artifact_paths() {
        let cfg = cfg_n6_k3();
        let req = populated_request(&cfg);

        let WitnessRequest { shared, per_jwt } = &req;
        let _ = (shared, per_jwt);
    }
}
