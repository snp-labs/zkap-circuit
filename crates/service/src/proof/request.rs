//! Raw V2 proof request — V1-semantic, byte-array shape.
//!
//! [`RawProofRequest`] is the host-facing surface that the wasm runtime
//! consumes. All fields are raw bytes (BE-encoded field elements, RSA
//! big-endian byte strings, JWT byte buffers) so that bindings (Node,
//! UniFFI, React-Native) carry no hex/Base64 string parsing — the
//! conversion to canonical wire bytes happens at the caller.
//!
//! The request is split into three parts:
//! - file paths (host-only),
//! - [`ZkapSharedFields`] — fields constant across the K-credential batch,
//! - [`ZkapPerJwtFields`] — one entry per credential.

use std::path::PathBuf;

use ark_utils::wire::{CircuitConfig, ZkapInputV1};

use crate::error::ApplicationError;

/// Fields that are shared across every JWT in a K-credential batch.
#[derive(Debug, Clone)]
pub struct ZkapSharedFields {
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
pub struct ZkapPerJwtFields {
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

impl ZkapPerJwtFields {
    /// Compose this per-JWT slice with the batch-shared fields and the
    /// wire-format circuit config into a single [`ZkapInputV1`] payload.
    ///
    /// This replaces the 17-line ad-hoc mapping that previously lived
    /// in `proof/mod.rs`.
    pub fn to_zkap_input_v1(&self, shared: &ZkapSharedFields, cfg: &CircuitConfig) -> ZkapInputV1 {
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

/// Raw, unvalidated proof request received from the outside world.
///
/// `shared.anchor_values_be.len()` MUST equal `n - k + 1`,
/// `shared.anchor_known_x_be.len()` MUST equal `k`,
/// `shared.anchor_selector.len()` MUST equal `n`, and
/// `per_jwt.len()` MUST equal `k`. Length validation runs in
/// [`Self::validate`] and is also re-applied by the wasm-side
/// `into_circuit_input` for defense-in-depth.
#[derive(Debug, Clone)]
pub struct RawProofRequest {
    /// Path to the `.arzkey` proving key on disk.
    pub pk_path: PathBuf,
    /// Path to the `.wasm` witness-generator artifact paired with `pk_path`.
    pub wasm_path: PathBuf,
    /// Fields constant across all K credentials in this request.
    pub shared: ZkapSharedFields,
    /// Per-credential fields, one entry per JWT.
    pub per_jwt: Vec<ZkapPerJwtFields>,
}

impl RawProofRequest {
    /// Number of JWT credentials (`k`).
    pub fn token_count(&self) -> usize {
        self.per_jwt.len()
    }

    /// Validate the shared and per-JWT shapes against `params.k` / `params.n`.
    /// Catches host-side dimension bugs before the wasm boundary.
    pub fn validate(&self, k: usize, n: usize) -> Result<(), ApplicationError> {
        let expected_anchor_values = n - k + 1;
        if self.shared.anchor_values_be.len() != expected_anchor_values {
            return Err(ApplicationError::InvalidFormat(format!(
                "shared.anchor_values_be.len()={} but n - k + 1 = {}",
                self.shared.anchor_values_be.len(),
                expected_anchor_values
            )));
        }
        if self.shared.anchor_known_x_be.len() != k {
            return Err(ApplicationError::InvalidFormat(format!(
                "shared.anchor_known_x_be.len()={} but k={}",
                self.shared.anchor_known_x_be.len(),
                k
            )));
        }
        if self.shared.anchor_selector.len() != n {
            return Err(ApplicationError::InvalidFormat(format!(
                "shared.anchor_selector.len()={} but n={}",
                self.shared.anchor_selector.len(),
                n
            )));
        }
        if self.per_jwt.len() != k {
            return Err(ApplicationError::InvalidFormat(format!(
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

    fn empty_per_jwt() -> ZkapPerJwtFields {
        ZkapPerJwtFields {
            jwt_bytes: Vec::new(),
            rsa_modulus_be: Vec::new(),
            rsa_signature_be: Vec::new(),
            anchor_current_idx: 0,
            merkle_leaf_sibling_hash_be: [0u8; 32],
            merkle_auth_path_be: Vec::new(),
            merkle_leaf_idx: 0,
        }
    }

    fn empty(k: usize, n: usize) -> RawProofRequest {
        RawProofRequest {
            pk_path: PathBuf::from("/tmp/pk.arzkey"),
            wasm_path: PathBuf::from("/tmp/zkap.wasm"),
            shared: ZkapSharedFields {
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
        let raw = empty(3, 6);
        assert!(raw.validate(3, 6).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_anchor_values() {
        let mut raw = empty(3, 6);
        raw.shared.anchor_values_be.pop();
        let err = raw.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("anchor_values_be"));
    }

    #[test]
    fn validate_rejects_wrong_per_jwt_count() {
        let mut raw = empty(3, 6);
        raw.per_jwt.pop();
        let err = raw.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("per_jwt"));
    }

    #[test]
    fn validate_rejects_wrong_selector() {
        let mut raw = empty(3, 6);
        raw.shared.anchor_selector.pop();
        let err = raw.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("anchor_selector"));
    }
}
