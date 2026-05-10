//! Raw V2 proof request — V1-semantic, byte-array shape.
//!
//! [`RawProofRequest`] is the host-facing surface that the wasm runtime
//! consumes. All fields are raw bytes (BE-encoded field elements, RSA
//! big-endian byte strings, JWT byte buffers) so that bindings (Node,
//! UniFFI, React-Native) carry no hex/Base64 string parsing — the
//! conversion to canonical wire bytes happens at the caller.

use std::path::PathBuf;

use crate::error::ApplicationError;

/// Raw, unvalidated proof request received from the outside world.
///
/// All vectors that scale with K (the number of credentials) MUST have
/// length = K, and `anchor_values_be` MUST have length = `n - k + 1`.
/// Length validation runs in [`Self::validate`] and is also re-applied by
/// the wasm-side `into_circuit_input` for defense-in-depth.
#[derive(Debug, Clone)]
pub struct RawProofRequest {
    /// Path to the `.arzkey` proving key on disk.
    pub pk_path: PathBuf,
    /// Path to the `.wasm` witness-generator artifact paired with `pk_path`.
    pub wasm_path: PathBuf,

    // ---- shared (one copy across all K JWTs) ----
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

    // ---- per-JWT (length = k) ----
    /// Full JWT bytes per credential.
    pub jwt_bytes: Vec<Vec<u8>>,
    /// RSA-2048 modulus N as the natural big-endian byte string per JWT
    /// — each entry is exactly 256 bytes.
    pub rsa_modulus_be: Vec<Vec<u8>>,
    /// PKCS#1 v1.5 SHA-256 RSA-2048 signature, big-endian, per JWT.
    pub rsa_signature_be: Vec<Vec<u8>>,
    /// Anchor selector position this JWT claims (per JWT).
    pub anchor_current_idx: Vec<u64>,
    /// Merkle first-level sibling hash per JWT.
    pub merkle_leaf_sibling_hash_be: Vec<[u8; 32]>,
    /// Merkle inner-node sibling hashes per JWT — each entry has length =
    /// `tree_height - 1`.
    pub merkle_auth_path_be: Vec<Vec<[u8; 32]>>,
    /// Merkle leaf index per JWT.
    pub merkle_leaf_idx: Vec<u64>,
}

impl RawProofRequest {
    /// Number of JWT credentials (`k`).
    pub fn token_count(&self) -> usize {
        self.jwt_bytes.len()
    }

    /// Validate every per-JWT vector has the same length and that
    /// `anchor_values_be.len() == n - k + 1`. Cross-checks against
    /// `params.k` and `params.n` so a host bug surfaces here rather than
    /// inside the wasm boundary.
    pub fn validate(&self, k: usize, n: usize) -> Result<(), ApplicationError> {
        let expected_anchor_values = n - k + 1;
        if self.anchor_values_be.len() != expected_anchor_values {
            return Err(ApplicationError::InvalidFormat(format!(
                "anchor_values_be.len()={} but n - k + 1 = {}",
                self.anchor_values_be.len(),
                expected_anchor_values
            )));
        }
        if self.anchor_known_x_be.len() != k {
            return Err(ApplicationError::InvalidFormat(format!(
                "anchor_known_x_be.len()={} but k={}",
                self.anchor_known_x_be.len(),
                k
            )));
        }
        if self.anchor_selector.len() != n {
            return Err(ApplicationError::InvalidFormat(format!(
                "anchor_selector.len()={} but n={}",
                self.anchor_selector.len(),
                n
            )));
        }

        let per_jwt_lengths = [
            ("jwt_bytes", self.jwt_bytes.len()),
            ("rsa_modulus_be", self.rsa_modulus_be.len()),
            ("rsa_signature_be", self.rsa_signature_be.len()),
            ("anchor_current_idx", self.anchor_current_idx.len()),
            (
                "merkle_leaf_sibling_hash_be",
                self.merkle_leaf_sibling_hash_be.len(),
            ),
            ("merkle_auth_path_be", self.merkle_auth_path_be.len()),
            ("merkle_leaf_idx", self.merkle_leaf_idx.len()),
        ];
        for (name, len) in per_jwt_lengths {
            if len != k {
                return Err(ApplicationError::InvalidFormat(format!(
                    "{}.len()={} but k={}",
                    name, len, k
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(k: usize, n: usize) -> RawProofRequest {
        RawProofRequest {
            pk_path: PathBuf::from("/tmp/pk.arzkey"),
            wasm_path: PathBuf::from("/tmp/zkap.wasm"),
            random_be: [0u8; 32],
            h_sign_user_op_be: [0u8; 32],
            anchor_values_be: vec![[0u8; 32]; n - k + 1],
            anchor_known_x_be: vec![[0u8; 32]; k],
            anchor_selector: vec![0u8; n],
            merkle_root_be: [0u8; 32],
            jwt_bytes: vec![Vec::new(); k],
            rsa_modulus_be: vec![Vec::new(); k],
            rsa_signature_be: vec![Vec::new(); k],
            anchor_current_idx: vec![0u64; k],
            merkle_leaf_sibling_hash_be: vec![[0u8; 32]; k],
            merkle_auth_path_be: vec![Vec::new(); k],
            merkle_leaf_idx: vec![0u64; k],
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
        raw.anchor_values_be.pop();
        let err = raw.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("anchor_values_be"));
    }

    #[test]
    fn validate_rejects_wrong_per_jwt_count() {
        let mut raw = empty(3, 6);
        raw.rsa_signature_be.pop();
        let err = raw.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("rsa_signature_be"));
    }

    #[test]
    fn validate_rejects_wrong_selector() {
        let mut raw = empty(3, 6);
        raw.anchor_selector.pop();
        let err = raw.validate(3, 6).unwrap_err();
        assert!(format!("{}", err).contains("anchor_selector"));
    }
}
