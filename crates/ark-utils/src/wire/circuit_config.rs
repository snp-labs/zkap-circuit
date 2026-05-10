//! Single source-of-truth circuit-shape configuration for the V1 wire
//! schema. Absorbed verbatim from former `zkap-input-types` crate.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

/// Single source-of-truth circuit-shape configuration shared by:
/// - the V1 wire payload ([`super::ZkapInputV1::circuit_config`]),
/// - the circuit-side parameter struct (re-exported from
///   `circuit::constants::CircuitConfig`),
/// - host-side proof-request assembly (`zkap-service`).
///
/// String-typed fields (`claims`, `forbidden_string`) are kept as
/// `String` / `Vec<String>` for ergonomic JSON serialisation and for
/// canonical-byte parity with the legacy `RawCircuitConfig` JSON layout.
/// `CanonicalSerialize` of `String` produces the same bytes as
/// `CanonicalSerialize` of `Vec<u8>`, so `.arzkey` byte compatibility
/// is preserved across the consolidation.
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct CircuitConfig {
    pub max_jwt_b64_len: u64,
    pub max_payload_b64_len: u64,
    pub max_aud_len: u64,
    pub max_exp_len: u64,
    pub max_iss_len: u64,
    pub max_nonce_len: u64,
    pub max_sub_len: u64,
    pub n: u64,
    pub k: u64,
    pub tree_height: u64,
    pub num_audience_limit: u64,
    pub claims: Vec<String>,
    pub forbidden_string: String,
}

impl CircuitConfig {
    /// Validate the parameter constraints required by the ZKAP circuit.
    ///
    /// Checks that `k >= 1`, `k <= n`, `tree_height >= 1`, `max_payload_b64_len <= max_jwt_b64_len`,
    /// `num_audience_limit >= 1`, and that `claims` is non-empty.  Returns an error string
    /// describing the first violation found.
    pub fn validate(&self) -> Result<(), String> {
        if self.k < 1 {
            return Err(format!("k must be >= 1, got: {}", self.k));
        }
        if self.k > self.n {
            return Err(format!("k ({}) must be <= n ({})", self.k, self.n));
        }
        if self.n < 1 {
            return Err(format!("n must be >= 1, got: {}", self.n));
        }
        if self.tree_height < 1 {
            return Err(format!(
                "tree_height must be >= 1, got: {}",
                self.tree_height
            ));
        }
        if self.max_payload_b64_len > self.max_jwt_b64_len {
            return Err(format!(
                "max_payload_b64_len ({}) must be <= max_jwt_b64_len ({})",
                self.max_payload_b64_len, self.max_jwt_b64_len
            ));
        }
        if self.num_audience_limit < 1 {
            return Err(format!(
                "num_audience_limit must be >= 1, got: {}",
                self.num_audience_limit
            ));
        }
        if self.claims.is_empty() {
            return Err("claims must not be empty".into());
        }
        Ok(())
    }
}
