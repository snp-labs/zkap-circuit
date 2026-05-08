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

/// Validation error returned by [`CircuitConfig::validate`].
#[derive(Debug, thiserror::Error)]
pub enum CircuitConfigError {
    #[error("k must be >= 1, got: {0}")]
    InvalidK(u64),
    #[error("k ({k}) must be <= n ({n})")]
    KExceedsN { k: u64, n: u64 },
    #[error("n must be >= 1, got: {0}")]
    InvalidN(u64),
    #[error("tree_height must be >= 1, got: {0}")]
    InvalidTreeHeight(u64),
    #[error("max_payload_b64_len ({payload}) must be <= max_jwt_b64_len ({jwt})")]
    PayloadExceedsJwt { payload: u64, jwt: u64 },
    #[error("num_audience_limit must be >= 1, got: {0}")]
    InvalidNumAudienceLimit(u64),
    #[error("claims must not be empty")]
    EmptyClaims,
}

impl CircuitConfig {
    /// Validate the parameter constraints required by the ZKAP circuit.
    ///
    /// Checks that `k >= 1`, `k <= n`, `n >= 1`, `tree_height >= 1`,
    /// `max_payload_b64_len <= max_jwt_b64_len`, `num_audience_limit >= 1`,
    /// and that `claims` is non-empty.  Returns the first violation found.
    pub fn validate(&self) -> Result<(), CircuitConfigError> {
        if self.k < 1 {
            return Err(CircuitConfigError::InvalidK(self.k));
        }
        if self.k > self.n {
            return Err(CircuitConfigError::KExceedsN { k: self.k, n: self.n });
        }
        if self.n < 1 {
            return Err(CircuitConfigError::InvalidN(self.n));
        }
        if self.tree_height < 1 {
            return Err(CircuitConfigError::InvalidTreeHeight(self.tree_height));
        }
        if self.max_payload_b64_len > self.max_jwt_b64_len {
            return Err(CircuitConfigError::PayloadExceedsJwt {
                payload: self.max_payload_b64_len,
                jwt: self.max_jwt_b64_len,
            });
        }
        if self.num_audience_limit < 1 {
            return Err(CircuitConfigError::InvalidNumAudienceLimit(self.num_audience_limit));
        }
        if self.claims.is_empty() {
            return Err(CircuitConfigError::EmptyClaims);
        }
        Ok(())
    }
}
