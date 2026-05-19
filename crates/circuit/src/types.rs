//! Protocol type aliases for the ZKAP circuit.
//!
//! This module collects the concrete curve/field/hash choices used throughout
//! the crate as a single set of type aliases:
//!
//! | Alias          | Concrete type                              |
//! |----------------|--------------------------------------------|
//! | `F`            | BN254 base field (`ark_ed_on_bn254`)       |
//! | `CG`           | `ark_ed_on_bn254::EdwardsProjective`       |
//! | `BNP`          | `BigNat2048Params` (2048-bit, 64-bit limbs)|
//! | `PoseidonHash` | `CRH<F>`                                   |
//! | `BN254`        | `ark_bn254::Bn254` (pairing engine)        |
//! | `PAD_CHAR`     | `'\0'` — SHA-256 padding sentinel          |
//!
//! [`CircuitConfig`] is the single canonical runtime-parameter type
//! shared across all crates.

use std::fmt::Debug;

use ark_crypto_primitives::crh::poseidon::CRH;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use gadget::bigint::constraints::BigNatCircuitParams;
use serde::{Deserialize, Serialize};

/// SHA-256 padding sentinel character used by host-side string→field
/// conversions to fill the unused tail of fixed-length claim buffers.
pub const PAD_CHAR: char = '\0';

/// Single source-of-truth circuit-shape configuration shared by:
/// - the circuit-side parameter struct,
/// - host-side proof-request assembly (`zkap-service`).
///
/// String-typed fields (`claims`, `forbidden_string`) are kept as
/// `String` / `Vec<String>` for ergonomic JSON serialisation.
/// `CanonicalSerialize` of `String` produces the same bytes as
/// `CanonicalSerialize` of `Vec<u8>`, so the on-disk byte stream stays
/// stable across the consolidation.
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct CircuitConfig {
    /// Maximum length, in bytes, of the base64-encoded JWT input.
    pub max_jwt_b64_len: u64,
    /// Maximum length, in bytes, of the base64-encoded JWT payload section.
    pub max_payload_b64_len: u64,
    /// Maximum length, in bytes, of the JWT `aud` claim value.
    pub max_aud_len: u64,
    /// Maximum length, in bytes, of the JWT `exp` claim value.
    pub max_exp_len: u64,
    /// Maximum length, in bytes, of the JWT `iss` claim value.
    pub max_iss_len: u64,
    /// Maximum length, in bytes, of the JWT `nonce` claim value.
    pub max_nonce_len: u64,
    /// Maximum length, in bytes, of the JWT `sub` claim value.
    pub max_sub_len: u64,
    /// Total number of secret shares in the threshold setup.
    pub n: u64,
    /// Threshold (recovery quorum size); must satisfy `1 <= k <= n`.
    pub k: u64,
    /// Depth of the audience Merkle tree.
    pub tree_height: u64,
    /// Maximum number of audience entries permitted in a single proof.
    pub num_audience_limit: u64,
    /// Required JWT claim names, in the order the circuit expects to
    /// extract them.
    pub claims: Vec<String>,
    /// Reserved string that must not appear inside any extracted claim
    /// (forbidden-substring guard).
    pub forbidden_string: String,
}

/// Validation error returned by [`CircuitConfig::validate`].
#[derive(Debug, thiserror::Error)]
pub enum CircuitConfigError {
    /// `k` must be at least 1.
    #[error("k must be >= 1, got: {0}")]
    InvalidK(u64),
    /// `k` must not exceed `n`.
    #[error("k ({k}) must be <= n ({n})")]
    KExceedsN {
        /// Observed `k`.
        k: u64,
        /// Observed `n`.
        n: u64,
    },
    /// `n` must be at least 1.
    #[error("n must be >= 1, got: {0}")]
    InvalidN(u64),
    /// `tree_height` must be at least 1.
    #[error("tree_height must be >= 1, got: {0}")]
    InvalidTreeHeight(u64),
    /// `max_payload_b64_len` must not exceed `max_jwt_b64_len`.
    #[error("max_payload_b64_len ({payload}) must be <= max_jwt_b64_len ({jwt})")]
    PayloadExceedsJwt {
        /// Observed payload length.
        payload: u64,
        /// Observed JWT length.
        jwt: u64,
    },
    /// `num_audience_limit` must be at least 1.
    #[error("num_audience_limit must be >= 1, got: {0}")]
    InvalidNumAudienceLimit(u64),
    /// `claims` must not be empty.
    #[error("claims must not be empty")]
    EmptyClaims,
    /// A claim-length field fed to `pack_bytes_to_field_native` must be a
    /// multiple of 31 (the BN254 limb width).  Any other value causes
    /// `chunks(31)` to silently drop trailing bytes, corrupting field
    /// elements.
    #[error("{field} must be a multiple of 31 (got {value})")]
    ClaimLenNotMultipleOf31 {
        /// Name of the offending field (e.g. `"max_aud_len"`).
        field: &'static str,
        /// Observed value.
        value: u64,
    },
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
            return Err(CircuitConfigError::KExceedsN {
                k: self.k,
                n: self.n,
            });
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
            return Err(CircuitConfigError::InvalidNumAudienceLimit(
                self.num_audience_limit,
            ));
        }
        if self.claims.is_empty() {
            return Err(CircuitConfigError::EmptyClaims);
        }
        // `pack_bytes_to_field_native` packs bytes into BN254 field elements
        // using 31-byte chunks.  Any `max_*_len` that is not a multiple of 31
        // causes `chunks(31)` to silently drop trailing bytes, corrupting the
        // resulting field elements.  Catch this at config-load time so the
        // error surfaces before any proof attempt.
        for (field, value) in [
            ("max_aud_len", self.max_aud_len),
            ("max_iss_len", self.max_iss_len),
            ("max_sub_len", self.max_sub_len),
        ] {
            if value % 31 != 0 {
                return Err(CircuitConfigError::ClaimLenNotMultipleOf31 { field, value });
            }
        }
        Ok(())
    }
}

const LAMBDA: usize = 2048; // 2048 bits

/// 2048-bit `BigNatCircuitParams` instantiation used by the RSA-2048
/// signature gadget — 32 limbs of 64 bits each.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat2048Params;
impl BigNatCircuitParams for BigNat2048Params {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

/// `ark_ed_on_bn254::EdwardsProjective` — the inner curve whose base
/// field [`F`] hosts every R1CS variable in the circuit.
pub type CG = ark_ed_on_bn254::EdwardsProjective;
/// Base field of [`CG`]; the protocol field used by every R1CS gadget.
pub type F = <CG as ark_ec::CurveGroup>::BaseField;
/// Poseidon CRH instantiated over [`F`].
pub type PoseidonHash = CRH<F>;
/// `ark_bn254::Bn254` — the pairing engine used by Groth16.
pub type BN254 = ark_bn254::Bn254;
/// 2048-bit BigNat parameters used by RSA-2048 verification inside the ZKAP
/// circuit. The `2048` matches the JWT signing key size — RSA limbs are
/// packed into BN254 field elements via `BigNat2048Params`'s 64-bit limb
/// schedule. Used as the `BNP` type parameter on [`crate::zkap::ZkapCircuit`].
pub type BNP = BigNat2048Params;

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline valid config used as a starting point for mutation tests.
    /// All `max_*_len` values that feed `pack_bytes_to_field_native` are
    /// multiples of 31 (93 = 3 × 31, 155 = 5 × 31).
    fn valid_config() -> CircuitConfig {
        CircuitConfig {
            max_jwt_b64_len: 1024,
            max_payload_b64_len: 640,
            max_aud_len: 155, // 5 × 31
            max_exp_len: 20,
            max_iss_len: 93, // 3 × 31
            max_nonce_len: 93,
            max_sub_len: 93, // 3 × 31
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

    #[test]
    fn validate_accepts_multiple_of_31() {
        // 93 = 3 × 31 and 155 = 5 × 31 — all claim-length fields are valid.
        let cfg = valid_config();
        cfg.validate().expect("valid config must pass validation");
    }

    #[test]
    fn validate_rejects_non_multiple_of_31_max_aud_len() {
        let mut cfg = valid_config();
        cfg.max_aud_len = 100; // 100 % 31 = 7 — invalid
        match cfg.validate() {
            Err(CircuitConfigError::ClaimLenNotMultipleOf31 { field, value }) => {
                assert!(
                    field.contains("max_aud_len"),
                    "expected max_aud_len in error, got: {field}"
                );
                assert_eq!(value, 100);
            }
            other => panic!("expected ClaimLenNotMultipleOf31, got: {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_non_multiple_of_31_max_iss_len() {
        let mut cfg = valid_config();
        cfg.max_iss_len = 100; // 100 % 31 = 7 — invalid
        match cfg.validate() {
            Err(CircuitConfigError::ClaimLenNotMultipleOf31 { field, value }) => {
                assert!(
                    field.contains("max_iss_len"),
                    "expected max_iss_len in error, got: {field}"
                );
                assert_eq!(value, 100);
            }
            other => panic!("expected ClaimLenNotMultipleOf31, got: {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_non_multiple_of_31_max_sub_len() {
        let mut cfg = valid_config();
        cfg.max_sub_len = 100; // 100 % 31 = 7 — invalid
        match cfg.validate() {
            Err(CircuitConfigError::ClaimLenNotMultipleOf31 { field, value }) => {
                assert!(
                    field.contains("max_sub_len"),
                    "expected max_sub_len in error, got: {field}"
                );
                assert_eq!(value, 100);
            }
            other => panic!("expected ClaimLenNotMultipleOf31, got: {:?}", other),
        }
    }

    #[test]
    fn validate_accepts_zero_claim_len() {
        // Zero is a multiple of 31 (0 % 31 == 0), so it passes the
        // 31-divisibility check.  Other constraints (e.g. shape checks in the
        // prover) may later reject zero-length claims, but validate() itself
        // must accept it.
        let mut cfg = valid_config();
        cfg.max_aud_len = 0;
        cfg.max_iss_len = 0;
        cfg.max_sub_len = 0;
        cfg.validate()
            .expect("zero is a multiple of 31 — validate must accept it");
    }
}
