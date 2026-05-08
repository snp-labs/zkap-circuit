//! Token-related types and gadgets for JWT claim verification.
//!
//! Sub-modules:
//! - [`claimverifier`] — R1CS gadgets for claim extraction and format verification
//!   (`claim_extractor_v2`, `claim_format_verifier_v2`)
//! - [`claim_indices`] — [`ClaimIndicesVar`] R1CS variable + `AllocVar` impl
//! - [`rsa`] — [`RSA2048VerifyGadget`] RSA-2048 PKCS#1 signature verification
//! - [`jwt_field`] — byte-to-field converters for JWT nonce (hex) and expiry (decimal)
//! - [`constraints`] — backward-compatible re-export of `claim_indices` + `rsa`
//!
//! Host-side data:
//! - [`ClaimIndices`] — plain indices describing a claim's position in the JWT payload
//!   (zeroed `ClaimIndices::default()` is the placeholder for trusted setup)
//! - [`Claim`] — host-only struct combining key, value, and indices; not used in R1CS

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub mod claim_indices;
pub mod claimverifier;
pub mod jwt_field;
pub mod rsa;

/// Backward-compatible re-export of [`claim_indices`] and [`rsa`] contents.
///
/// Existing code using `token::constraints::ClaimIndicesVar` or
/// `token::constraints::RSA2048VerifyGadget` continues to compile unchanged.
pub mod constraints {
    pub use super::claim_indices::ClaimIndicesVar;
    pub use super::rsa::RSA2048VerifyGadget;
}

#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ClaimIndices {
    pub offset: usize,
    pub claim_len: usize,
    pub colon_idx: usize,
    pub value_idx: usize,
    pub value_len: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Claim {
    pub key: String,
    pub value: String,
    pub indices: ClaimIndices,
}

impl Claim {
    pub fn empty() -> Self {
        Claim {
            key: String::new(),
            value: String::new(),
            indices: ClaimIndices::default(),
        }
    }
}
