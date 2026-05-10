//! Token-related types and gadgets for JWT claim verification.
//!
//! Sub-modules:
//! - [`claimverifier`] — R1CS gadgets for claim extraction and format verification
//!   (`claim_extractor_v2`, `claim_format_verifier_v2`)
//! - [`claim_indices`] — [`ClaimIndicesVar`](claim_indices::ClaimIndicesVar)
//!   R1CS variable + `AllocVar` impl
//! - [`rsa`] — [`RSA2048VerifyGadget`](rsa::RSA2048VerifyGadget) for RSA-2048
//!   PKCS#1 signature verification
//! - [`jwt_field`] — byte-to-field converters for JWT nonce (hex) and expiry
//!   (decimal); split into `jwt_field/nonce.rs` and `jwt_field/exp.rs` siblings
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

/// Plain (host-side) indices describing one named claim's position in
/// the decoded JWT payload. Allocated into [`claim_indices::ClaimIndicesVar`]
/// for in-circuit use. The `Default` (all zeros) form is the placeholder
/// used by [`crate::zkap::ZkapCircuit::generate_mock_circuit`] for
/// trusted setup; real proving paths must overwrite every field.
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ClaimIndices {
    /// Offset of the claim's opening quote in the JWT payload.
    pub offset: usize,
    /// Total claim length (key + colon + value, including surrounding quotes).
    pub claim_len: usize,
    /// Position of the `:` separator between key and value.
    pub colon_idx: usize,
    /// Offset of the first byte of the claim value.
    pub value_idx: usize,
    /// Length in bytes of the claim value (excluding any surrounding quotes).
    pub value_len: usize,
}

/// Host-only struct combining a JWT claim's textual key/value with its
/// byte-position [`ClaimIndices`]. Used by `zkap-service::jwt::parser`
/// and the wasm test fixtures; not consumed by R1CS code.
#[derive(Clone, Debug, Default)]
pub struct Claim {
    /// Claim key (e.g. `"aud"`, `"sub"`, `"iss"`).
    pub key: String,
    /// Claim value as the textual JSON string the JWT carries.
    pub value: String,
    /// Byte-position metadata for in-circuit slicing.
    pub indices: ClaimIndices,
}

impl Claim {
    /// Returns a [`Claim`] with empty `key`, empty `value`, and zeroed
    /// indices — convenience constructor for fixtures and placeholders.
    pub fn empty() -> Self {
        Claim {
            key: String::new(),
            value: String::new(),
            indices: ClaimIndices::default(),
        }
    }
}
