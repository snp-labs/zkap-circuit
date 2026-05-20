//! Token-related types and gadgets for JWT claim verification.
//!
//! Sub-modules:
//! - [`claimverifier`] — R1CS gadgets for claim extraction and format verification
//!   (`claim_extractor_v2`, `claim_format_verifier_v2`)
//! - [`claim_indices`] — [`ClaimIndicesVar`](claim_indices::ClaimIndicesVar)
//!   R1CS variable + `AllocVar` impl
//! - [`jwt_field`] — byte-to-field converters for JWT nonce (hex) and expiry
//!   (decimal); split into `jwt_field/nonce.rs` and `jwt_field/exp.rs` siblings
//!
//! Host-side data:
//! - [`ClaimIndices`] — plain indices describing a claim's position in the JWT payload
//!   (zeroed `ClaimIndices::default()` is the placeholder for trusted setup)
//! - `Claim` — host-only struct combining key, value, and indices; moved to
//!   `zkap_service::jwt::Claim` (§4.4 audit remediation; not consumed by R1CS code)

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub mod claim_indices;
pub mod claimverifier;
pub mod jwt_field;

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

