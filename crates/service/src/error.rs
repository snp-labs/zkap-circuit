//! Top-level error types for the zkap-service layer.
//!
//! [`ApplicationError`] is the single error type returned by all public APIs.
//! IO failures use `Other(String)` (or the `Io` variant after S7), cryptographic
//! failures use `CryptographicError`/`PoseidonHashError`, proof failures use
//! `ProofGenerationFailed`/`VerifyFailed`, and parse failures use
//! `InvalidFormat`/`ParseError`.

use ark_utils::ConvertError;
use ark_utils::error::{FieldParseError, TextError};
use gadget::anchor::error::AnchorError;
use thiserror::Error;

/// Top-level error type for the zkap-service layer.
///
/// Consumer-facing variants are named by concern, not by internal crate origin.
#[derive(Debug, Error)]
pub enum ApplicationError {
    /// Input could not be parsed against the expected format (JSON shape,
    /// length, or CircuitConfig invariants). The string carries the upstream
    /// error message so callers can route or surface it without inspecting
    /// the variant.
    #[error("{0}")]
    InvalidFormat(String),

    /// Deprecated catch-all kept for source compatibility — new code should
    /// use a specific variant or `Other(String)`. Removal is planned in the
    /// next breaking release.
    #[deprecated(note = "use Other(String) or a specific variant instead")]
    #[error("Internal error")]
    InternalError,

    /// Filesystem or std::io failure (auto-converted from [`std::io::Error`]
    /// via `?`); wraps the underlying error so callers can downcast on the
    /// `source()` chain.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for failures that don't yet have a typed variant. Prefer
    /// adding a typed variant when the same call site appears more than once.
    #[error("{0}")]
    Other(String),

    /// Cryptographic primitive failure (e.g. anchor or HMAC) that bubbles up
    /// from the gadget layer; the string holds the upstream description.
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),

    /// Poseidon hash evaluation failed — the in-tree implementation is
    /// total, so this variant is reserved for future Poseidon backends that
    /// can fail.
    #[error("Poseidon hash error")]
    PoseidonHashError,

    /// Coordinate or field-element parsing failed (auto-converted from
    /// [`FieldParseError`] via `?`); covers `0x…` decoding, decimal parsing,
    /// and curve / subgroup validation rejections.
    #[error("Field parsing error: {0}")]
    FieldParsingError(#[from] FieldParseError),

    /// Base64 / UTF-8 / JWT-segment decoding failed at the text layer (i.e.
    /// before the value reached field parsing).
    #[error("Text encoding error: {0}")]
    TextEncodingError(String),

    /// Generic parse failure for upstream-typed errors that map cleanly to
    /// a string description (e.g. `ConvertError`, `TokenError`).
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Groth16 prover or witness construction failed during proof
    /// generation; the string carries the upstream description.
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Groth16 verifier returned `false` — the proof is invalid against the
    /// supplied verifying key and public inputs (no further detail is
    /// available, by Groth16's design).
    #[error("Proof verification failed")]
    VerifyFailed,
}

impl From<AnchorError> for ApplicationError {
    fn from(e: AnchorError) -> Self {
        ApplicationError::CryptographicError(e.to_string())
    }
}

impl From<TextError> for ApplicationError {
    fn from(e: TextError) -> Self {
        ApplicationError::TextEncodingError(e.to_string())
    }
}

impl From<ConvertError> for ApplicationError {
    fn from(e: ConvertError) -> Self {
        ApplicationError::ParseError(e.to_string())
    }
}

#[cfg(feature = "proof")]
impl From<crate::jwt::parser::TokenError> for ApplicationError {
    fn from(e: crate::jwt::parser::TokenError) -> Self {
        ApplicationError::ParseError(e.to_string())
    }
}
