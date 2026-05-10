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
    #[error("{0}")]
    InvalidFormat(String),

    #[deprecated(note = "use Other(String) or a specific variant instead")]
    #[error("Internal error")]
    InternalError,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),

    #[error("Poseidon hash error")]
    PoseidonHashError,

    #[error("Field parsing error: {0}")]
    FieldParsingError(#[from] FieldParseError),

    #[error("Text encoding error: {0}")]
    TextEncodingError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

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
