//! Error types for the anchor scheme.
//!
//! [`AnchorError`] covers all failure modes in setup, witness generation, and verification:
//! invalid parameters, dimension mismatches, cryptographic failures (hash errors), matrix
//! solver errors (propagated from [`crate::matrix::error::VandermondeMatrixError`]),
//! and verification failures.

use thiserror::Error;

use crate::matrix::error::VandermondeMatrixError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("Invalid parameters provided: {0}")]
    InvalidParameters(String),
    #[error("Dimension mismatch: {0}")]
    DimensionMismatch(String),
    #[error("Underlying cryptographic error: {0}")]
    CryptoError(String),
    #[error("Matrix error: {0}")]
    MatrixError(#[from] VandermondeMatrixError),
    #[error("Verification failed")]
    VerificationFailed,
}
