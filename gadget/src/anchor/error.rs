use thiserror::Error;

use crate::matrix::error::VandermondeMatrixError;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("Invalid parameters provided: {0}")]
    InvalidParameters(String),
    #[error("Dimension mismatch: {0}")]
    DimensionMismatch(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Underlying cryptographic error: {0}")]
    CryptoError(String),
    #[error("Matrix error: {0}")]
    MatrixError(#[from] VandermondeMatrixError),
    #[error("Verification failed")]
    VerificationFailed2,
}
