use gadget::{anchor::error::AnchorError, matrix::error::LinearSystemError};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorServiceError {

    #[error("Anchor crypto core error: {0}")]
    AnchorCryptoCoreError(#[from] AnchorError),

    #[error("Matrix crypto core error: {0}")]
    MatrixCryptoCoreError(#[from] LinearSystemError),

    #[error("Invalid anchor type")]
    InvalidAnchorType,

    #[error("Invalid anchor format: {0}")]
    InvalidFormat(String),
}