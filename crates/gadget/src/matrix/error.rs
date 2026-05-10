//! Error types for matrix operations.
//!
//! [`VandermondeMatrixError`] covers failures in matrix construction and inversion:
//! wrong lengths (`LengthError`), singular matrices (`SingularMatrix`), and missing
//! modular inverse (`NoInverse`).

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VandermondeMatrixError {
    #[error("Length error: {0}")]
    LengthError(String),

    #[error("Singular matrix error")]
    SingularMatrix,

    #[error("No inverse")]
    NoInverse,
}
