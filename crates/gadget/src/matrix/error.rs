//! Error types for matrix operations.
//!
//! [`VandermondeMatrixError`] covers failures in matrix construction and inversion:
//! wrong lengths (`LengthError`), singular matrices (`SingularMatrix`), and missing
//! modular inverse (`NoInverse`).

use thiserror::Error;

/// Errors raised by [`crate::matrix::VandermondeMatrix`] construction,
/// submatrix extraction, and Gaussian-elimination solver.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VandermondeMatrixError {
    /// A vector or selector length disagrees with the matrix
    /// dimensions (`n`, `m`, or the configured threshold `k`). The
    /// payload string carries the offending lengths for diagnostics.
    #[error("Length error: {0}")]
    LengthError(String),

    /// Gaussian elimination encountered a zero pivot column with no
    /// non-zero candidate below — i.e. the submatrix is rank-deficient
    /// and the linear system has no unique solution.
    #[error("Singular matrix error")]
    SingularMatrix,

    /// A pivot field element has no modular inverse. Cannot occur for
    /// `PrimeField` values that are non-zero, so this surfaces only
    /// when an upstream invariant has already been violated.
    #[error("No inverse")]
    NoInverse,
}
