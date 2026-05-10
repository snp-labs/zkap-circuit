//! Error types for the anchor scheme.
//!
//! [`AnchorError`] covers all failure modes in setup, witness generation, and verification:
//! invalid parameters, dimension mismatches, cryptographic failures (hash errors), matrix
//! solver errors (propagated from [`crate::matrix::error::VandermondeMatrixError`]),
//! and verification failures.

use thiserror::Error;

use crate::matrix::error::VandermondeMatrixError;

/// All failure modes in anchor setup, witness generation, and verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnchorError {
    /// Fired when `n`, `k`, or selector length violates the scheme invariants
    /// (e.g. `k > n`, empty secrets, or a selector whose sum ≠ k).
    #[error("Invalid parameters provided: {0}")]
    InvalidParameters(String),
    /// Fired when two vectors or matrices that must share a dimension do not
    /// (e.g. `selector.len() ≠ n`, secrets length ≠ matrix column count).
    #[error("Dimension mismatch: {0}")]
    DimensionMismatch(String),
    /// Wraps a hash evaluation failure from the underlying Poseidon CRH; the
    /// inner string carries the original error message.
    #[error("Underlying cryptographic error: {0}")]
    CryptoError(String),
    /// Propagated from [`crate::matrix::error::VandermondeMatrixError`] when
    /// `calculate_vector_a` or `multiply_vector` fails (e.g. singular matrix).
    #[error("Matrix error: {0}")]
    MatrixError(#[from] VandermondeMatrixError),
    /// Fired by [`crate::anchor::AnchorScheme::verify`] when `⟨a, anchor⟩ ≠ ⟨b, h_known⟩`.
    #[error("Verification failed")]
    VerificationFailed,
}
