use ark_relations::r1cs::SynthesisError;
use thiserror::Error;

/// Error type for both native and in-circuit hash evaluations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashError {
    /// Propagated from the arkworks R1CS synthesis layer when constraint allocation fails.
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] SynthesisError),

    /// Generic native hash failure (Poseidon CRH returned an error from the ark-crypto-primitives layer).
    #[error("Native hash error: {0}")]
    NativeHashError(String),

    /// Fired by the native SHA-256 evaluator (e.g. wrong input length or padding invariant violated).
    #[error("NativeSha256Error: {0}")]
    NativeSha256Error(String),

    /// Fired by the native MiMC evaluator; retained for legacy compatibility.
    #[error("NativeMiMCError: {0}")]
    NativeMiMCError(String),

    /// Fired by the MiMC R1CS gadget when constraint synthesis fails.
    #[error("Circuit MiMC error: {0}")]
    CircuitMiMCError(String),

    /// Fired by the SHA-256 R1CS gadget (e.g. `SHA256Gadget::digest_with_pad`
    /// receives a non-64-byte-aligned input).
    #[error("Circuit SHA256 error: {0}")]
    CircuitSha256Error(String),

    /// Fired when a hash function receives an input whose length violates
    /// the scheme's arity requirement (e.g. SHA-256 block size, Poseidon width).
    #[error("Invalid input length: {0}")]
    InvalidInputLength(String),

    /// Fired when the hash scheme cannot be instantiated because the supplied
    /// parameter struct is missing or invalid.
    #[error("Parameter error: {0}")]
    ParameterError(String),
}
