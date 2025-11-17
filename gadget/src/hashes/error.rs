use ark_relations::r1cs::SynthesisError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashError {
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] SynthesisError),

    #[error("Native hash error: {0}")]
    NativeHashError(String),

    #[error("NativeSha256Error: {0}")]
    NativeSha256Error(String),

    #[error("NativeMiMCError: {0}")]
    NativeMiMCError(String),

    #[error("Circuit MiMC error: {0}")]
    CircuitMiMCError(String),

    #[error("Circuit SHA256 error: {0}")]
    CircuitSha256Error(String),

    #[error("Invalid input length: {0}")]
    InvalidInputLength(String),

    #[error("Parameter error: {0}")]
    ParameterError(String),
}
