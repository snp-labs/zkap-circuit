use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] ark_relations::r1cs::SynthesisError),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("Parameter error: {0}")]
    ParameterError(String),

    #[error("Native error: {0}")]
    NativeError(String),

    #[error("Generate lib key error")]
    GenerateLibKeyError,

    #[error("Generatae lib signature error")]
    GenerateLibSignatureError,

    #[error("Lib signature verify error: {0}")]
    LibSignatureVerifyError(String),

    #[error("panic: {0}")]
    Panic(String),

    #[error("Failed to Digest to Scalar Field")]
    FailedToDigestToScalarField,

    #[error("CRHScheme error")]
    CRHSchemeError(#[from] ark_crypto_primitives::Error),

    #[error("Serialization error")]
    SerializationError(#[from] ark_serialize::SerializationError),
}
