//! Error types for the signature scheme.
//!
//! [`SignatureError`] covers key generation failures (`GenerateLibKeyError`,
//! `GenerateLibSignatureError`), verification failures (`LibSignatureVerifyError`,
//! `VerificationFailed`), R1CS synthesis errors (`SynthesisError`), and serialization
//! errors.

use thiserror::Error;

/// Errors that can arise during RSA signature operations (native and in-circuit).
///
/// Covers the full lifecycle: key generation, signing, native verification, R1CS
/// constraint synthesis, and serialization. Circuit code typically sees only
/// `SynthesisError`; native callers may see any variant.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Propagated from arkworks R1CS constraint allocation; wraps any
    /// [`ark_relations::gr1cs::SynthesisError`] encountered while building the gadget.
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] ark_relations::gr1cs::SynthesisError),

    /// The supplied public key bytes could not be parsed or validated (e.g., modulus
    /// is too small, exponent is zero).
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The supplied secret key bytes are malformed or inconsistent with the public key.
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// The signature bytes have an unexpected length or encoding.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Native PKCS#1 v1.5 verification completed but the recovered hash did not match
    /// the message hash (i.e., the signature is cryptographically invalid).
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),

    /// A public-parameter value (e.g., key size, hash OID) is out of range or missing.
    #[error("Parameter error: {0}")]
    ParameterError(String),

    /// A lower-level library call failed for a reason not covered by a more specific variant.
    #[error("Native error: {0}")]
    NativeError(String),

    /// The `rsa` crate failed to generate a new private key (e.g., entropy exhaustion).
    #[error("Generate lib key error")]
    GenerateLibKeyError,

    /// The `rsa` crate failed to produce a signature (e.g., key is malformed).
    #[error("Generate lib signature error")]
    GenerateLibSignatureError,

    /// The `rsa` crate's verifier rejected the signature; the error message contains
    /// details from the underlying `rsa::Error`.
    #[error("Lib signature verify error: {0}")]
    LibSignatureVerifyError(String),

    /// A panic was caught and converted to an error (e.g., from an FFI boundary).
    #[error("panic: {0}")]
    Panic(String),

    /// An [`ark_crypto_primitives`] CRH error propagated during hash-gadget construction.
    #[error("CRHScheme error")]
    CRHSchemeError(#[from] ark_crypto_primitives::Error),

    /// An arkworks serialization/deserialization error (e.g., compressed-point decoding).
    #[error("Serialization error")]
    SerializationError(#[from] ark_serialize::SerializationError),
}
