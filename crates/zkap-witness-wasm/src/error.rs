//! Errors raised by the zkap-witness-wasm thin layer.
//!
//! Conversions to [`WitnessAbiCode`] funnel every variant to
//! `CircuitBuildError` (status 7); finer-grained ABI signals
//! (`PostcardDecodeError`, `MalformedInput`) are produced by the generic
//! macro before this layer is reached.

use ark_ar1cs_wasm_witness::WitnessAbiCode;

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ZkapWitnessError {
    /// `circuit_config.validate()` rejected the supplied parameters.
    #[error("zkap V1 circuit config invalid: {0}")]
    InvalidConfig(String),

    /// A length-tagged field (anchor / merkle / selector) did not match
    /// the dimensions implied by `circuit_config` (n, k, tree_height).
    #[error("zkap V1 dimension mismatch: {0}")]
    DimensionMismatch(String),

    /// `jwt_bytes` is not valid UTF-8 / not three `.`-separated parts.
    #[error("zkap V1 malformed JWT bytes: {0}")]
    MalformedJwt(String),

    /// Base64 decoding (payload or signature segment) failed.
    #[error("zkap V1 base64 decode failed: {0}")]
    Base64(String),

    /// A required claim key was not located in the decoded JWT payload.
    #[error("zkap V1 claim `{0}` not found in JWT payload")]
    ClaimNotFound(String),

    /// Anchor witness construction (Vandermonde / Poseidon) failed.
    #[error("zkap V1 anchor witness build failed: {0}")]
    AnchorBuild(String),

    /// `IndexBits::from_base64_url` rejected the payload (e.g. invalid
    /// base64 chars, oversize).
    #[error("zkap V1 base64 index-bits build failed: {0}")]
    IndexBits(String),

    /// A 32-byte BE field-element encoding represents an integer
    /// `>= F::MODULUS`. V1 wire format requires canonical encodings —
    /// silent `mod p` reduction is rejected so that a malformed payload
    /// can never be silently coerced to a different field element.
    #[error("zkap V1 non-canonical field encoding: {0}")]
    NonCanonicalField(String),

    /// The `rsa_signature_be` wire field does not byte-match the
    /// base64-decoded `sig_b64` segment of `jwt_bytes`. V1 ships both
    /// to make the host's intent explicit, then the wasm side rejects
    /// any disagreement before building the witness.
    #[error("zkap V1 RSA signature mismatch: {0}")]
    SignatureMismatch(String),
}

impl From<ZkapWitnessError> for WitnessAbiCode {
    fn from(_: ZkapWitnessError) -> Self {
        WitnessAbiCode::CircuitBuildError
    }
}
