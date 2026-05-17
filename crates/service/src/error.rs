//! Top-level error types for the zkap-service layer.
//!
//! [`ApplicationError`] is the single error type returned by all public APIs.
//! IO failures use `Other(String)` (or the `Io` variant after S7), cryptographic
//! failures use `CryptographicError`/`PoseidonHashError`, proof failures use
//! `ProofGenerationFailed`/`VerifyFailed`, and parse failures use
//! `InvalidFormat`/`ParseError`.

use ark_utils::ConvertError;
use ark_utils::error::{FieldParseError, TextError};
use gadget::anchor::error::AnchorError;
use thiserror::Error;

/// Top-level error type for the zkap-service layer.
///
/// Consumer-facing variants are named by concern, not by internal crate origin.
///
/// `#[non_exhaustive]` so that adding new typed variants (e.g. anchor- or
/// audience-specific failures) is not a breaking change for downstream
/// `match` sites.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApplicationError {
    /// Input could not be parsed against the expected format (JSON shape,
    /// length, or CircuitConfig invariants). The string carries the upstream
    /// error message so callers can route or surface it without inspecting
    /// the variant.
    #[error("{0}")]
    InvalidFormat(String),

    /// Deprecated catch-all kept for source compatibility — new code should
    /// use a specific variant or `Other(String)`. Removal is planned in the
    /// next breaking release.
    #[deprecated(note = "use Other(String) or a specific variant instead")]
    #[error("Internal error")]
    InternalError,

    /// Filesystem or std::io failure (auto-converted from [`std::io::Error`]
    /// via `?`); wraps the underlying error so callers can downcast on the
    /// `source()` chain.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for failures that don't yet have a typed variant. Prefer
    /// adding a typed variant when the same call site appears more than once.
    #[error("{0}")]
    Other(String),

    /// Cryptographic primitive failure (e.g. anchor or HMAC) that bubbles up
    /// from the gadget layer; the string holds the upstream description.
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),

    /// Poseidon hash evaluation failed — the in-tree implementation is
    /// total, so this variant is reserved for future Poseidon backends that
    /// can fail.
    #[error("Poseidon hash error")]
    PoseidonHashError,

    /// Coordinate or field-element parsing failed (auto-converted from
    /// [`FieldParseError`] via `?`); covers `0x…` decoding, decimal parsing,
    /// and curve / subgroup validation rejections.
    #[error("Field parsing error: {0}")]
    FieldParsingError(#[from] FieldParseError),

    /// Base64 / UTF-8 / JWT-segment decoding failed at the text layer (i.e.
    /// before the value reached field parsing).
    #[error("Text encoding error: {0}")]
    TextEncodingError(String),

    /// Generic parse failure for upstream-typed errors that map cleanly to
    /// a string description (e.g. `ConvertError`, `TokenError`).
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Groth16 prover or witness construction failed during proof
    /// generation; the string carries the upstream description.
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Groth16 verifier returned `false` — the proof is invalid against the
    /// supplied verifying key and public inputs (no further detail is
    /// available, by Groth16's design).
    #[error("Proof verification failed")]
    VerifyFailed,

    /// A field-element input string could not be parsed as either `0x`-hex or
    /// decimal. `index` is the 0-based position of the offending entry inside
    /// the input vector; `message` carries the upstream parser description.
    /// Returned by [`crate::generate_poseidon_hash`].
    #[error("invalid field element at index {index}: {message}")]
    InvalidFieldElement {
        /// 0-based position of the offending input.
        index: usize,
        /// Upstream parser description.
        message: String,
    },

    /// The supplied audience list is longer than the circuit's
    /// `num_audience_limit`. Returned by [`crate::generate_audience_hashes`].
    #[error("audience limit exceeded: got {got}, limit {limit}")]
    AudienceLimitExceeded {
        /// Number of audiences the caller supplied.
        got: usize,
        /// Maximum number permitted by `CircuitConfig::num_audience_limit`.
        limit: usize,
    },

    /// A JWT claim value (e.g. an issuer or audience string) failed
    /// domain-level validation before hashing. `which` names the claim
    /// (`"iss"`, `"aud"`, …); `message` carries the upstream description.
    #[error("invalid {which} value: {message}")]
    InvalidClaimValue {
        /// Claim name (`"iss"`, `"aud"`, …).
        which: String,
        /// Upstream description.
        message: String,
    },

    /// A base64 input could not be decoded. The string carries the upstream
    /// description. Returned by [`crate::generate_issuer_key_hash`] when the
    /// supplied `rsa_modulus_b64` fails base64 decoding.
    #[error("invalid base64: {0}")]
    InvalidBase64(String),

    /// The supplied RSA modulus failed structural validation (e.g. its
    /// decoded byte length is not the RSA-2048 size of 256 bytes). The
    /// string carries the failure detail.
    #[error("invalid RSA modulus: {0}")]
    InvalidRsaModulus(String),

    /// Poseidon evaluation failed during a host-side hash computation. The
    /// in-tree Poseidon implementation is total today, so this variant is
    /// reserved for future Poseidon backends that can fail and as a defensive
    /// catch-all from the hash-API surface.
    #[error("hash computation failed: {0}")]
    HashFailed(String),

    /// The number of supplied anchor secrets does not match the matrix row
    /// count `n` declared in [`circuit::types::CircuitConfig`]. Returned by
    /// [`crate::generate_anchor`] when
    /// `request.secrets.len() != config.n`.
    #[error("anchor dimension mismatch: expected {expected} secrets, got {got}")]
    AnchorDimensionMismatch {
        /// Number of secrets the circuit configuration requires (`config.n`).
        expected: usize,
        /// Number of secrets the caller supplied.
        got: usize,
    },

    /// An input on the prove API failed boundary validation (length, format,
    /// or decoding). `field` is a dotted path into the [`crate::ProveRequest`]
    /// (e.g. `"credentials[2].rsa_modulus_b64"`); `message` carries the
    /// upstream description.
    #[error("invalid prove request at {field}: {message}")]
    InvalidProveRequest {
        /// Dotted field path into the failing [`crate::ProveRequest`].
        field: String,
        /// Upstream parser / validator description.
        message: String,
    },
}

impl From<AnchorError> for ApplicationError {
    fn from(e: AnchorError) -> Self {
        ApplicationError::CryptographicError(e.to_string())
    }
}

impl From<TextError> for ApplicationError {
    fn from(e: TextError) -> Self {
        ApplicationError::TextEncodingError(e.to_string())
    }
}

impl From<ConvertError> for ApplicationError {
    fn from(e: ConvertError) -> Self {
        ApplicationError::ParseError(e.to_string())
    }
}

impl From<crate::jwt::parser::TokenError> for ApplicationError {
    fn from(e: crate::jwt::parser::TokenError) -> Self {
        ApplicationError::ParseError(e.to_string())
    }
}
