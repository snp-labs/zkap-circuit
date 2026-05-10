use std::string::FromUtf8Error;

use ark_relations::r1cs::SynthesisError;
use base64::DecodeError;
use thiserror::Error;

/// Errors that can arise during Base64 URL-safe decoding and in-circuit enforcement.
///
/// Covers both native decoding failures (bad characters, invalid UTF-8, oversized input)
/// and the R1CS synthesis errors that propagate from in-circuit constraint generation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Base64Error {
    /// Propagated from arkworks R1CS constraint allocation; wraps any
    /// [`ark_relations::r1cs::SynthesisError`] that occurs during gadget enforcement.
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] SynthesisError),

    /// The `base64` crate could not decode the input under any supported variant
    /// (URL-safe no-pad, standard no-pad, URL-safe padded, standard padded).
    #[error("Failed to decode base64 string: {0}")]
    DecodeError(#[from] DecodeError),

    /// The decoded bytes are not valid UTF-8; returned by
    /// [`decode_any_base64_to_string`](super::decoder::decode_any_base64_to_string).
    #[error("Decoded bytes are not valid UTF-8: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),

    /// Field `0` is the byte position of the offending character; field `1` is the
    /// character itself. Valid characters are `A-Z`, `a-z`, `0-9`, `-`, `_`
    /// (URL-safe Base64 alphabet).
    #[error("Invalid Base64 character: index - {0}, character - {1}")]
    InvalidBase64Character(usize, char),

    /// The input string is longer than the `padded_len` supplied to
    /// [`IndexBits::from_base64_url`](super::decoder::IndexBits::from_base64_url).
    /// Field `0` is the actual input length; field `1` is the allowed maximum.
    #[error("Input length {0} exceeds padded length {1}")]
    InputTooLong(usize, usize),
}
