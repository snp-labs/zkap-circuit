use std::string::FromUtf8Error;

use ark_relations::r1cs::SynthesisError;
use base64::DecodeError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Base64Error {
    #[error("Synthesis error: {0}")]
    SynthesisError(#[from] SynthesisError),

    #[error("Failed to decode base64 string: {0}")]
    DecodeError(#[from] DecodeError),

    #[error("Decoded bytes are not valid UTF-8: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),

    #[error("Invalid Base64 character: index - {0}, character - {1}")]
    WrongCharacter(usize, char),
}
