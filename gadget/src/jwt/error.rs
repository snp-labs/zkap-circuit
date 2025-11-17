use thiserror::Error;
use crate::base64::Base64Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    #[error("Base64 error")]
    Base64ErrorInToken(#[from] Base64Error),

    #[error("Key not found: {0}")]
    NotFoundKeyError(String),

    #[error("Invalid length: {0}")]
    InvalidLengthError(String),
}
