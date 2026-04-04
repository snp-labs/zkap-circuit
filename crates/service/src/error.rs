use ark_utils::error::{FieldParseError, TextError};
use ark_utils::ConvertError;
use gadget::anchor::error::AnchorError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("{0}")]
    InvalidFormat(String),

    #[error("Invalid variant")]
    InvalidVariant,

    #[error("{0}")]
    Other(String),

    #[error("Anchor error: {0}")]
    AnchorError(#[from] AnchorError),

    #[error("Poseidon hash error")]
    PoseidonHashError,

    #[error("Field parsing error: {0}")]
    FieldParsingError(#[from] FieldParseError),

    #[error("Text error: {0}")]
    TextError(#[from] TextError),

    #[error("Convert error: {0}")]
    ConvertError(#[from] ConvertError),
}
