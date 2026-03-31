use thiserror::Error;

#[derive(Debug, Error)]
pub enum FieldParseError {
    #[error("Invalid decimal string for field element")]
    InvalidDecimal,

    #[error("Invalid hex string for field element")]
    InvalidHex,

    #[error("Invalid length for ASCII to field conversion: expected multiple of {0}, got {1}")]
    InvalidLength(usize, usize),

    #[error("point is not on curve")]
    NotOnCurve,

    #[error("point is not in correct subgroup")]
    NotInCorrectSubgroup,
}

#[derive(Debug, Error)]
pub enum IoError {
    #[error("Failed to load key file")]
    LoadKeyFailed,

    #[error("Failed to deserialize key file")]
    DeserializeFailed,
}

#[derive(Debug, Error)]
pub enum TextError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}
