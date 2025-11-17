use thiserror::Error;

/// Error type for the circuit module
#[derive(Error, Debug, PartialEq, Eq)]
pub enum UtilError {
    #[error("failed to convert")]
    ConversionError,
}
