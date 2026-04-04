//! Backward-compatibility shim. Use `convert` module directly.

pub use crate::convert::pad;

// TextError remains as independent enum for backward compat
// (service/src/error.rs uses #[from] TextError separately from ConvertError)
#[derive(Debug, thiserror::Error)]
pub enum TextError {
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}
