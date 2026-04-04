//! Error re-exports for backward compatibility.
//!
//! Error types are defined in their respective modules:
//! - `FieldParseError` → `affine_serde`
//! - `IoError` → `io`
//! - `TextError` → `convert`
//! - `ConvertError` → `convert`

#[cfg(feature = "field-serde")]
pub use crate::affine_serde::FieldParseError;
#[cfg(feature = "io")]
pub use crate::io::IoError;
pub use crate::convert::TextError;
pub use crate::convert::ConvertError;
