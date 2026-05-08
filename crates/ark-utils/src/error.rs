//! Error re-exports for callers that prefer a single `ark_utils::error::*`
//! import root.
//!
//! Errors are defined in their owning modules:
//! - `FieldParseError` → `codec::affine`
//! - `IoError` → `io`
//! - `TextError` → `codec::string`
//! - `ConvertError` → `codec::string`
//! - `NonCanonicalFieldError` → `codec::field`

pub use crate::codec::field::NonCanonicalFieldError;
pub use crate::codec::string::{ConvertError, TextError};

#[cfg(feature = "field-serde")]
pub use crate::codec::affine::FieldParseError;
#[cfg(feature = "io")]
pub use crate::io::IoError;
