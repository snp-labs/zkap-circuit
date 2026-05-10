//! Common DTO types for multi-platform bindings (napi, uniffi, wasm)
//!
//! These core types define the canonical data structures shared across all bindings.
//! Each binding wraps these types with platform-specific attributes.

mod hash;
#[cfg(feature = "proof")]
mod proof;

pub use hash::*;
#[cfg(feature = "proof")]
pub use proof::*;
