//! Common DTO types for multi-platform bindings (napi, uniffi, wasm)
//!
//! These core types define the canonical data structures shared across all bindings.
//! Each binding wraps these types with platform-specific attributes.

mod anchor;
mod hash;
mod proof;

pub use anchor::*;
pub use hash::*;
pub use proof::*;
