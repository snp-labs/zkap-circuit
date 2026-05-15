//! Common DTO types for multi-platform bindings (napi, uniffi, wasm)
//!
//! These core types define the canonical data structures shared across all bindings.
//! Each binding wraps these types with platform-specific attributes.

mod anchor;
mod hash;
#[cfg(feature = "proof")]
mod proof;
#[cfg(feature = "proof")]
mod prove;

pub use anchor::*;
pub use hash::*;
#[cfg(feature = "proof")]
pub use proof::*;
#[cfg(feature = "proof")]
pub use prove::{ProveCredential, ProveRequest};
