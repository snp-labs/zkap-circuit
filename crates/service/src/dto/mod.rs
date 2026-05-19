//! Common DTO types for multi-platform bindings (napi, uniffi, wasm)
//!
//! These core types define the canonical data structures shared across all bindings.
//! Each binding wraps these types with platform-specific attributes.

mod anchor;
mod hash;
mod proof;
mod prove;
pub mod public_inputs;

pub use anchor::*;
pub use hash::*;
pub use proof::*;
pub use prove::{ProveCredential, ProveRequest};
pub use public_inputs::{PUBLIC_INPUTS, PUBLIC_INPUT_NAMES, PublicInputSlot};

// `dto/proof.rs` exports `ProofComponents`, `SharedPublicInputs`, and
// `ProveResponse`. The earlier `ZkapProofResult` / `PerProofPublicInputs`
// types were removed when the response was reshaped into parallel
// `Vec<String>` `jwt_exp` / `verification_rhs` columns alongside
// `shared_public_inputs` (US-003 of the prove API redesign).
