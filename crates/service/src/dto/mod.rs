//! Common DTO types for multi-platform bindings (napi, uniffi, wasm)
//!
//! These core types define the canonical data structures shared across all bindings.
//! Each binding wraps these types with platform-specific attributes.

mod anchor;
mod hash;
#[cfg(feature = "proof-types")]
mod proof;
mod prove;
pub mod public_inputs;
#[cfg(feature = "proof-types")]
mod witness;

pub use anchor::*;
pub use hash::*;
#[cfg(feature = "proof-types")]
pub use proof::*;
pub use prove::{ProveCredential, ProveRequest};
pub use public_inputs::{PUBLIC_INPUT_NAMES, PUBLIC_INPUTS, PublicInputSlot};
#[cfg(feature = "proof-types")]
pub use witness::WitnessBundle;

// `dto/proof.rs` exports `ProofComponents`, `SharedPublicInputs`, and
// `ProveResponse`. The earlier `ZkapProofResult` / `PerProofPublicInputs`
// types were removed when the response was reshaped into parallel
// `Vec<String>` `jwt_exp` / `verification_rhs` columns alongside
// `shared_public_inputs` (US-003 of the prove API redesign).
