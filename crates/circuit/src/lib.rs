//! zkap-circuit — the Groth16 R1CS circuit definition for the ZKAP protocol.
//!
//! Provides [`ZkapCircuit`], the main constraint synthesizer, along with all witness types
//! ([`ZkapCircuitInput`], [`CircuitPublicInputs`], witness structs) and the shared
//! [`CircuitConfig`](crate::types::CircuitConfig) parameter type (re-exported from
//! `ark-utils::wire`).  This crate is a dependency of `zkap-service` and is not usually
//! consumed directly by application code.

use ark_ff::Field;

pub mod token;
pub mod witness;
pub mod zkap;

pub mod types;

/// Deprecated alias for [`types`].
///
/// Renamed in Phase 2 C4 — use `circuit::types` instead.  This alias will be
/// removed in the next release.
#[deprecated(
    note = "renamed to `circuit::types` in Phase 2 C4; this alias will be removed in the next release"
)]
pub use types as constants;

/// Deprecated alias for [`witness`].
///
/// Renamed in Phase 2 C5 — use `circuit::witness` instead.  This alias will
/// be removed in the next release.
#[deprecated(
    note = "renamed to `circuit::witness` in Phase 2 C5; this alias will be removed in the next release"
)]
pub use witness as input;

// Re-export circuit witness types
pub use witness::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};

pub trait ExposesPublicInputs<F: Field> {
    fn public_inputs(&self) -> Vec<F>;
}
