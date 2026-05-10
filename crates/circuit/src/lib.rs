//! zkap-circuit — the Groth16 R1CS circuit definition for the ZKAP protocol.
//!
//! Provides [`ZkapCircuit`](crate::zkap::ZkapCircuit), the main constraint
//! synthesizer, along with all witness types ([`ZkapCircuitInput`],
//! [`CircuitPublicInputs`], witness structs) and the shared
//! [`CircuitConfig`](crate::types::CircuitConfig) parameter type (re-exported from
//! `ark-utils::wire`).  This crate is a dependency of `zkap-service` and is not usually
//! consumed directly by application code.

// Crate-internal `missing_docs` warning, not a workspace deny. Phase 6
// / H5-staged-2: clears the circuit baseline (32 warnings at HEAD =
// dde7792a, plan v2 §6) and locks the floor without depending on the
// workspace-wide flip in `00-workspace-hygiene.md` §H5.
#![warn(missing_docs)]
// rustdoc lock floor — Phase 9 P9-circuit-rustdoc-audit (Phase 8 critic
// MINOR #3 follow-up). Mirrors Phase 8 P8-arkutils-doc-link-audit and
// Phase 9 P9-gadget-rustdoc-audit: any new `///`/`//!` doc with a broken
// intra-doc link or invalid HTML tag fails the `Rustdoc` CI job.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::invalid_html_tags)]

use ark_ff::Field;

pub mod token;
pub mod witness;
pub mod zkap;

pub mod types;

// Re-export circuit witness types
pub use witness::{
    AnchorWitness, AudienceWitness, CircuitConstants, CircuitPublicInputs, JwtWitness,
    MerkleWitness, MiscWitness, ZkapCircuitInput,
};

/// Adapter for objects that can be reduced to the Groth16 public-input
/// vector accepted by `ark_groth16::Groth16::verify_proof`. Implemented
/// for [`ZkapCircuit`](crate::zkap::ZkapCircuit) and used by
/// `zkap-service::proof::verify` to assemble the verifier input from a
/// completed prover side.
pub trait ExposesPublicInputs<F: Field> {
    /// Return the ordered public inputs for this circuit instance.
    /// The element order must match
    /// [`CircuitPublicInputs::to_vec`](crate::CircuitPublicInputs::to_vec).
    fn public_inputs(&self) -> Vec<F>;
}
