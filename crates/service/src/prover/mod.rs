//! Native ark-ar1cs proof generation entry point.
//!
//! Canonical post-migration flow (2026-05 ark-ar1cs boundary plan):
//!
//! ```text
//!   ArtifactSet::load(manifest, dir)            // trust gate
//!     → Prover::from_artifact(set)              // build handle
//!     → Prover::prove(&proof_request, rng)
//!         → witness::build_input                // ProofRequest → Vec<ZkapInputV1>
//!         → witness::into_circuit_input         // ZkapInputV1 → ZkapCircuitInput<F>
//!         → ZkapCircuit::from_input             // build the in-process circuit
//!         → ark_ar1cs::synthesize_full_assignment
//!         → ark_ar1cs::prove(&pk, &arcs, &full_assignment, rng)
//! ```
//!
//! Pure native flow — the host loads the manifest-validated CRS
//! bundle and the prover runs in-process. The single non-canonical
//! shortcut
//! [`prove_from_unverified_paths`] exists for tests and caller-trusted
//! environments; production callers MUST use
//! [`crate::artifact::ArtifactSet::load`] + [`Prover::from_artifact`] +
//! [`Prover::prove`] so the manifest trust gate is exercised on every
//! prove batch.

pub(crate) mod adapter;
mod prove;

pub use prove::{Prover, prove_from_unverified_paths};
