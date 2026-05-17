//! Native ark-ar1cs proof generation entry point.
//!
//! Canonical post-migration flow:
//!
//! ```text
//!   ArtifactSet::load(manifest, dir)            // trust gate
//!     → Prover::from_artifact(set)              // build handle
//!     → Prover::prove(&prove_request)
//!         → adapter::prove_request_to_internal  // ProveRequest → ProofRequest
//!         → witness::build_input                // ProofRequest → Vec<ZkapInputV1>
//!         → witness::into_circuit_input         // ZkapInputV1 → ZkapCircuitInput<F>
//!         → ZkapCircuit::from_input             // build the in-process circuit
//!         → ark_ar1cs::synthesize_full_assignment
//!         → ark_ar1cs::prove(&pk, &arcs, &full_assignment, OsRng)
//! ```
//!
//! Pure native flow — the host loads the manifest-validated CRS
//! bundle and the prover runs in-process. The single non-canonical
//! shortcut `prove_from_unverified_paths_for_testing` (gated behind
//! the `dev-unverified-artifacts` Cargo feature) exists for tests and
//! caller-trusted environments; production builds do not compile it.
//! Production callers MUST use
//! [`crate::artifact::ArtifactSet::load`] + [`Prover::from_artifact`] +
//! [`Prover::prove`] so the manifest trust gate is exercised on every
//! prove batch.

pub(crate) mod adapter;
mod prove;

pub use prove::Prover;
#[cfg(feature = "dev-unverified-artifacts")]
pub use prove::prove_from_unverified_paths_for_testing;
