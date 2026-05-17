//! Hosts the [`prove`] free function (proof generation), the
//! request→witness `adapter` submodule, and the native witness-shaping
//! `witness` submodule. The `prover/` directory name predates the
//! 2026-05 binding-friendly refactor (the `Prover` struct was removed
//! in that change); git history of the prove flow is preserved by
//! keeping the directory in place.
//!
//! Canonical post-migration flow:
//!
//! ```text
//!   ArtifactSet::load(manifest, dir)            // trust gate
//!     → prove(&artifact_set, &prove_request)
//!         → adapter::prove_request_to_internal  // ProveRequest → WitnessRequest
//!         → witness::into_circuit_input         // (WitnessRequest, &CircuitConfig) → Vec<ZkapCircuitInput<F>>
//!         → ZkapCircuit::from_input             // build the in-process circuit
//!         → ark_ar1cs::synthesize_full_assignment
//!         → ark_ar1cs::prove(&pk, &arcs, &full_assignment, OsRng)
//! ```
//!
//! Pure native flow — the host loads the manifest-validated CRS
//! bundle and the prove function runs in-process. Production callers
//! MUST use [`crate::artifact::ArtifactSet::load`] + [`prove`] so the
//! manifest trust gate is exercised on every prove batch.

pub(crate) mod adapter;
mod prove;
pub(crate) mod witness;

pub use prove::prove;
