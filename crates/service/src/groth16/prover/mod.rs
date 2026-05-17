//! Hosts the [`prove`] free function (proof generation), the
//! request→witness `adapter` submodule, and the witness-shaping
//! `witness_{error,input,request}` sibling modules. The `prover/`
//! directory name predates the 2026-05 binding-friendly refactor
//! (the `Prover` struct was removed in that change); git history of
//! the prove flow is preserved by keeping the directory in place.
//!
//! Canonical post-migration flow:
//!
//! ```text
//!   ArtifactSet::load(manifest, dir)              // trust gate
//!     → prove(&artifact_set, &prove_request)
//!         → adapter::prove_request_to_internal    // ProveRequest → WitnessRequest
//!         → witness_input::into_circuit_input     // (WitnessRequest, &CircuitConfig) → Vec<ZkapCircuitInput<F>>
//!         → ZkapCircuit::from_input               // build the in-process circuit
//!         → ark_ar1cs::synthesize_full_assignment
//!         → ark_ar1cs::prove(&pk, &arcs, &full_assignment, OsRng)
//! ```
//!
//! Pure native flow — the host loads the manifest-validated CRS
//! bundle and the prove function runs in-process. Production callers
//! MUST use [`crate::artifact::ArtifactSet::load`] + [`prove`] so the
//! manifest trust gate is exercised on every prove batch.

pub(crate) mod adapter;
pub(crate) mod circuit_input;
mod prove;
pub(crate) mod witness_error;
pub(crate) mod witness_input;
pub(crate) mod witness_request;

/// Required wire-format length for `rsa_modulus_be` and `rsa_signature_be`.
/// RSA-2048 keys/signatures are exactly 256 bytes; any other length is a
/// host bug or a malformed payload.
pub(crate) const RSA_2048_BYTES: usize = 256;

pub use prove::prove;
