//! Native Groth16 prove pipeline.
//!
//! `adapter` decodes the wire-format `ProveRequest` into the F-based
//! `SharedDecoded` + `Vec<CredentialDecoded>` tuple (lean — no derived
//! crypto state). `circuit_input` exposes `pub(crate)` stage builders
//! (`build_anchor_stage`, `build_jwt_stage`, `build_audience_stage`,
//! `build_merkle_witness`, `compute_public_inputs`) that turn decoded
//! inputs into the per-credential `ZkapCircuitInput<F>` algebra.
//! `prove` orchestrates the cryptographic pipeline (pre-batch derive_x /
//! derive_selector / one_positions) and per-credential streaming
//! (`synthesize_full_assignment` → `ar1cs_prove`).
//!
//! Canonical post-migration flow:
//!
//! ```text
//!   ArtifactSet::load_signed(manifest, dir, vk)    // signed trust gate
//!   # or ArtifactSet::load_unsigned(manifest, dir) // caller-trusted manifest
//!     → prove(&artifact_set, &prove_request)
//!         → adapter::prove_request_to_decoded      // ProveRequest → (SharedDecoded, [CredentialDecoded; k])
//!         → derive_x_from_secret per credential    // x_list: Vec<F>
//!         → derive_selector_from_x_list_and_anchor // selector + one_positions
//!         → for each credential:
//!             circuit_input::build_anchor_stage
//!             circuit_input::build_jwt_stage
//!             circuit_input::build_audience_stage
//!             circuit_input::build_merkle_witness
//!             circuit_input::compute_public_inputs
//!             ZkapCircuit::from_input
//!             ark_ar1cs::synthesize_full_assignment
//!             ark_ar1cs::prove_with_mode(&pk, &prepared_arcs, &full_assignment, OsRng, VerifyAfter)
//! ```
//!
//! Pure native flow — the host loads the manifest-validated CRS bundle
//! and the prove function runs in-process. Production signed-bundle callers
//! MUST use [`crate::artifact::ArtifactSet::load_signed`] + [`prove`] so the
//! manifest authenticity and artifact hash gates are exercised before proving.

pub(crate) mod adapter;
pub(crate) mod circuit_input;
mod prove;

pub(crate) use crate::RSA_2048_BYTES;

pub use prove::{prove, synthesize_witnesses, synthesize_witnesses_streaming};
