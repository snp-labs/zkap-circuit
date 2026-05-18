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
//!   ArtifactSet::load(manifest, dir)               // trust gate
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
//!             ark_ar1cs::prove(&pk, &arcs, &full_assignment, OsRng)
//! ```
//!
//! Pure native flow — the host loads the manifest-validated CRS bundle
//! and the prove function runs in-process. Production callers MUST use
//! [`crate::artifact::ArtifactSet::load`] + [`prove`] so the manifest
//! trust gate is exercised on every prove batch.

pub(crate) mod adapter;
pub(crate) mod circuit_input;
mod prove;

/// Required wire-format length for `rsa_modulus_b64` and the JWT signature
/// segment. RSA-2048 keys/signatures are exactly 256 bytes; any other
/// length is a host bug or a malformed payload.
pub(crate) const RSA_2048_BYTES: usize = 256;

pub use prove::{WitnessBundle, prove, synthesize_witnesses, synthesize_witnesses_streaming};
