//! Native Groth16 prove pipeline.
//!
//! `adapter` decodes the wire-format `ProveRequest` into the F-based
//! `SharedDecoded` + `Vec<CredentialDecoded>` tuple (lean — no derived
//! crypto state). `circuit_input` exposes `pub(crate)` stage builders
//! (`build_anchor_stage`, `build_jwt_stage`, `build_shared_audience_stage`,
//! `build_merkle_witness`, `compute_public_inputs`) that turn decoded
//! inputs into the per-credential `ZkapCircuitInput<F>` algebra. The
//! audience stage is **batch-shared**: one `aud_list` / `h_aud_list` built
//! from every credential's `aud` is reused across all k witnesses.
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
//!         → validate::validate_decoded_inputs        // off-circuit pre-flight (merkle membership, nonce binding, random!=0)
//!         → build_shared_audience_stage              // one aud_list/h_aud_list for the batch
//!         → for each credential:
//!             circuit_input::build_anchor_stage
//!             circuit_input::build_jwt_stage
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
mod validate;

pub(crate) use crate::RSA_2048_BYTES;

pub use prove::{PreflightMode, prove, prove_bundles, synthesize_witnesses, verify};
// `synthesize_witnesses_streaming` is re-exported only when the
// internal, non-default `internal-streaming-witness` feature is active
// (enabled by the in-workspace `zkap-witness-gen-wasm` crate). Gating
// the re-export here keeps it out of the default public surface and
// avoids an unused-import warning when the feature is off.
#[cfg(feature = "internal-streaming-witness")]
pub use prove::synthesize_witnesses_streaming;
