//! Artifact loader for the post-migration ZKAP CRS bundle.
//!
//! This module owns the caller-facing trust boundary helper. The
//! canonical production path is:
//!
//! ```text
//! let set = ArtifactSet::load(&manifest, &dir)?;
//! let prover = Prover::from_artifact(set);     // (Commit 4)
//! let proof  = prover.prove(&request, rng)?;    // (Commit 4)
//! ```
//!
//! [`ArtifactSet::load`] verifies the loaded files against the manifest:
//! `arcs.body_blake3()` against `manifest.ar1cs_blake3`, and the sha256
//! of every binary artifact against the corresponding manifest entry.
//! Mismatches abort with [`ArtifactError::HashMismatch`].
//!
//! [`ArtifactSet::load_unverified`] is the **non-canonical** sibling for
//! tests, tools, and caller-trusted environments. It does not consult a
//! manifest and trusts the on-disk layout verbatim. Production callers
//! MUST prefer [`ArtifactSet::load`].
//!
//! The `Prover` handle and the proving entry points themselves arrive in
//! Commit 3 (witness/full_assignment) and Commit 4 (prove flow); this
//! module ships only the loader to keep Commit 2 atomic.

mod error;
mod set;

pub use error::ArtifactError;
pub use set::ArtifactSet;
