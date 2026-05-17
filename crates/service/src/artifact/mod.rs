//! Artifact loader for the post-migration ZKAP CRS bundle.
//!
//! This module owns the caller-facing trust boundary helper. The
//! canonical production path is:
//!
//! ```text
//! let set      = ArtifactSet::load(&manifest, &dir)?;
//! let response = prove(&set, &request)?;
//! ```
//!
//! [`ArtifactSet::load`] verifies the loaded files against the manifest:
//! `arcs.body_blake3()` against `manifest.ar1cs_blake3`, and the sha256
//! of every binary artifact against the corresponding manifest entry.
//! Mismatches abort with [`ArtifactError::HashMismatch`].
//!
//! The prove entry point itself lives in [`crate::prove`]; this module
//! ships only the loader so the trust gate stays separable.

mod error;
mod set;

pub use error::ArtifactError;
pub use set::ArtifactSet;
