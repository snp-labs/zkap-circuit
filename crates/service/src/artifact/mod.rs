//! Artifact loader for the post-migration ZKAP CRS bundle.
//!
//! This module owns the caller-facing trust boundary helper. The
//! canonical production path is:
//!
//! ```text
//! let set      = ArtifactSet::load_signed(&manifest, &dir, &verifying_key)?;
//! let response = prove(&set, &request)?;
//! ```
//!
//! [`ArtifactSet::load_signed`] first verifies manifest authenticity, then
//! verifies the loaded files against the manifest: `ar1cs_blake3` against the
//! parsed `.ar1cs` body hash, and the sha256 of every binary artifact against
//! the corresponding manifest entry. [`ArtifactSet::load_unsigned`] performs
//! the same hash checks but trusts manifest authenticity to the caller.
//! Mismatches abort with [`ArtifactError::HashMismatch`].
//!
//! The prove entry point itself lives in [`crate::prove`]; this module
//! ships only the loader so the trust gate stays separable.

mod error;
mod set;

pub use error::ArtifactError;
pub use set::{ArtifactLoadTiming, ArtifactSet};
