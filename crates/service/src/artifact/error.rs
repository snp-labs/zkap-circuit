//! Error type for [`super::ArtifactSet`] loaders.

use std::path::PathBuf;

use crate::manifest::ManifestError;

/// Reason an [`super::ArtifactSet`] load failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactError {
    /// Filesystem read failed for `path`.
    #[error("io error reading {path}: {source}")]
    Io {
        /// The path that failed to open / read.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The `.ar1cs` body failed format / checksum validation.
    #[error("circuit.ar1cs parse error: {0}")]
    ArcsFormat(String),

    /// `CanonicalDeserialize` failed for one of pk / vk / pvk.
    #[error("{what} deserialize error: {message}")]
    Deserialize {
        /// Logical artifact name (`"pk"`, `"vk"`, `"pvk"`).
        what: &'static str,
        /// Underlying ark-serialize error rendered as text (`SerializationError`
        /// does not implement `std::error::Error` in a stable way across
        /// arkworks releases).
        message: String,
    },

    /// A hash check (sha256 or `ar1cs_blake3`) disagreed with the manifest.
    #[error("hash mismatch on {field}: expected {expected}, got {got}")]
    HashMismatch {
        /// The manifest field whose hash disagrees.
        field: &'static str,
        /// Manifest value (lowercase hex).
        expected: String,
        /// Recomputed value (lowercase hex).
        got: String,
    },

    /// Manifest signature verification failed (or a signature was
    /// required and not present). Emitted by
    /// [`super::ArtifactSet::load`] when the caller supplies a
    /// `VerifyingKey` and the manifest signature is missing,
    /// malformed, or rejected by the ed25519 verifier.
    #[error("manifest signature check failed: {0}")]
    Signature(#[from] ManifestError),
}
