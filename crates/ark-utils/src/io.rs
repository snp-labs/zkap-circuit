//! Key-file I/O helpers for arkworks proving/verifying keys.
//!
//! Exports: [`load_key_uncompressed`], [`IoError`]. Loads a
//! `CanonicalDeserialize` value from an uncompressed binary file (e.g.
//! the `.bin` payloads in the post-migration CRS bundle). Requires the
//! `io` feature (implied by `wire` default).

use ark_serialize::CanonicalDeserialize;
use std::{fs::File, io::BufReader, path::PathBuf};

/// Errors returned by [`load_key_uncompressed`].
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    /// Wraps a `std::io::Error` raised while opening or reading the file.
    #[error("failed to load key file: {0}")]
    LoadKey(#[from] std::io::Error),
    /// Wraps a `ark_serialize::SerializationError` raised while
    /// deserialising the file contents.
    #[error("failed to deserialize key file: {0}")]
    Deserialize(#[from] ark_serialize::SerializationError),
}

/// Load a `CanonicalDeserialize` value from an uncompressed binary file
/// (e.g. an arkworks proving / verifying key written with
/// `serialize_uncompressed`). Uses the `_unchecked` deserialiser — the
/// caller is responsible for trusting the source of `path`.
pub fn load_key_uncompressed<T: CanonicalDeserialize + Send + Sync + 'static>(
    path: &PathBuf,
) -> Result<T, IoError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = T::deserialize_uncompressed_unchecked(&mut reader)?;
    Ok(key)
}
