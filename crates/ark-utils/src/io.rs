//! Key-file I/O helpers for arkworks proving/verifying keys.
//!
//! Exports: [`load_key_uncompressed`], [`IoError`].  Loads a
//! `CanonicalDeserialize` value from an uncompressed binary file (e.g.
//! `.arzkey`).  Requires the `io` feature (implied by `wire` default).

use ark_serialize::CanonicalDeserialize;
use std::{fs::File, io::BufReader, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum IoError {
    #[error("failed to load key file: {0}")]
    LoadKey(#[from] std::io::Error),
    #[error("failed to deserialize key file: {0}")]
    Deserialize(#[from] ark_serialize::SerializationError),
}

pub fn load_key_uncompressed<T: CanonicalDeserialize + Send + Sync + 'static>(
    path: &PathBuf,
) -> Result<T, IoError> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let key = T::deserialize_uncompressed_unchecked(&mut reader)?;
    Ok(key)
}
