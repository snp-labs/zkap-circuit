use std::{fs::File, io::BufReader, path::PathBuf};

use ark_serialize::CanonicalDeserialize;

use crate::error::IoError;

pub fn load_key_uncompressed<T: CanonicalDeserialize + Send + Sync + 'static>(
    path: &PathBuf,
) -> Result<T, IoError> {
    let file = File::open(path).map_err(|_| IoError::LoadKeyFailed)?;

    let mut reader = BufReader::new(file);
    let key = T::deserialize_uncompressed_unchecked(&mut reader)
        .map_err(|_| IoError::DeserializeFailed)?;

    Ok(key)
}
