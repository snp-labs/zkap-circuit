use std::{fs::File, io::BufReader, path::PathBuf};

use ark_serialize::CanonicalDeserialize;

use crate::error::{ApplicationError, KeyError};

pub fn load_key_uncompressed<T: CanonicalDeserialize + Send + Sync + 'static>(
    path: &PathBuf,
) -> Result<T, ApplicationError> {
    load_key_uncompressed_inner(path).map_err(ApplicationError::from)
}

fn load_key_uncompressed_inner<T: CanonicalDeserialize + Send + Sync + 'static>(
    path: &PathBuf,
) -> Result<T, KeyError> {
    let file = File::open(path).map_err(|source| KeyError::LoadFailed {
        path: path.display().to_string(),
        source,
    })?;

    // let mmap = unsafe {
    //     memmap2::MmapOptions::new()
    //         .map(&file)
    //         .map_err(|source| KeyError::LoadFailed {
    //             path: path.display().to_string(),
    //             source,
    //         })?
    // };

    // let mut slice: &[u8] = &mmap;
    // T::deserialize_uncompressed_unchecked(&mut slice).map_err(|source| {
    //     KeyError::DeserializeFailed {
    //         path: path.display().to_string(),
    //         source,
    //     }
    // })
    let mut reader = BufReader::new(file);
    let key = T::deserialize_uncompressed_unchecked(&mut reader).map_err(|source| {
        KeyError::DeserializeFailed {
            path: path.display().to_string(),
            source,
        }
    })?;

    Ok(key)
}
