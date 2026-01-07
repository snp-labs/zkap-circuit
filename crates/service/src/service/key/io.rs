use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::error::KeyError;

pub fn save_key_uncompressed<T: CanonicalSerialize>(
    path: &PathBuf,
    key: &T,
) -> Result<(), KeyError> {
    let file = File::create(path).map_err(|source| KeyError::SaveFailed {
        path: path.display().to_string(),
        source,
    })?;
    let mut writer = BufWriter::new(file);

    key.serialize_uncompressed(&mut writer)
        .map_err(|source| KeyError::SerializeFailed {
            path: path.display().to_string(),
            source,
        })?;

    writer.flush().map_err(|source| KeyError::SaveFailed {
        path: path.display().to_string(),
        source,
    })?;

    Ok(())
}
pub fn load_key_uncompressed<T: CanonicalDeserialize + Send + Sync + 'static>(
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
