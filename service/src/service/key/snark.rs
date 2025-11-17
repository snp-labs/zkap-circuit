use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::{
    error::error::ApplicationError,
    interface::snark::ProvingKeyExtension,
    service::{
        constants::BN254,
        key::{
            io::load_key_uncompressed,
            manager::{KeyKind, KeyManager},
        },
    },
};

pub static SNARK_KEY_MANAGER: Lazy<Arc<KeyManager>> = Lazy::new(|| Arc::new(KeyManager::new()));

pub fn load_snark_key_handle(path: String) -> Result<u64, ApplicationError> {
    let handle =
        SNARK_KEY_MANAGER.load_key_from_path(KeyKind::ProvingKeyExt, path.clone(), |p| {
            load_key_uncompressed::<ProvingKeyExtension<BN254>>(p)
        })?;
    Ok(handle.0)
}
