use std::sync::Arc;

use common::constants::F;
use once_cell::sync::Lazy;

use crate::{
    error::error::ApplicationError,
    interface::anchor::PoseidonAnchorKeyExtension,
    service::{
        key::{
            io::load_key_uncompressed,
            manager::{KeyKind, KeyManager},
        },
    },
};

pub static ANCHOR_KEY_MANAGER: Lazy<Arc<KeyManager>> = Lazy::new(|| Arc::new(KeyManager::new()));

pub fn load_poseidon_anchor_key_handle(path: String) -> Result<u64, ApplicationError> {
    let handle =
        ANCHOR_KEY_MANAGER.load_key_from_path(KeyKind::PoseidonAnchorKeyExt, path.clone(), |p| {
            load_key_uncompressed::<PoseidonAnchorKeyExtension<F>>(p)
        })?;

    Ok(handle.0)
}