pub mod constraints;
pub mod error;
pub mod utils;
pub mod constraints_v2;
pub mod mod_v2;

pub use constraints::*;
pub use error::*;
pub use utils::*;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Base64Table {
    pub table: Vec<u8>,
}

pub fn get_base64_table() -> Base64Table {
    let str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    Base64Table {
        table: str.as_bytes().to_vec(),
    }
}
