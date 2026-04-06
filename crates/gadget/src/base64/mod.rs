pub mod constraints;
pub mod decoder;
pub mod error;

pub use constraints::*;
pub use decoder::*;
pub use error::*;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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
