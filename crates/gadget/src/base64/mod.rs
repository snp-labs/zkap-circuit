//! Base64 URL-safe alphabet decoding — native types and table.
//!
//! Exposes [`Base64Table`] (the URL-safe alphabet `A-Z a-z 0-9 - _`) and [`get_base64_table`]
//! for constructing it. The circuit-level gadget lives in [`constraints`]; native decoding
//! helpers are in [`decoder`]. NULL-padding characters are normalised to index 0 (`'A'`)
//! so that padded JWT segments round-trip correctly through the gadget.

pub mod constraints;
pub mod decoder;
/// Error types for Base64 URL-safe decoding failures.
pub mod error;

pub use constraints::*;
pub use decoder::*;
pub use error::*;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// The 64-character URL-safe Base64 alphabet as raw ASCII byte values.
///
/// Order: `A-Z` (0–25), `a-z` (26–51), `0-9` (52–61), `-` (62), `_` (63).
/// Used by both the native decoder and the in-circuit [`Base64TableVar`] gadget.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Base64Table {
    /// The 64 ASCII byte values of the URL-safe alphabet, indexed by 6-bit Base64 position.
    pub table: Vec<u8>,
}

/// Constructs the URL-safe Base64 alphabet as a [`Base64Table`].
///
/// The returned table is stable and deterministic; callers should construct it once
/// and pass it by reference to avoid repeated allocation.
pub fn get_base64_table() -> Base64Table {
    let str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    Base64Table {
        table: str.as_bytes().to_vec(),
    }
}
