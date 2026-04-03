extern crate alloc;

// Always available
pub mod constants;
pub mod utils;
pub mod debug;

// Feature-gated modules
#[cfg(feature = "anchor")]
pub mod anchor;
#[cfg(feature = "anchor")]
pub mod matrix;

#[cfg(feature = "hashes-poseidon")]
pub mod hashes;

#[cfg(feature = "merkletree")]
pub mod merkletree;

#[cfg(feature = "base64")]
pub mod base64;

#[cfg(feature = "rsa")]
pub mod bigint;
#[cfg(feature = "rsa")]
pub mod signature;