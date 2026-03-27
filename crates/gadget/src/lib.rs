extern crate alloc;

// WASM-compatible modules (always available)
pub mod anchor;
pub mod utils;
pub mod matrix;
pub mod hashes;
pub mod mekletree;
pub mod debug;

// Full-only modules (require std-dependent deps like rsa, num-bigint, etc.)
#[cfg(feature = "full")]
pub mod base64;
#[cfg(feature = "full")]
pub mod bigint;
#[cfg(feature = "full")]
pub mod signature;