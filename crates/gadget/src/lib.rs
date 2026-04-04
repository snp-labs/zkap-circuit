//! zkap-gadget — low-level cryptographic primitives and R1CS gadgets for the ZKAP circuit.
//!
//! Provides feature-gated modules for all building blocks used by `zkap-circuit`:
//! Poseidon hashing (`hashes-poseidon`), the threshold anchor scheme (`anchor`),
//! Base64 decoding gadgets (`base64`), RSA-2048 signature verification (`rsa`),
//! Merkle tree helpers (`merkletree`), and the Vandermonde matrix (`anchor`).
//! Most application code should interact with this crate through `zkap-circuit` or
//! `zkap-service` rather than directly.

extern crate alloc;

// Always available
pub mod constants;


// Re-export ark-utils as utils for backward compatibility
pub use ark_utils as utils;

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