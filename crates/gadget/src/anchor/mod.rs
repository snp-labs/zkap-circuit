//! Threshold anchor scheme traits and core data structures.
//!
//! The anchor scheme allows a prover to demonstrate knowledge of at least `k` out of `n`
//! secrets without revealing which `k` were used. Two core traits are defined here:
//! [`AnchorScheme`] for setup/anchor/witness generation and verification, and
//! [`AnchorUtils`] for inner-product helpers used by the gadget layer.

use ark_std::rand::Rng;

use crate::anchor::error::AnchorError;

pub mod constraints;
pub mod error;
pub mod poseidon;
#[cfg(feature = "rsa")]
pub mod utils;

/// Core trait for the Anchor Scheme V3
///
/// Key improvements:
/// - Removed unnecessary methods (get_indices split into a separate utility)
/// - Clearer separation of responsibilities
/// - Simplified type parameters
pub trait AnchorScheme {
    /// Vandermonde matrix type; encodes the `(m × n)` structure that maps the
    /// secret vector to the anchor polynomial evaluation.
    type Matrix;
    /// Public-key type returned by [`Self::setup`]; carries the hash parameters
    /// (e.g. Poseidon `PoseidonConfig`) used by both prover and verifier.
    type PublicKey;
    /// Secret type: a vector of `n` field elements — the pre-hashed
    /// H(aud, iss, sub) values for each slot.
    type Secret;
    /// Anchor type: a vector of `m = n − k + 1` field elements computed as
    /// `Matrix · H(secrets)`, committed publicly on-chain.
    type Anchor;
    /// Witness type carrying `a` (auxiliary, length m), `b = a · Matrix`
    /// (length n), and `h_known` (hashed secrets at selected positions).
    type Witness;

    /// Generate a public key
    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::PublicKey, AnchorError>;

    /// Generate an Anchor (from the full set of secrets)
    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Self::Matrix,
    ) -> Result<Self::Anchor, AnchorError>;

    /// Generate a Witness (from a partial set of secrets)
    fn generate_witness(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        selector: &[u8],
        matrix: &Self::Matrix,
    ) -> Result<Self::Witness, AnchorError>;

    /// Verify an Anchor and Witness
    fn verify(anchor: &Self::Anchor, witness: &Self::Witness) -> Result<(), AnchorError>;
}

/// Trait for Anchor-related helper functions
pub trait AnchorUtils {
    /// The scalar field over which inner-product computations are performed;
    /// must match the field used by the associated [`AnchorScheme`] implementation.
    type Field;

    /// Compute the inner product of two vectors
    fn inner_product(v1: &[Self::Field], v2: &[Self::Field]) -> Result<Self::Field, AnchorError>;
}
