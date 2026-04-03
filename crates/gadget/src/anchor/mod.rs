use ark_std::rand::Rng;

use crate::anchor::error::AnchorError;

pub mod constraints;
// pub mod dl;
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
    type Matrix;
    type PublicKey;
    type Secret;
    type Anchor;
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
    type Field;

    /// Compute the inner product of two vectors
    fn inner_product(v1: &[Self::Field], v2: &[Self::Field]) -> Result<Self::Field, AnchorError>;
}
