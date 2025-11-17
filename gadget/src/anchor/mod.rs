use ark_ff::PrimeField;
use ark_std::rand::Rng;

use crate::{anchor::error::AnchorError, matrix::Matrix};

pub mod constraints;
pub mod dl;
pub mod error;
pub mod poseidon;
pub mod utils;

pub trait AnchorScheme {
    type Scalar: PrimeField;
    type PublicKey;
    type Secret;
    type Anchor;
    type Witness;

    fn setup<R: Rng>(rng: &mut R, n: usize) -> Result<Self::PublicKey, AnchorError>;
    fn generate_anchor(
        pk: &Self::PublicKey,
        secrets: &Self::Secret,
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Self::Anchor, AnchorError>;
    fn generate_witness(
        secrets: &Self::Secret,
        selector: &[usize],
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Self::Witness, AnchorError>;
    fn verify(
        pk: &Self::PublicKey,
        anchor: &Self::Anchor,
        witness: &Self::Witness,
    ) -> Result<(), AnchorError>;
    fn get_indices(
        pk: &Self::PublicKey,
        anchor: &Self::Anchor,
        known_secrets: &Self::Secret,
        matrix: &Matrix<Self::Scalar>,
    ) -> Result<Vec<usize>, AnchorError>;
}
