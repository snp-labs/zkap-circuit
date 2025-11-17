use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::mekletree::tree_config::{Empty, MerkleTreeParams};

pub mod constraints;
pub mod tree_config;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleCircuitInput<F: PrimeField + Absorb> {
    pub leaf: F,
    pub leaf_idx: usize,
    pub path: Path<MerkleTreeParams<F>>,
}

impl<F> MerkleCircuitInput<F>
where
    F: PrimeField + Absorb,
{
    pub fn empty(tree_height: usize) -> Self {
        let leaf = F::default();
        let leaf_idx = 0;
        let path = Path::empty(tree_height);
        MerkleCircuitInput {
            leaf,
            leaf_idx,
            path,
        }
    }
}
