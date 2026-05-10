//! Merkle tree circuit input types for ZKAP membership proofs.
//!
//! [`MerkleCircuitInput`] bundles a leaf value, its index, and the [`Path`] (sibling
//! hashes) needed to reconstruct the root. The tree uses the Poseidon CRH via
//! [`crate::merkletree::tree_config::MerkleTreeParams`]. The in-circuit membership
//! enforcer is [`crate::merkletree::constraints::MerkleCircuitInputVar`].

use ark_crypto_primitives::{merkle_tree::Path, sponge::Absorb};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::merkletree::tree_config::{Empty, MerkleTreeParams};

pub mod constraints;
pub mod tree_config;

/// Bundles a Merkle leaf with its authentication path for use in membership proofs.
///
/// `leaf` is the raw field element committed at position `leaf_idx`; `path` contains
/// the sibling hashes needed to reconstruct the root. Allocated in-circuit via
/// [`crate::merkletree::constraints::MerkleCircuitInputVar`].
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleCircuitInput<F: PrimeField + Absorb> {
    /// The leaf value committed at this position (Poseidon-hashed before insertion).
    pub leaf: F,
    /// Zero-based index of this leaf in the tree; used to set the path direction bits.
    pub leaf_idx: usize,
    /// Sibling hashes along the path from leaf to root (depth-first, closest sibling first).
    pub path: Path<MerkleTreeParams<F>>,
}

impl<F> MerkleCircuitInput<F>
where
    F: PrimeField + Absorb,
{
    /// Returns an all-zero `MerkleCircuitInput` with an empty sibling path of `tree_height` levels.
    ///
    /// Used to allocate a placeholder before witness values are computed.
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
