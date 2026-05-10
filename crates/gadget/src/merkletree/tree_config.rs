//! Merkle tree configuration and the `Empty` trait for default path construction.
//!
//! [`MerkleTreeParams`] configures a Poseidon-based sparse Merkle tree over BN254-Fr
//! as used throughout the ZKAP anchor and membership proofs. [`MerkleTreeParamsVar`] is
//! the corresponding R1CS parameter type. The [`Empty`] trait extends `ark-crypto-primitives`'
//! [`Path`] (an external type, so inherent impl is not possible) with an `empty` constructor
//! that builds a default all-zero sibling path of the given height.

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use core::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::{
    Config, IdentityDigestConverter, Path, constraints::ConfigGadget,
};

use ark_crypto_primitives::crh::poseidon::{
    self,
    constraints::{CRHGadget, TwoToOneCRHGadget},
};

/// Poseidon-based Merkle tree configuration for BN254-Fr membership proofs.
///
/// Leaf hashing uses `poseidon::CRH<F>` and interior node combining uses
/// `poseidon::TwoToOneCRH<F>`. Both leaf and inner digests are plain `F`
/// field elements, avoiding type conversions at each level.
pub struct MerkleTreeParams<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for MerkleTreeParams<F> {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = poseidon::CRH<F>;
    type TwoToOneHash = poseidon::TwoToOneCRH<F>;
}

/// R1CS configuration gadget for [`MerkleTreeParams`]: maps each native type to
/// its in-circuit `FpVar` / `CRHGadget` counterpart.
pub struct MerkleTreeParamsVar<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F> ConfigGadget<MerkleTreeParams<F>, F> for MerkleTreeParamsVar<F>
where
    F: PrimeField + Absorb,
{
    type Leaf = [FpVar<F>];
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = CRHGadget<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

/// Extension trait that adds an `empty` constructor to [`Path`].
///
/// [`Path`] is an external type from `ark-crypto-primitives`, so an inherent `impl` is not
/// possible. This trait is implemented for `Path<P>` to supply a default all-zero sibling
/// path of the given `height`, used for placeholder witness allocation before tree proofs
/// are computed.
pub trait Empty<P: Config> {
    /// Constructs a default `Path` with all-zero sibling hashes and `leaf_index = 0`.
    ///
    /// `height` must equal the tree depth; the `auth_path` will have `height - 1` entries.
    fn empty(height: usize) -> Path<P>;
}

impl<P: Config> Empty<P> for Path<P> {
    fn empty(height: usize) -> Self {
        Self {
            leaf_sibling_hash: P::LeafDigest::default(),
            auth_path: vec![P::InnerDigest::default(); height - 1],
            leaf_index: 0,
        }
    }
}
