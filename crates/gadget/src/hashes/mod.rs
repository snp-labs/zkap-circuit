//! Hash scheme traits and module re-exports for Poseidon and SHA-256.
//!
//! Defines [`CRHScheme`] (single-input collision-resistant hash) and [`TwoToOneCRHScheme`]
//! (binary compression function) as the abstract interface shared by Poseidon and SHA-256
//! instantiations. [`Parameter`] abstracts over scheme parameters. Concrete implementations
//! live in [`poseidon`] (always available with `hashes-poseidon`) and [`sha256`] (gated
//! behind `hashes-sha256`). The R1CS counterparts are in [`constraints`].

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::hash::Hash;
use core::borrow::Borrow;
use core::fmt::Debug;
use error::HashError;

pub mod constraints;
pub mod error;
pub mod poseidon;
#[cfg(feature = "hashes-sha256")]
pub mod sha256;

pub trait CRHScheme {
    type Input: ?Sized;
    type Output: Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;

    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, HashError>;
}

pub trait TwoToOneCRHScheme {
    type Input: ?Sized;
    type Output;

    fn evaluate<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError>;

    fn compress<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError>;
}

pub trait Parameter<F: Field>: Sized {
    type ParameterStruct: Clone + Debug;

    fn params() -> Self::ParameterStruct;
}
