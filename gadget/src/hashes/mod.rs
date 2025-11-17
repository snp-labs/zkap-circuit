use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::hash::Hash;
use error::HashError;
use std::borrow::Borrow;
use std::fmt::Debug;

pub mod blake2s256;
pub mod constraints;
pub mod error;
pub mod mimc7;
pub mod poseidon;
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
