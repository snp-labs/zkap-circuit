//! Hash scheme traits and module re-exports for Poseidon and SHA-256.
//!
//! Defines [`CRHScheme`] (single-input collision-resistant hash) and [`TwoToOneCRHScheme`]
//! (binary compression function) as the abstract interface shared by Poseidon and SHA-256
//! instantiations. [`Parameter`] abstracts over scheme parameters. Concrete implementations
//! live in [`poseidon`] (always available with `hashes-poseidon`) and the `sha256`
//! submodule (gated behind `hashes-sha256`). The R1CS counterparts are in
//! [`constraints`].

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::hash::Hash;
use core::borrow::Borrow;
use core::fmt::Debug;
use error::HashError;

pub mod constraints;
/// Error types for all hash operations (native and in-circuit).
pub mod error;
pub mod poseidon;
/// SHA-256 native evaluation and circuit gadgets (enabled by `hashes-sha256`).
#[cfg(feature = "hashes-sha256")]
pub mod sha256;

/// Abstract interface for a single-input collision-resistant hash function.
///
/// Implementors provide native `evaluate` and carry their state via associated types.
/// The Poseidon instantiation is in [`poseidon`]; SHA-256 is in the `sha256` submodule
/// (feature-gated).
/// The R1CS counterpart is [`constraints::CRHSchemeGadget`].
pub trait CRHScheme {
    /// The hash input type; `?Sized` allows slice inputs like `[F]` or `[u8]`.
    type Input: ?Sized;
    /// The hash output type; must be serializable and comparable for use in Merkle trees.
    type Output: Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Evaluates the hash on `input` and returns the output or a [`HashError`].
    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, HashError>;
}

/// Abstract interface for a two-to-one collision-resistant compression function.
///
/// Used as the interior hash in Merkle trees to combine two child digests into one parent.
/// `evaluate` and `compress` are kept separate so implementations can use different
/// strategies (e.g. length-separated domains); the default Poseidon impl delegates both
/// to the same underlying hash.
pub trait TwoToOneCRHScheme {
    /// The input type for both left and right operands; `?Sized` allows slice inputs.
    type Input: ?Sized;
    /// The output type produced by combining two children.
    type Output;

    /// Evaluates `H(left_input || right_input)` — the standard Merkle combination.
    fn evaluate<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError>;

    /// Applies a compression step for length-separation or domain-specific contexts;
    /// for Poseidon this delegates to `evaluate`.
    fn compress<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError>;
}

/// Associates a concrete parameter struct with a field type `F`.
///
/// Implementors (e.g. Poseidon) return their pre-computed `PoseidonConfig` via
/// `params()`; callers cache the result rather than re-constructing on every call.
pub trait Parameter<F: Field>: Sized {
    /// The concrete configuration struct (e.g. `PoseidonConfig<F>`).
    type ParameterStruct: Clone + Debug;

    /// Returns the fixed parameters for this scheme and field.
    fn params() -> Self::ParameterStruct;
}
