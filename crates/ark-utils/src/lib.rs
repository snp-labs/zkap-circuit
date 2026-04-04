//! ark-utils — utility helpers for arkworks-based zero-knowledge proof code.
//!
//! Provides field-element conversion (`hex_decimal_to_field`, `try_str_to_fields`),
//! R1CS array/slice gadgets (`select`, `slice`, `packing`), EVM calldata codegen (`evm`),
//! serialisation helpers (`io`, `field-serde`), and shared error types.
//! Feature flags: `r1cs`, `evm-codegen`, `field-serde`, `io`.

extern crate alloc;

// R1CS modules (feature = "r1cs")
#[cfg(feature = "r1cs")]
pub mod comparison;

#[cfg(feature = "r1cs")]
pub mod jwt_field;
#[cfg(feature = "r1cs")]
pub mod packing;
#[cfg(feature = "r1cs")]
pub mod select;
#[cfg(feature = "r1cs")]
pub mod slice;
#[cfg(feature = "r1cs")]
pub mod uint32;

// EVM codegen (feature = "evm-codegen")
#[cfg(feature = "evm-codegen")]
pub mod evm;

// Field serde (feature = "field-serde")
#[cfg(feature = "field-serde")]
pub mod affine_serde;
#[cfg(feature = "field-serde")]
pub use affine_serde as field_serde;

// IO (feature = "io")
#[cfg(feature = "io")]
pub mod io;

// Always available
pub mod convert;
pub mod error;

// Always-available re-exports
pub use convert::*;

// R1CS re-exports
#[cfg(feature = "r1cs")]
pub use comparison::*;
#[cfg(feature = "r1cs")]
pub use packing::*;
#[cfg(feature = "r1cs")]
pub use select::*;
#[cfg(feature = "r1cs")]
pub use slice::*;
#[cfg(feature = "r1cs")]
pub use uint32::*;

// Field serde re-exports (selective to avoid ambiguity with convert::hex_decimal_to_field)
#[cfg(feature = "field-serde")]
pub use affine_serde::{
    FieldParseError, FromCoords, affine_to_decimal_str, affine_to_hex_str, coords_to_affine,
};

// IO re-exports
#[cfg(feature = "io")]
pub use io::*;
