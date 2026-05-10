//! ark-utils — utility helpers for arkworks-based zero-knowledge proof code.
//!
//! Provides field-element conversion (`hex_decimal_to_field`, `try_str_to_fields`),
//! R1CS array/slice gadgets (`comparison`, `packing`, `select`, `slice`, `uint32`),
//! affine-point serialisation (`affine_serde`, feature `field-serde`),
//! key-file I/O helpers (`io`), V1 wire-format types (`wire`),
//! and shared error types (`error`).
//! Feature flags: `r1cs` (default), `field-serde`, `io`, `wire` (default).
//!
//! Error types are accessible via `ark_utils::error::*` or directly from the
//! crate root (`ark_utils::ConvertError`, `ark_utils::FieldParseError`, etc.).

extern crate alloc;

// R1CS modules (feature = "r1cs")
#[cfg(feature = "r1cs")]
pub mod comparison;

#[cfg(feature = "r1cs")]
pub mod packing;
#[cfg(feature = "r1cs")]
pub mod select;
#[cfg(feature = "r1cs")]
pub mod slice;
#[cfg(feature = "r1cs")]
pub mod uint32;

// Field serde (feature = "field-serde")
#[cfg(feature = "field-serde")]
pub mod affine_serde;
#[cfg(feature = "field-serde")]
pub use affine_serde as field_serde;

// IO (feature = "io")
#[cfg(feature = "io")]
pub mod io;

// V1 wire schema (feature = "wire") — absorbed from former
// `zkap-input-types` crate. See `wire/mod.rs` head doc for context.
#[cfg(feature = "wire")]
pub mod wire;

// Always available
pub mod convert;
pub mod error;
pub mod field_codec;

// Always-available re-exports
#[cfg(feature = "field-serde")]
pub use convert::hex_decimal_to_field;
pub use convert::{ConvertError, TextError, pad, str_to_limbs, try_str_to_fields};
pub use field_codec::{NonCanonicalFieldError, fe_from_be32_canonical, fe_to_be32, field_to_hex};

// R1CS re-exports
#[cfg(feature = "r1cs")]
pub use comparison::{enforce_less_than, is_greater_or_equal, is_less_than, lt_bit_vector};
#[cfg(feature = "r1cs")]
pub use packing::{
    pack_bytes_to_field_unchecked, pack_decompose_bytes_checked, pack_decompose_bytes_unchecked,
};
#[cfg(feature = "r1cs")]
pub use select::{
    multi_mux, one_bit_vector, select_array_element, select_array_element_be, single_multiplexer,
};
#[cfg(feature = "r1cs")]
pub use slice::{
    num_to_segments_be, segments_to_num_be, slice_efficient, slice_from_start, slice_grouped,
};
#[cfg(feature = "r1cs")]
pub use uint32::UInt32Ext;

// Field serde re-exports (selective to avoid ambiguity with convert::hex_decimal_to_field)
#[cfg(feature = "field-serde")]
pub use affine_serde::{
    FieldParseError, FromCoords, affine_to_decimal_str, affine_to_hex_str, coords_to_affine,
};

// IO re-exports
#[cfg(feature = "io")]
pub use io::{IoError, load_key_uncompressed};
