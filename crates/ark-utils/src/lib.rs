//! ark-utils — utility helpers for arkworks-based zero-knowledge proof code.
//!
//! # Module groups
//!
//! - [`codec`] — field-element / byte-string / affine-point conversions
//!   ([`try_str_to_fields`], [`fe_to_be32`], [`field_to_hex`], …; with
//!   `field-serde`: also `hex_decimal_to_field` and the affine-point
//!   helpers in `codec::affine`).
//! - [`r1cs`] — R1CS gadgets (`comparison`, `packing`, `select`, `slice`,
//!   `uint32`) — all gated behind the `r1cs` feature.
//! - `io` — uncompressed key-file loader; gated behind the `io` feature.
//! - [`error`] — re-exports of the per-module error types for callers that
//!   prefer a single import root (`ark_utils::error::ConvertError`, etc.).
//!
//! Feature flags: `r1cs` (default), `field-serde`, `io`.
//!
//! Error types are accessible via `ark_utils::error::*` or directly from the
//! crate root (`ark_utils::ConvertError`, `ark_utils::FieldParseError`, etc.).

// Crate-internal `missing_docs` warning, not a `#[deny]`. Phase 6 / H5
// staged path: clears the ark-utils baseline (41 warnings at HEAD =
// dde7792a, plan v2 §6) and locks in the floor without depending on a
// workspace-wide `[lints.rust] missing_docs = "warn"` (which would block
// on ≥314 cross-crate warnings — see `00-workspace-hygiene.md` §H5
// baseline). The workspace-wide flip happens once every other crate
// hits zero warnings at this gate.
#![warn(missing_docs)]
// Phase 8 / P8-arkutils-doc-link-audit (Phase 7 critic MINOR #3):
// rustdoc lints elevated to deny so a broken intra-doc link or
// stray angle-bracketed type (`Foo<T>` interpreted as HTML) fails
// the canonical `cargo doc -p ark-utils --no-deps` build instead
// of accumulating silently. Only the canonical (default-features)
// build is gated; `--no-default-features` rustdoc is not on a CI
// gate today and may surface conditional-feature link warnings.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::invalid_html_tags)]

extern crate alloc;

// Always-available conversions (`field`, `string`).  `affine` lives under
// the same module group but is gated on `field-serde`.
pub mod codec;

// R1CS gadgets (feature = "r1cs", default-on).
#[cfg(feature = "r1cs")]
pub mod r1cs;

// IO (feature = "io")
#[cfg(feature = "io")]
pub mod io;

// Per-module error re-exports (kept as its own path so callers can
// `use ark_utils::error::*;` without the conversion submodule).
pub mod error;

// Always-available re-exports (codec)
pub use codec::field::{NonCanonicalFieldError, fe_from_be32_canonical, fe_to_be32, field_to_hex};
#[cfg(feature = "field-serde")]
pub use codec::string::hex_decimal_to_field;
pub use codec::string::{ConvertError, TextError, pad, str_to_limbs, try_str_to_fields};

// Field-serde re-exports (selective to avoid ambiguity with
// codec::string::hex_decimal_to_field).
#[cfg(feature = "field-serde")]
pub use codec::affine::{
    FieldParseError, FromCoords, affine_to_decimal_str, affine_to_hex_str, coords_to_affine,
};

// R1CS re-exports
#[cfg(feature = "r1cs")]
pub use r1cs::comparison::{enforce_less_than, is_greater_or_equal, is_less_than, lt_bit_vector};
#[cfg(feature = "r1cs")]
pub use r1cs::packing::{
    pack_bytes_to_field_unchecked, pack_decompose_bytes_checked, pack_decompose_bytes_unchecked,
};
#[cfg(feature = "r1cs")]
pub use r1cs::select::{
    multi_mux, one_bit_vector, select_array_element, select_array_element_be, single_multiplexer,
};
#[cfg(feature = "r1cs")]
pub use r1cs::slice::{
    num_to_segments_be, segments_to_num_be, slice_efficient, slice_from_start, slice_grouped,
};
#[cfg(feature = "r1cs")]
pub use r1cs::uint32::UInt32Ext;

// IO re-exports
#[cfg(feature = "io")]
pub use io::{IoError, load_key_uncompressed};
