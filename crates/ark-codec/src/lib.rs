//! Conversion helpers between byte/string forms and field elements.
//!
//! Three sibling modules:
//!
//! - [`field`] — canonical 32-byte field-element codec
//!   ([`fe_to_be32`](field::fe_to_be32), [`fe_from_be32_canonical`](field::fe_from_be32_canonical),
//!   [`field_to_hex`](field::field_to_hex)).
//! - [`string`] — string-shaped inputs (decimal/hex JSON-style strings, padding,
//!   limb decomposition) — [`try_str_to_fields`](string::try_str_to_fields),
//!   [`pad`](string::pad), [`str_to_limbs`](string::str_to_limbs); with
//!   `field-serde`, also `string::hex_decimal_to_field`.
//! - `affine` — affine-point hex/decimal serialisation
//!   (`affine_to_hex_str`, `affine_to_decimal_str`, `coords_to_affine`) —
//!   gated on the `field-serde` feature because it depends on `ark-ec`.
//!
//! All public symbols are re-exported at the crate root for convenience
//! (e.g. `ark_codec::pad`, `ark_codec::try_str_to_fields`).
//!
//! Split out of the legacy `ark-utils` meta-crate during the 2026-05
//! audit-driven hardening pass (P2 #14b). The companion split is
//! [`ark-r1cs-helpers`] for the R1CS gadget side; the legacy `ark-utils`
//! no longer exists.

#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::invalid_html_tags)]

extern crate alloc;

pub mod field;
pub mod string;

#[cfg(feature = "field-serde")]
pub mod affine;

/// Per-module error re-exports for callers that prefer a single
/// `ark_codec::error::*` import root.
pub mod error {
    //! Errors are defined in their owning modules:
    //! - `FieldParseError` → `affine` (with `field-serde`)
    //! - `TextError` → `string`
    //! - `ConvertError` → `string`
    //! - `NonCanonicalFieldError` → `field`

    pub use crate::field::NonCanonicalFieldError;
    pub use crate::string::{ConvertError, TextError};

    #[cfg(feature = "field-serde")]
    pub use crate::affine::FieldParseError;
}

// Always-available re-exports
pub use error::{ConvertError, NonCanonicalFieldError, TextError};
pub use field::{fe_from_be32_canonical, fe_to_be32, field_to_hex};
pub use string::{pad, str_to_limbs, try_str_to_fields};

#[cfg(feature = "field-serde")]
pub use string::hex_decimal_to_field;

// Field-serde re-exports (selective to avoid ambiguity with
// string::hex_decimal_to_field).
#[cfg(feature = "field-serde")]
pub use affine::{
    FieldParseError, FromCoords, affine_to_decimal_str, affine_to_hex_str, coords_to_affine,
};
