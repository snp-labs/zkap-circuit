//! Conversion helpers between byte/string forms and field elements.
//!
//! Three sibling modules:
//!
//! - [`field`] — canonical 32-byte field-element codec
//!   ([`fe_to_be32`](field::fe_to_be32), [`fe_from_be32_canonical`](field::fe_from_be32_canonical),
//!   [`field_to_hex`](field::field_to_hex)).
//! - [`string`] — string-shaped inputs (decimal/hex JSON-style strings, padding,
//!   limb decomposition) — [`try_str_to_fields`](string::try_str_to_fields),
//!   [`pad`](string::pad), [`str_to_limbs`](string::str_to_limbs),
//!   [`hex_decimal_to_field`](string::hex_decimal_to_field).
//! - [`affine`] — affine-point hex/decimal serialisation
//!   ([`affine_to_hex_str`](affine::affine_to_hex_str), [`affine_to_decimal_str`](affine::affine_to_decimal_str),
//!   [`coords_to_affine`](affine::coords_to_affine)) — gated on the `field-serde`
//!   feature because it depends on `ark-ec`.
//!
//! All public symbols are re-exported at the crate root for convenience
//! (e.g. `ark_utils::pad`, `ark_utils::try_str_to_fields`).

pub mod field;
pub mod string;

#[cfg(feature = "field-serde")]
pub mod affine;
