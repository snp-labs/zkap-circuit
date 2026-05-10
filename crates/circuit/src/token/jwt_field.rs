//! R1CS gadgets for converting JWT field byte strings to field elements.
//!
//! Two domains are covered, each in its own sibling submodule:
//!
//! - **Hex (nonce)**: [`jwt_nonce_hex_to_field`] + [`hex_char_to_value`]
//!   live in the private `nonce` submodule. Parse a `"0x…"` hex string
//!   (up to 64 digits) into a single field element.
//!
//! - **Decimal (expiry)**: [`jwt_exp_to_field`] (with private
//!   `decimal_byte_to_digit`) lives in the private `exp` submodule. Parse
//!   a 10-digit decimal timestamp byte array into a single field element.
//!
//! All functions enforce their parsing constraints in-circuit.  See the
//! individual function doc-comments for the precise soundness/completeness
//! statements.
//!
//! L1 (R1CS-equivalence) note: the production split (nonce / exp) is purely
//! file-organisational — the constraint expressions and their ordering are
//! byte-for-byte identical to the pre-split single file.  See
//! `.omc/plans/2026-05-08-per-crate-refactor/00-cross-cutting-locks.md § L1`.
//!
//! # Tests
//!
//! Internal correctness tests live in
//! `crates/circuit/tests/jwt_field_internal.rs`.  They exercise both
//! [`jwt_nonce_hex_to_field`] and [`jwt_exp_to_field`] through the public
//! surface, so no `pub(crate)` widening is needed.

mod exp;
mod nonce;

pub use exp::jwt_exp_to_field;
pub use nonce::{hex_char_to_value, jwt_nonce_hex_to_field};
