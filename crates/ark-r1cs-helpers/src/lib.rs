//! R1CS gadgets used across the ZKAP circuit.
//!
//! - [`comparison`] — bit-level less-than / greater-or-equal helpers and
//!   the `enforce_less_than` boundary gadget.
//! - [`packing`] — checked / unchecked byte-to-field packing and
//!   field-to-byte decomposition.
//! - [`select`] — multi-mux, multiplexer-tree, and array-element selection
//!   helpers.
//! - [`mod@slice`] — sliding-window slice extractors used by the JWT claim
//!   gadgets (`slice_efficient`, `slice_grouped`, `slice_from_start`).
//! - [`uint32`] — [`uint32::UInt32Ext`] convenience trait.
//!
//! All public symbols are re-exported at the crate root for convenience
//! (e.g. `ark_r1cs_helpers::slice_efficient`,
//! `ark_r1cs_helpers::enforce_less_than`).
//!
//! Split out of the legacy `ark-utils` meta-crate during the 2026-05
//! audit-driven hardening pass (P2 #14c). The companion split is
//! [`ark-codec`] for field/string/affine codec helpers; the legacy
//! `ark-utils` no longer exists.

#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::invalid_html_tags)]

extern crate alloc;

pub mod comparison;
pub mod packing;
pub mod select;
pub mod slice;
pub mod uint32;

// Root re-exports (matches the legacy `ark_utils::*` flat namespace).
pub use comparison::{enforce_less_than, is_greater_or_equal, is_less_than, lt_bit_vector};
pub use packing::{
    pack_bytes_to_field_unchecked, pack_decompose_bytes_checked, pack_decompose_bytes_unchecked,
};
pub use select::{
    multi_mux, one_bit_vector, select_array_element, select_array_element_be, single_multiplexer,
};
pub use slice::{
    num_to_segments_be, segments_to_num_be, slice_efficient, slice_from_start, slice_grouped,
};
pub use uint32::UInt32Ext;
