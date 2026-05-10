//! R1CS gadgets used across the ZKAP circuit.
//!
//! All sub-modules are gated behind the `r1cs` feature (default-on); each
//! one is independent of the others — they are grouped together only for
//! navigability.
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
//! (e.g. `ark_utils::slice_efficient`, `ark_utils::enforce_less_than`).

pub mod comparison;
pub mod packing;
pub mod select;
pub mod slice;
pub mod uint32;
