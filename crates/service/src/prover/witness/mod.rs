//! Native witness-building path for the post-migration proof flow.
//!
//! Pure in-process logic that turns a host-supplied
//! [`request::WitnessRequest`] into a fully assigned
//! `ZkapCircuitInput<F>` (via [`input::into_circuit_input`]).
//!
//! Crate-internal only — host callers reach this layer through
//! [`crate::ProveRequest`] and [`crate::prove`], never through
//! the raw [`request::SharedFields`] / [`request::PerJwtFields`] shapes.

pub(crate) mod error;
pub(crate) mod input;
pub(crate) mod request;

/// Required wire-format length for `rsa_modulus_be` and `rsa_signature_be`.
/// RSA-2048 keys/signatures are exactly 256 bytes; any other length is a
/// host bug or a malformed payload.
pub(crate) const RSA_2048_BYTES: usize = 256;

pub(crate) use input::into_circuit_input;
pub(crate) use request::{PerJwtFields, SharedFields, WitnessRequest};
