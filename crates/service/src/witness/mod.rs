//! Native witness-building path for the post-migration proof flow.
//!
//! Pure in-process logic that turns a host-supplied [`request::ProofRequest`]
//! into a `Vec<ZkapInputV1>` (via [`request::build_input`]) and from there
//! into a fully assigned `ZkapCircuitInput<F>` (via
//! [`input::into_circuit_input`]).
//!
//! No wasm dependency, no postcard wire decoding, no artifact paths in the
//! request type. Wasm-side ABI plumbing remains in the legacy
//! `zkap-witness-wasm` crate until its Commit 7 removal.
//!
//! Crate-internal only — host callers reach this layer through
//! [`crate::ProveRequest`] and [`crate::Prover::prove`], never through
//! the raw [`request::SharedFields`] / [`request::PerJwtFields`] shapes.

pub(crate) mod error;
pub(crate) mod input;
pub(crate) mod request;

pub(crate) use input::into_circuit_input;
pub(crate) use request::{PerJwtFields, ProofRequest, SharedFields, build_input};
