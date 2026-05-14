//! Native witness-building path for the post-migration proof flow.
//!
//! Pure in-process logic that turns a host-supplied [`request::ProofRequest`]
//! into a `Vec<ZkapInputV1>` (via [`request::build_input`]) and from there
//! into a fully assigned `ZkapCircuitInput<F>` / [`input::ZkapMainCircuit`]
//! (via [`input::into_circuit_input`] / [`input::build_main_circuit`]).
//!
//! No wasm dependency, no postcard wire decoding, no artifact paths in the
//! request type. Wasm-side ABI plumbing remains in the legacy
//! `zkap-witness-wasm` crate until its Commit 7 removal.

pub mod error;
pub mod input;
pub mod request;

pub use error::ZkapWitnessError;
pub use input::{ZkapMainCircuit, build_main_circuit, into_circuit_input};
pub use request::{PerJwtFields, ProofRequest, SharedFields, build_input};
