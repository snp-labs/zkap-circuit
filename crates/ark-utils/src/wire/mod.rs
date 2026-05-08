//! V1 wire-format types for the ZKAP main circuit, absorbed from the
//! former `zkap-input-types` crate (L4 follow-up plan
//! `.omc/plans/2026-05-07-l4-zkap-input-types-absorption.md`, PR1).
//!
//! `ark-utils` itself is `circuit`/`gadget`-free at the time of writing
//! — the `wire` module is gated behind the `wire` feature (default-on);
//! disabling `wire` does not pull `ark-serialize` either.
//!
//! Single source of truth for the semantic [`ZkapInputV1`] payload that
//! the host hands to the wasm witness-generator and that the wasm side
//! decodes via postcard.
//!
//! These types live in `ark_utils::wire` (this module). `ark-utils`
//! itself is `circuit`/`gadget`-free, so any host-side caller depending
//! on `ark-utils` (with `default-features = false, features = ["wire"]`
//! if R1CS is undesired) can construct a V1 payload without pulling the
//! circuit / gadget compile graph.
//!
//! The full encoding contract — field order, BE/LE rules, length
//! prefixes, the `WitnessGenerator::CIRCUIT_ID` lockstep requirement —
//! lives in `zkap-witness-wasm::input` (the conversion-side companion).
//! Bumping anything here is a wire-format break.

pub mod circuit_config;
pub mod v1;

pub use circuit_config::{CircuitConfig, CircuitConfigError};
pub use v1::{RSA_2048_BYTES, ZkapInputV1};
