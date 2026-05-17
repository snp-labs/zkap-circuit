//! Groth16 lifecycle modules: trusted setup and native Groth16 prove.
//!
//! This module is `pub(crate)` — external callers reach the SNARK
//! API through the top-level re-exports
//! (`zkap_service::{setup, prove, SetupOutput, SetupShape}`).
//! Module-qualified paths (`zkap_service::groth16::*`) are intentionally
//! not part of the public surface so the parent grouping can be
//! restructured (e.g. `snark/{groth16, plonk}`) without a follow-up
//! breaking change if another proof system is added later.

pub(crate) mod prover;
pub(crate) mod setup;
