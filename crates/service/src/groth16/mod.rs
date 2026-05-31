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
// `setup` (trusted-setup / key generation) pulls `crate::crs` + `rand_chacha`
// + `ark-poly`, all of which are `setup`-feature-gated. Gate the module
// declaration to match, so `native-prove` (prove-only consumers that load a
// pre-generated bundle and never run setup, e.g. the zkap-zkp SDK) compiles
// without enabling `setup`. The crate-root re-export and `crate::crs` are
// already `#[cfg(feature = "setup")]`-gated, so this stays consistent.
#[cfg(feature = "setup")]
pub(crate) mod setup;
