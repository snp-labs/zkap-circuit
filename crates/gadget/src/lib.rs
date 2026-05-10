//! zkap-gadget — low-level cryptographic primitives and R1CS gadgets for the ZKAP circuit.
//!
//! Provides feature-gated modules for all building blocks used by `zkap-circuit`:
//! Poseidon hashing (`hashes-poseidon`), the threshold anchor scheme (`anchor`),
//! Base64 decoding gadgets (`base64`), RSA-2048 signature verification (`rsa`),
//! Merkle tree helpers (`merkletree`), and Vandermonde matrix operations (`matrix`).
//! Most application code should interact with this crate through `zkap-circuit` or
//! `zkap-service` rather than directly. Enable modules via `[features = "..."]`
//! from your workspace member's `Cargo.toml`.

// Crate-internal `missing_docs` warning, matching the pattern locked in
// by Phase 6 H5-staged-1 (ark-utils), H5-staged-2 (circuit), and Phase 7
// H5-staged-3 (zkap-service). CI's
// `cargo clippy --workspace --all-targets -- -D warnings` promotes this
// to a deny so a regression is caught at PR-time. The workspace-wide
// `[workspace.lints.rust] missing_docs = "warn"` flip (H5-finalize)
// becomes safe once every lib crate hits this gate at zero warnings —
// gadget was the last one (213 sites at the start of Phase 8).
#![warn(missing_docs)]
// rustdoc lock floor — Phase 9 P9-gadget-rustdoc-audit. Mirrors the pattern
// locked in by Phase 8 P8-arkutils-doc-link-audit (ark-utils crate root):
// any new `///`/`//!` doc string with a broken intra-doc link or invalid HTML
// tag fails the `Rustdoc (gadget)` CI job. The H5-staged-4 cycle (Phase 8
// `c630dd78`) added 213 fresh doc strings without `cargo doc` validation;
// this PR retroactively closes that gap (Phase 8 critic MINOR #3).
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::invalid_html_tags)]

extern crate alloc;

// Always available
pub mod constants;

// Feature-gated modules
#[cfg(feature = "anchor")]
pub mod anchor;
#[cfg(feature = "anchor")]
pub mod matrix;

#[cfg(feature = "hashes-poseidon")]
pub mod hashes;

#[cfg(feature = "merkletree")]
pub mod merkletree;

#[cfg(feature = "base64")]
pub mod base64;

#[cfg(feature = "rsa")]
pub mod bigint;
#[cfg(feature = "rsa")]
pub mod signature;
