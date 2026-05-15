//! zkap-service — high-level API for ZKAP proof generation and verification.
//!
//! # Public API
//!
//! **Always available:**
//! - [`generate_poseidon_hash`], [`generate_audience_hashes`],
//!   [`generate_issuer_key_hash`] — Poseidon hashing (Request/Response DTOs
//!   live in the [`dto`] re-exports below)
//! - [`generate_anchor`] — threshold anchor generation (Request/Response DTOs
//!   re-exported below; see [`AnchorSecret`])
//! - [`load_circuit_config`] — load [`CircuitConfig`] from JSON
//!
//! **`proof` feature (default):**
//! - [`setup`] — trusted setup: generates proving/verifying keys and writes them to disk
//! - [`Prover`] / [`prove_from_unverified_paths`] — native Groth16 prover
//!   (takes [`ProofRequest`])
//! - [`jwt`] — JWT payload claim parsing ([`jwt::parser::parse_claim_from_str`])
//!
//! Proof verification is intentionally **not** wrapped by this crate
//! after Commit 5 of the 2026-05 ark-ar1cs boundary migration: callers
//! borrow the prepared verifying key from
//! [`SetupOutput::prepared_verifying_key`] (or from a `Prover` /
//! [`ArtifactSet`]) and feed it directly to
//! `ark_groth16::Groth16::verify_proof`.
//!
//! Solidity on-chain verifier codegen lives in the sibling crate
//! [`zkap-evm-verifier`](../zkap_evm_verifier/index.html); call
//! `<VerifyingKey<E> as zkap_evm_verifier::SolidityContractGenerator>::generate_solidity`
//! directly. The bundled `Groth16Verifier.sol` produced by [`setup`] uses it
//! internally.
//! - DTOs: [`ProofComponents`], [`SharedPublicInputs`], [`ProveResponse`]
//! - Keys: [`SetupOutput`], [`SharedFields`], [`PerJwtFields`]

// Crate-internal `missing_docs` warning, not a `#[deny]`. Phase 7 / H5
// staged path: clears the zkap-service baseline (39 service warnings +
// 9 ark-utils warnings that surface only under the `field-serde`
// feature combination zkap-service activates — see
// `00-workspace-hygiene.md` §6 v3 H5 baseline drift note) and locks in
// the floor without depending on a workspace-wide `[lints.rust]
// missing_docs = "warn"` (which would still block on gadget's 213
// outstanding warnings — `00-workspace-hygiene.md` §H5 baseline).
// The workspace-wide flip happens once gadget hits zero at this gate.
#![warn(missing_docs)]

pub(crate) mod anchor_host;
pub(crate) mod dto;
pub mod error;
pub(crate) mod hash;

// Manifest schema — proof-feature-independent. Hosts that consume the
// manifest without pulling ark-groth16 (lightweight bindings, manifest
// inspectors, dev tools) can depend on the module cheaply.
pub mod manifest;

#[cfg(feature = "proof")]
pub mod artifact;
#[cfg(feature = "proof")]
pub(crate) mod crs;
#[cfg(feature = "proof")]
pub mod jwt;
#[cfg(feature = "proof")]
pub mod proof;

// Native witness-shaping path — pure, wasm-free.
#[cfg(feature = "proof")]
pub mod witness;

// Native ark-ar1cs prover — canonical post-migration entry point.
#[cfg(feature = "proof")]
pub mod prover;

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use circuit::types::F;
use std::sync::OnceLock;

// Field-codec re-export — single source of truth lives in
// `ark-utils::field_codec` (PR4 / Step 7 of the DTO consolidation plan).
pub(crate) use ark_utils::codec::field::field_to_hex;

/// Cached Poseidon parameters — constructed once, shared across all modules.
pub(crate) fn poseidon_params() -> &'static PoseidonConfig<F> {
    static PARAMS: OnceLock<PoseidonConfig<F>> = OnceLock::new();
    PARAMS.get_or_init(gadget::hashes::poseidon::get_poseidon_params::<F>)
}

/// Load a [`CircuitConfig`] from a JSON config file.
///
/// Accepts both `config.json` produced by [`setup`] and stand-alone config files
/// in the same [`CircuitConfig`] JSON format.
pub fn load_circuit_config(
    path: &std::path::Path,
) -> Result<CircuitConfig, error::ApplicationError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        error::ApplicationError::InvalidFormat(format!("Failed to read config: {}", e))
    })?;
    let config: circuit::types::CircuitConfig = serde_json::from_str(&content).map_err(|e| {
        error::ApplicationError::InvalidFormat(format!("Failed to parse config: {}", e))
    })?;
    config
        .validate()
        .map_err(|e| error::ApplicationError::InvalidFormat(e.to_string()))?;
    Ok(config)
}

pub use circuit::types;

// Public API (always available)
pub use anchor_host::poseidon::generate_anchor;
pub use circuit::types::CircuitConfig;
pub use dto::{
    AnchorSecret, AudienceHashRequest, AudienceHashResponse, GenerateAnchorRequest,
    GenerateAnchorResponse, HashRequest, HashResponse, IssuerKeyHashRequest, IssuerKeyHashResponse,
};
pub use hash::{generate_audience_hashes, generate_issuer_key_hash, generate_poseidon_hash};

// Public API (proof feature only)
#[cfg(feature = "proof")]
pub use artifact::{ArtifactError, ArtifactSet};
#[cfg(feature = "proof")]
pub use dto::{ProofComponents, ProveResponse, SharedPublicInputs};
#[cfg(feature = "proof")]
pub use proof::{SetupOutput, SetupShape, setup};
#[cfg(feature = "proof")]
pub use prover::{Prover, prove_from_unverified_paths};
#[cfg(feature = "proof")]
pub use witness::{PerJwtFields, ProofRequest, SharedFields};
