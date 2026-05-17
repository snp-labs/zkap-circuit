//! zkap-service — high-level API for ZKAP proof generation and verification.
//!
//! # Public API
//!
//! All entry points are always-on after the 2026-05 binding-friendly
//! refactor (the `proof` and `dev-unverified-artifacts` Cargo features
//! were removed; heavy ark-* deps are now unconditional).
//!
//! - [`generate_poseidon_hash`], [`generate_audience_hashes`],
//!   [`generate_issuer_key_hash`] — Poseidon hashing (Request/Response DTOs
//!   live in the `dto` re-exports below)
//! - [`generate_anchor`] — threshold anchor generation (Request/Response DTOs
//!   re-exported below; see [`AnchorSecret`])
//! - [`load_circuit_config`] — load [`CircuitConfig`] from JSON
//! - [`setup`] — trusted setup: generates proving/verifying keys and writes them to disk
//! - [`prove`] — native Groth16 prover free function (takes
//!   `&ArtifactSet` + [`ProveRequest`]; mirrors the `generate_anchor`
//!   shape).
//! - [`jwt`] — JWT payload claim parsing ([`jwt::parser::parse_claim_from_str`])
//!
//! Proof verification is intentionally **not** wrapped by this crate
//! after Commit 5 of the 2026-05 ark-ar1cs boundary migration: callers
//! borrow the prepared verifying key from
//! [`SetupOutput::prepared_verifying_key`] (or from an
//! [`ArtifactSet`]) and feed it directly to
//! `ark_groth16::Groth16::verify_proof`.
//!
//! Solidity on-chain verifier codegen lives in the sibling crate
//! [`zkap-evm-verifier`](../zkap_evm_verifier/index.html); call
//! `<VerifyingKey<E> as zkap_evm_verifier::SolidityContractGenerator>::generate_solidity`
//! directly. The bundled `Groth16Verifier.sol` produced by [`setup`] uses it
//! internally.
//! - Request DTOs: [`ProveRequest`], [`ProveCredential`]
//! - Response DTOs: [`ProveResponse`], [`ProofComponents`], [`SharedPublicInputs`]
//! - Setup output: [`SetupOutput`]
//!
//! ## Prove flow (visual reference)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ EXTERNAL CALLER                                                  │
//! │   ProveRequest {                                                 │
//! │     random, h_sign_user_op, anchor[*], merkle_root,              │
//! │     credentials: [ProveCredential; k]                            │
//! │   }                                                              │
//! └──────────────────────────────┬───────────────────────────────────┘
//!                                │ prove(&set, &req)
//!                                ▼
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ adapter::prove_request_to_decoded                                │
//! │   1. cfg.validate()                                              │
//! │   2. shape validation (lengths + leaf-idx bound)                 │
//! │   3. decode shared field strings (hex/decimal → F)               │
//! │   4. per-credential: base64-decode RSA/sig, merkle path → F      │
//! │   → (SharedDecoded, Vec<CredentialDecoded>)                      │
//! └──────────────────────────────┬───────────────────────────────────┘
//!                                │
//!                                ▼
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ prove() body                                                     │
//! │   pre-batch:                                                     │
//! │     parse JWTs → derive_x_from_secret → x_list                   │
//! │     derive_selector_from_x_list_and_anchor → selector            │
//! │     one_positions[i] = i-th 1-position of selector               │
//! │   per credential:                                                │
//! │     circuit_input::build_anchor_stage                            │
//! │     circuit_input::build_jwt_stage                               │
//! │     circuit_input::build_audience_stage                          │
//! │     circuit_input::build_merkle_witness                          │
//! │     circuit_input::compute_public_inputs                         │
//! │     ZkapCircuit::from_input → synthesize_full_assignment         │
//! │     → ark_ar1cs::prove                                           │
//! └──────────────────────────────┬───────────────────────────────────┘
//!                                │
//!                                ▼
//! ┌──────────────────────────────────────────────────────────────────┐
//! │ ProveResponse { proofs, shared_public_inputs,                    │
//! │                 jwt_exp[*], verification_rhs[*] }                │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! `ArtifactSet::load(manifest, dir)` is the trust boundary — manifest
//! hash validation happens before [`prove`] runs, and [`prove`]
//! does not re-verify any hash.
//!
//! ### Drift safeguard
//!
//! Compile-checked guard against accidental signature drift on the
//! canonical `prove` entry point. Updates to this signature must update
//! the diagram above (and the flow doc in
//! `crates/service/src/groth16/prover/mod.rs`).
//!
//! ```ignore
//! use zkap_service::{ArtifactSet, ProveRequest, ProveResponse, prove};
//! use zkap_service::error::ApplicationError;
//! let _: fn(&ArtifactSet, &ProveRequest) -> Result<ProveResponse, ApplicationError> = prove;
//! ```

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

pub(crate) mod anchor;
pub(crate) mod dto;
pub mod error;
pub(crate) mod hash;

// Manifest schema — proof-feature-independent. Hosts that consume the
// manifest without pulling ark-groth16 (lightweight bindings, manifest
// inspectors, dev tools) can depend on the module cheaply.
pub mod manifest;

pub mod artifact;
pub(crate) mod crs;
pub mod jwt;

// Groth16 lifecycle parent — `pub(crate)` so module-qualified paths
// `zkap_service::setup::*` / `zkap_service::groth16::*` are intentionally
// gone (BREAKING change). External callers must use the top-level
// re-exports below (`zkap_service::{setup, prove, SetupOutput, ...}`).
// Hosts the wire-decoder (adapter), per-credential stage builders
// (circuit_input), and the ar1cs orchestrator (prove). Boundary callers
// reach the SNARK layer through `ProveRequest` and never see raw
// F-decoded bundles.
pub(crate) mod groth16;

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
pub use anchor::poseidon::generate_anchor;
pub use circuit::types::CircuitConfig;
pub use dto::{
    AnchorSecret, AudienceHashRequest, AudienceHashResponse, GenerateAnchorRequest,
    GenerateAnchorResponse, HashRequest, HashResponse, IssuerKeyHashRequest, IssuerKeyHashResponse,
};
pub use hash::{generate_audience_hashes, generate_issuer_key_hash, generate_poseidon_hash};

// Public API (proof + setup surface — always available after the 2026-05 refactor)
pub use artifact::{ArtifactError, ArtifactSet};
pub use dto::{ProofComponents, ProveCredential, ProveRequest, ProveResponse, SharedPublicInputs};
pub use groth16::prover::prove;
pub use groth16::setup::{SetupOutput, SetupShape, setup};
