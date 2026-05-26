# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1-rc.1] - 2026-05-27

### Breaking

- Split `ArtifactSet` loading into explicit trust-boundary APIs:
  `ArtifactSet::load_signed(manifest, dir, verifying_key)` verifies
  manifest authenticity plus artifact hashes, while
  `ArtifactSet::load_unsigned(manifest, dir)` keeps hash checks for
  caller-trusted manifests.
- Removed the public `Prover` wrapper surface. Proof generation now uses
  the top-level `zkap_service::prove(&ArtifactSet, &ProveRequest)` free
  function.
- Reworked the service public API around binding-friendly DTOs and
  top-level re-exports. Deprecated module-qualified setup/prove paths and
  old artifact loader names are no longer part of the public contract.
- Split the old ark utility crate into focused `ark-codec` and
  `ark-r1cs-helpers` crates.

### Added

- Added release and CI workflows for the develop-based release branch,
  including full release tests, release-profile builds, CRS bundle
  generation, Solidity smoke checks, and GitHub Release publishing.
- Added `witness_gen.wasm` as a required release and setup-bundle
  artifact. Release uploads include one common `witness_gen.wasm`, not
  per-shape wasm copies.
- Added signed/unsigned artifact-load timing APIs and manifest coverage
  for optional `witness_gen.wasm` entries.
- Added manifest and bundle integrity gates, including tamper tests for
  artifact hash mismatches and CI checks for the canonical bundle layout.
- Added reproducible manifest support through `SOURCE_DATE_EPOCH`.
- Added boundary and adversarial tests for circuit sizing, SHA-256
  padding, RSA verification, field/Solidity encoding parity, and
  Groth16 artifact loading.

### Changed

- Moved the proving stack onto the native `ark-ar1cs` flow and made
  `generate_setup` the canonical CLI for producing CRS bundles.
- Tightened circuit and gadget soundness checks, including `n <= 255`
  enforcement, checked index conversion, limbwise bigint equality, and
  safer R1CS comparison helpers.
- Migrated SHA-256 gadget logic to `ark-r1cs-std` 0.6 boolean operators
  and removed the legacy `UInt32Ext` helper.
- Optimized the circuit comparison path by replacing selected
  `is_less_than` usage with lower-cost less-than-or-equal helpers.
- Updated host-side audience and issuer hashing to quote-wrap claim
  strings so service hashes match the circuit byte form.
- Hardened CLI and setup output writes with atomic temp-file and rename
  flows.
- Updated public documentation to match the current artifact loader,
  setup, prove, manifest, and DTO contracts.

### Security

- Added signed manifest enforcement for production artifact loading and
  clear unsigned-loading semantics for test or externally authenticated
  bundles.
- Rejected point-at-infinity verifying-key coordinates in generated EVM
  verifier inputs.
- Zeroized transient signing-key buffers in the CLI signing-key loader.
- Converted several prover-fatal assertions into typed errors and
  removed dead or stale public surfaces.

---

## [0.1.0] - 2026-04-03

Initial open-source release.

### Added

- Zero-knowledge circuit for JWT/OAuth 2.0 verification using Groth16 (arkworks)
- Full SHA-256 computation inside the circuit for JWT header and payload
- Poseidon hash gadget with SNARK-friendly constraints
- Gadget library (`crates/gadget`): base64 decoder, bigint arithmetic, matrix operations, Merkle tree, and anchor gadgets
- R1CS utility library (`crates/ark-utils`): comparison, bit/byte conversions, and constraint helpers
- Service crate (`crates/service`) with multi-platform binding DTOs
- Groth16 integration tests with configurable K parameter (prove and verify)
- WASM binding for `generatePoseidonHash`
- CI workflow (GitHub Actions) for build and test on push and pull request
- Release workflow for publishing build artifacts
- MIT and Apache-2.0 dual license

### Changed

- Translated all Korean comments and messages to English across the entire workspace
- Resolved all clippy warnings across the workspace
- Consolidated base64 module and optimized decoder constraints
- Refactored bigint module: cleaned up code and extracted common helper functions
- Renamed matrix `constraints_v2` to `constraints` for clarity
- Removed Schnorr signature module (unused)
- Simplified build script: removed profile and binding system overhead
- Added open-source metadata (`description`, `repository`, `license`, `keywords`, `categories`) to all `Cargo.toml` files
- Removed internal documentation not suitable for public release

### Security

- CSO audit completed with 10 findings identified and resolved
- Secrets scan performed; no credentials committed to repository
- `.gitignore` updated to exclude build artifacts, keys, and environment files
