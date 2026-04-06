# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `proof` feature flag for `zkap-service`: separates the heavyweight Groth16 proving stack (enabled by default) from a lightweight WASM-compatible build. Disable with `default-features = false` for browser and mobile targets where proof generation happens server-side.

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
