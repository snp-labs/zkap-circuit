# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking — 2026-05 ark-ar1cs boundary migration

The proving stack moved off the historical wasm-runtime path and onto
a native `ark-ar1cs` flow. Every public type and entry point that
referenced the wasm path is gone; downstream callers must rewire
once.

- **CRS bundle layout (7 files).** `setup()` and the `generate_setup`
  CLI now write a single canonical bundle: `circuit.ar1cs`, `pk.bin`,
  `vk.bin`, `pvk.bin`, `Groth16Verifier.sol`, `config.json`,
  `manifest.json`. Older filenames and the wasm artifact that
  pre-dated the migration are no longer produced or consumed.
- **`ProofRequest` is the new request type.** Holds only
  `shared: SharedFields` and `per_jwt: Vec<PerJwtFields>` — every
  artifact-path field is gone. Lives in
  `service::witness::request`.
- **Native ar1cs prove path.** The proving entry point is
  `service::prover::Prover` (`Prover::from_artifact(set)` +
  `Prover::prove(&request, rng)`). Internally chains
  `witness::build_input → witness::into_circuit_input →
  ZkapCircuit::from_input → ark_ar1cs::synthesize_full_assignment →
  ark_ar1cs::prove(&pk, &arcs, &full_assignment, rng)`. The
  non-canonical `prove_from_unverified_paths(bundle_dir, &req, rng)`
  shortcut exists for tests/dev tools and is documented in-line as
  bypassing the manifest hash gate.
- **`ArtifactSet::load(manifest, dir)` is the single trust gate.**
  The loader checks `arcs.body_blake3() == manifest.ar1cs_blake3`
  plus `sha256` of every artifact (`circuit.ar1cs`, `pk.bin`,
  `vk.bin`, `pvk.bin`, `config.json`, optional `Groth16Verifier.sol`).
  Mismatch returns `ArtifactError::HashMismatch { field, expected,
  got }`. `Prover::prove` performs no manifest lookup, no
  `body_blake3` recompute, and no sha256 re-check. Tamper tests in
  `crates/service/tests/artifact_set_load.rs` enforce the contract.
- **Verify wrapper retired.** The previous in-crate verify helper
  and its opaque verifying-context handle are gone. Callers borrow
  the `PreparedVerifyingKey` from `Prover::prepared_verifying_key()`
  / `SetupOutput::prepared_verifying_key()` and call
  `ark_groth16::Groth16::<Bn254>::verify_proof(pvk, &proof,
  &inputs)` directly.
- **Cargo features purged.** Every wasm-runtime / streaming-prover
  feature flag is removed. The default `proof` feature now pulls
  only `ark-ar1cs` (root crate), `ark-groth16`, and the in-tree
  wire/codec helpers.
- **Legacy CLI binary removed.** Pre-migration setup binaries were
  retired; `generate_setup` is the canonical superset that writes
  the 7-file bundle in one shot.
- **Wasm witness substrate removed.** The wasm witness-generator
  crate, its ABI glue, and the host-side wasm runtime are no longer
  part of the workspace. Production callers depend on the native
  prove path.

### Added

- **Manifest hash check coverage.** `ArtifactSet::load` enumerates
  every artifact entry and reports the failing slot via
  `ArtifactError::HashMismatch::field` (e.g. `"ar1cs_blake3"`,
  `"artifacts.pk.sha256"`, `"artifacts.evm_verifier.sha256"`). Pinned
  by 9 active tamper tests in
  `crates/service/tests/artifact_set_load.rs`.
- **`SOURCE_DATE_EPOCH` reproducible-builds support.** When set,
  `manifest.build.built_at` (RFC3339 UTC) is derived from that
  unix-seconds value instead of wallclock. Combined with `--rng-seed
  --allow-test-only` + pinned `--build-commit`, two runs against the
  same config produce a byte-equal `manifest.json` (golden test:
  `crates/cli/tests/manifest_golden.rs`).
- **`prove_from_unverified_paths`** — non-canonical shortcut that
  loads `pk.bin`, `vk.bin`, `pvk.bin`, `circuit.ar1cs`, and
  `config.json` from a directory via `ArtifactSet::load_unverified`
  and forwards to `Prover::from_artifact` + `Prover::prove`. The
  rustdoc explicitly warns that production callers MUST use
  `ArtifactSet::load(manifest, dir)`.
- **`scripts/check-removed-api.sh`** and
  **`scripts/check-bundle-layout.sh`** are wired into CI as required
  gates on every PR. The bundle-layout gate runs against
  `dist/1-of-1` and `dist/3-of-3`.

### Changed

- **Workspace pin** for `ark-ar1cs` bumped to the rev that fuses the
  previous sub-crates into a single `ark-ar1cs` root crate and
  exposes `prove(pk, arcs, full_assignment, rng)` +
  `synthesize_full_assignment` as the canonical native API.

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
