# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **V1 byte API prove path with wasm witness-generator runtime.** `zkap_service::prove` now drives the ZKAP-specific `crates/zkap-witness-wasm` artifact (`circuit.wasm`) through a host-side `wasmi`-based runtime, postcard-encoded `ZkapInputV1` payloads, and the `ark_ar1cs_prover::prove(.arzkey, .arwtns)` interface. Witness construction is fully delegated to the wasm artifact; the host no longer pulls `circuit::ZkapCircuit` into the prove path. `RawProofRequest` now carries raw byte buffers (BE field elements, full JWT bytes, RSA modulus / signature byte strings) and a `wasm_path` alongside the existing `pk_path`.
- **`zkap-input-types` crate.** V1 wire-format types (`ZkapInputV1`, `ZkapCircuitConfigV1`, `RSA_2048_BYTES`, `fe_from_be32_canonical` / `fe_to_be32`) live in a `circuit`/`gadget`-free crate so hosts can construct V1 payloads without the full circuit compile graph.
- **`ar1cs_blake3` envelope binding.** `setup()` now writes `pk.arzkey` (proving key + ARCS/R1CS identity envelope) alongside the legacy `pk.key`/`vk.key`/`pvk.key`/`Groth16Verifier.sol`/`config.json` outputs. `circuit.wasm` build (`crates/zkap-witness-wasm/build-wasm.sh`) bakes the same hash in as `EMBEDDED_AR1CS_BLAKE3` via `build.rs`. The hash binds `.arzkey`, `.wasm`, and `.arwtns` to a single circuit identity.
- **Host-side `ar1cs_blake3` fail-fast pair check** in `ProofGenerator::generate`. Before the per-proof loop, the host instantiates the wasm runtime once, reads `embedded_ar1cs_blake3()`, and compares to `arzkey.header.ar1cs_blake3`. Mismatch returns `ApplicationError::InvalidFormat("ar1cs_blake3 mismatch: ...")` without entering the per-proof loop. The wasm-side `witness_generator` still enforces the same equality check internally as defense in depth — this host-side check improves mismatch detection and UX (catches stale caches, wrong dist paths, accidental mis-pairings) but is **not** a complete supply-chain defense against malicious wasm.
- **`wasm_to_prove` integration test** (`crates/zkap-witness-wasm/tests/wasm_to_prove.rs`). End-to-end: synthesizes a fresh test `.arzkey`, rebuilds `zkap-witness-wasm` as `wasm32-unknown-unknown` against it, drives the four ABI exports (`wasm_alloc`, `wasm_free`, `embedded_ar1cs_blake3`, `witness_generator`), checks the wasm-produced `.arwtns` is byte-identical to the native `circuit_to_arwtns` baseline, and runs `prove` + `verify_proof`. Includes a wrong-pair tamper test (wasm-side ABI 5 `Blake3Mismatch`) and a host-side mismatch test (`host_rejects_wasm_with_mismatched_ar1cs_blake3`) covering the new fail-fast path.
- `proof` feature flag for `zkap-service`: separates the heavyweight Groth16 proving stack (enabled by default) from a lightweight WASM-compatible build. Disable with `default-features = false` for browser and mobile targets where proof generation happens server-side.

### Changed

- **`groth16_proof` example temporarily disabled** (parked as `crates/service/examples/groth16_proof.rs.bak`). The example targets the legacy V0 hex/Base64 `RawProofRequest::new` shape and predates the wasm-witness runtime. Restoring a runnable end-to-end example using a checked-in small fixture `.arzkey` + `.wasm` pair is a planned follow-up. `cargo test -p zkap-witness-wasm --test wasm_to_prove --release` is the canonical V1 end-to-end exercise in the meantime.
- **`use-optimized` feature** is now a no-op alias for `proof` (the wasm-witness runtime path obsoletes the streaming Groth16 prover; the alias is kept for source-compat with downstream Cargo invocations).
- Removed unused workspace dependency `dotenvy` (unreferenced across all crates).
- Removed unused direct dependencies from `zkap-service`: `once_cell` (stdlib `OnceLock` used instead), `num`, `num-integer`, `num-bigint`, `num-traits` (RSA numeric ops handled inside `gadget`), `ark-ed-on-bn254`, and `ark-ec` (available transitively via `circuit`/`gadget`).
- Explicitly declared `[lib]` section in `zkap-service` (`staticlib`, `cdylib`, `rlib`) for clarity.

### Planned follow-ups (not in this release)

- Restore a runnable `groth16_proof` example against the V1 byte API using a checked-in small fixture `.arzkey` + `.wasm` pair.
- Cleanup of the `dist/` directory: today both the legacy V0 layout (`dist/1of1`, `dist/3of3` with `pk.key` + `Groth16Verifier.sol`) and the V1 layout (`dist/1-of-1`, `dist/3-of-3` with `circuit.arzkey` + `circuit.wasm`) coexist. A single canonical layout plus a per-bundle `manifest.json` (sha256 of `circuit.arzkey`, sha256 of `circuit.wasm`, `ar1cs_blake3`) is planned.
- Cross-project artifact compatibility test that exercises the checked-in `dist/` artifacts (currently the integration test rebuilds artifacts from scratch).
- Binding-side `prove` smoke test in `zkap-zkp` (the napi/UniFFI/wasm-bindgen byte-conversion code is currently exercised only at compile time).
- Decide whether the wasm host runtime (`wasmi`/`wasmtime` backend) should be relocated from `zkap-service` to a dedicated `ark-ar1cs-wasm-runtime` crate so that mobile bindings can drop the runtime when unused.

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
