# Changelog — `zkap-service`

All notable changes to the **public API** of the `zkap-service` crate are
documented here. This crate is the semver-stable boundary between the
internal `zkap-circuit` workspace (whose `circuit` / `gadget` constraint
internals and the `ark-ar1cs` prove API churn freely) and the external
`zkap-zkp` consumer. Internal-only changes (private modules, `pub(crate)`
items, constraint logic, witness layout, on-disk artifact format) are
intentionally **not** tracked here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/);
versions follow the crate's `Cargo.toml` `version`.

## Public API drift guard

The public prove/verify entry points are pinned by `const _` signature
assertions at the bottom of `src/lib.rs`
(`_ASSERT_PROVE_SIGNATURE`, `_ASSERT_PROVE_BUNDLES_SIGNATURE`,
`_ASSERT_VERIFY_SIGNATURE`). Any change to their parameter types, return
types, or arity is a compile error, so the boundary cannot move silently.
`cargo-public-api` was not available in the workspace at the time of this
change; if it is added later, prefer a `cargo-public-api` snapshot test to
extend coverage beyond the hand-written pins.

## [Unreleased]

## [0.1.1-rc.2] - 2026-05-31 — establish the semver-stable public boundary

This is the **first semver-tracked public API** of `zkap-service`. The
goal is to stop internal churn — especially the `ark-ar1cs`
`prove_with_mode` API and the `circuit`/`gadget` constraint types — from
leaking to the downstream `zkap-zkp` consumer.

### Added

- **`prove_bundles(&ArtifactSet, Vec<WitnessBundle>, PreflightMode)
  -> Result<ProveResponse, ApplicationError>`** — the stable entry point
  for the circuit-agnostic prove half. Turns pre-synthesized witness
  bundles into a `ProveResponse` by calling the internal `ark-ar1cs`
  prover per bundle. This replaces the previous pattern of reaching into
  `ArtifactSet`'s `pk` / `prepared_arcs` fields and calling
  `ark_ar1cs::prove_with_mode` directly. The per-bundle loop is
  sequential (no `rayon` in the workspace; correctness + minimal deps over
  the throughput win — callers can shard and call per shard from their own
  pool).
- **`verify(&ArtifactSet, &Proof<BN254>, &[F])
  -> Result<bool, ApplicationError>`** — Groth16 proof verification
  wrapper. Takes the prepared verifying key from the `ArtifactSet`
  internally, so consumers verify without borrowing `pvk` directly.
  `public_inputs` is the canonical 8-element instance vector
  (`ProveResponse::public_inputs_for` decoded back to `F`); the implicit
  constant-1 wire must NOT be included.
- **`PreflightMode`** — façade-owned enum (`VerifyAfter` default,
  `StrictPreflight`) mirroring the `ark-ar1cs` preflight variants `zkap-zkp`
  needs, mapped internally to `ark_ar1cs::PreflightMode`
  (`StrictPreflight → Strict`, `VerifyAfter → VerifyAfter`). Lets callers
  select preflight behaviour **without importing `ark-ar1cs`**. Adding new
  variants is non-breaking.
- **`Proof`** — re-export of `ark_groth16::Proof` (gated `proof-types`) so
  `verify` callers can name the proof type without depending on
  `ark-groth16` directly. Parameterised by `BN254`; carries only
  `ark-bn254` curve points (no circuit/gadget types).
- **`CircuitConfigError`** — now re-exported at the crate root alongside
  `CircuitConfig` (it is the error returned by `CircuitConfig::validate`).

### Changed / Removed (BREAKING)

- **`pub use circuit::types;` (whole module) → explicit
  `pub use circuit::types::{F, BN254, CircuitConfig, CircuitConfigError};`**.
  The internal constraint-system aliases `CG`, `BNP`, `BigNat2048Params`,
  and `PoseidonHash` are no longer re-exported. Only the fundamental
  field/curve types (`F`, `BN254`) and the canonical config types cross
  the boundary. Exposing gadget/constraint types in public signatures is
  the leak this boundary forbids.
- **`ArtifactSet` fields `pk`, `vk`, `pvk`, `prepared_arcs`: `pub` →
  `pub(crate)`**. External consumers reach the prover/verifier through
  `prove` / `prove_bundles` / `verify` instead of borrowing key material
  or prepared matrices directly. `cfg` and `witness_gen_wasm` stay `pub`
  (both expose only boundary-safe types).
- **`SetupOutput::arcs` (`ArcsFile<F>`): `pub` → `pub(crate)`**. The raw
  `ark-ar1cs` `ArcsFile` is an internal format type; it is persisted by
  the crate's own `crs::persist_setup_output` and never read off the
  `SetupOutput` externally. The public `prepared_verifying_key()`,
  `public_input_count()`, and `gamma_abc_g1_len()` accessors are
  unchanged.
- **`synthesize_witnesses_streaming`: removed from the default public
  surface**. It is the low-memory witness-pipeline implementation detail
  used only by the in-workspace `zkap-witness-gen-wasm` crate. It is now
  re-exported from the crate root **only** under the internal, non-default
  `internal-streaming-witness` feature (enabled solely by
  `zkap-witness-gen-wasm`). External native consumers and `zkap-zkp` use
  `synthesize_witnesses` / `prove_bundles` instead.

### Unchanged (still public)

- `prove`, `synthesize_witnesses`, `setup`, `SetupOutput`, `SetupRng`,
  `SetupShape`, `ArtifactSet` (and its loaders), `load_circuit_config`,
  the `dto` request/response types (`ProveRequest`, `ProveCredential`,
  `ProveResponse`, `ProofComponents`, `SharedPublicInputs`,
  `WitnessBundle`, anchor/hash DTOs), `public_inputs` constants, the
  `manifest` / `jwt` modules, and the host-primitive helpers
  (`generate_anchor`, `generate_poseidon_hash`, …) keep their existing
  signatures and visibility.

### Notes

- No circuit constraint logic, witness layout, key generation, or on-disk
  artifact format changed — this is an API-surface refactor only.
- Feature gating (`host-primitives`, `manifest`, `artifact-loader`,
  `setup`, `native-witness`, `proof-types`, `native-prove`) is preserved.
  The new `internal-streaming-witness` feature is internal and
  non-default.
