# Architecture

## High-Level Overview

zkap-circuit is a Rust library for generating Groth16 zero-knowledge proofs that verify JWT/OAuth tokens without revealing their contents. The circuit proves a valid JWT was issued by a known provider, enforces RSA-2048 signatures, and binds payloads cryptographically—all without exposing the token itself. It uses arkworks primitives on the BN254 curve and supports threshold schemes via Vandermonde-based anchor generation.

## Crate Dependency Graph

```
                       zkap-service ─────────────→ circuit ──→ gadget ──→ ark-utils
                            │                          ↑          ↑
                            ├──→ ark-ar1cs              │          └─→ arkworks
                            │       (root crate;        │
                            │        prove,             │
                            │        synthesize_full_   │
                            │        assignment,        │
                            │        format::ArcsFile)  │
                            └──→ ark-groth16            │
                                                        │
                            cli ──→ zkap-service ───────┘
```

- **ark-utils**: Base layer (R1CS helpers, field arithmetic, EVM codegen, V1 wire types in `ark_utils::wire`).
- **gadget**: Circuit gadgets (feature-gated): SHA256, Poseidon, RSA, base64, Merkle tree, anchor, matrix.
- **circuit**: Main `ZkapCircuit`, `CircuitConfig`, witness types, R1CS constraints. `ZkapCircuit::from_input` is the native constructor used by the `service::groth16::prover` flow.
- **zkap-service**: Proof generation orchestration, public API. Owns the wire-decoding boundary (`service::groth16::prover::adapter`), the per-credential stage builders (`service::groth16::prover::circuit_input`), the manifest-validated artifact loader (`service::artifact::ArtifactSet::load`), the trusted setup (`service::setup`), and the native ar1cs prove free function (`service::prove`).
- **cli**: Binary utilities — `generate_setup` (writes the 7-file CRS bundle) and `generate_hash` (standalone Poseidon hashing).
- **ark-ar1cs**: Circuit-agnostic byte interface. Exposes `prove(pk, arcs, full_assignment, rng)`, `synthesize_full_assignment`, and the `format::ArcsFile` envelope. Imported as a single git+rev workspace dep.

## Crate Responsibilities

**ark-utils** provides low-level R1CS constraint helpers (array selection, field arithmetic, comparison), packing/decomposition utilities for witness construction, EVM bytecode codegen for public input verification, and the V1 wire types (`ZkapInputV1`, `CircuitConfig`) that the host populates without pulling in the circuit graph.

**gadget** implements feature-gated ZK circuit gadgets: SHA256 hashing, Poseidon hashing with parameter caching, RSA-2048 signature verification, base64 decoding with table lookup, Merkle tree traversal using Poseidon, Vandermonde matrix operations for the anchor scheme, and bigint arithmetic for RSA. All gadgets are constraint-based (use `Var` types) and integrate with arkworks.

**circuit** defines the main ZkapCircuit struct, CircuitConfig (runtime parameters like n/k/max_jwt_b64_len/tree_height), and witness types (`JwtWitness`, `AnchorWitness`, `MerkleWitness`, `AudienceWitness`). It orchestrates all gadgets into a single R1CS constraint system that proves JWT validity, threshold membership, issuer membership, and audience membership without exposing the JWT itself. `ZkapCircuit::from_input(ZkapCircuitInput<F>)` is the native constructor consumed by the service-side prover.

**zkap-service** is the public API layer that orchestrates proof generation end-to-end. It splits cleanly into:

- `service::groth16::prover::adapter` — wire-decode boundary. `prove_request_to_decoded(&ProveRequest, &CircuitConfig)` validates the config, checks shapes, and decodes hex/decimal/base64 wire strings into the lean F-based `(SharedDecoded, Vec<CredentialDecoded>)` tuple. No cryptographic derivation here.
- `service::groth16::prover::circuit_input` — per-credential stage builders (`build_anchor_stage`, `build_jwt_stage`, `build_audience_stage`, `build_merkle_witness`, `compute_public_inputs`). Each builder is `pub(crate)` and turns decoded inputs into one slice of the eventual `ZkapCircuitInput<F>`.
- `service::artifact` — manifest-validated bundle loader. `ArtifactSet::load(manifest, dir)` is the **single trust gate**: it checks `arcs.body_blake3() == manifest.ar1cs_blake3` and the sha256 of every artifact (`circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`, `config.json`, optional `Groth16Verifier.sol`). `ArtifactSet::load_unverified` is the non-canonical, caller-trusted shortcut.
- `service::groth16::prover::prove` — the free function `prove(&ArtifactSet, &ProveRequest) -> Result<ProveResponse, ApplicationError>`. Calls the adapter, runs pre-batch `derive_x_from_secret` + `derive_selector_from_x_list_and_anchor`, then per credential composes the stage outputs into a `ZkapCircuitInput<F>` and feeds it to `ZkapCircuit::from_input → ark_ar1cs::synthesize_full_assignment → ark_ar1cs::prove(&pk, &arcs, &full_assignment, OsRng)`. Performs no manifest lookup, no `body_blake3` recompute, and no sha256 re-check — trust gating is the loader's job.
- `service::groth16::setup` — Groth16 trusted setup; persists the 7-file bundle (`crate::crs`).

The crate is split into two build profiles via the `proof` Cargo feature (enabled by default):
- **With `proof`** (default): full Groth16 proving stack (`ark-groth16`, `ark-ar1cs`, `ark-serialize`, `memmap2`, hash crates). Use for native server-side proof generation.
- **Without `proof`** (`default-features = false`): lightweight, WASM-compatible build. Only witness construction, DTOs, and data types are included. Proof generation functions are unavailable. Use for browser or mobile targets where proving happens server-side.

In-process verification: callers borrow the `PreparedVerifyingKey` from `Prover::prepared_verifying_key()` (or `SetupOutput::prepared_verifying_key()`) and call `ark_groth16::Groth16::<Bn254>::verify_proof(pvk, &proof, &inputs)` directly. The previous in-crate `verify` wrapper was retired in the 2026-05 ark-ar1cs boundary migration.

**cli** provides two binary utilities: `generate_setup` for trusted-setup CRS bundle generation (writes the 7-file layout) and `generate_hash` for standalone Poseidon hash computation.

## Data Flow

A proof is generated end-to-end as follows (post-migration native ar1cs prove flow):

1. **`ProveRequest`** (wire-format strings): The host (binding crates in `zkap-zkp`, the `cli` binary, etc.) supplies a `ProveRequest` populated with hex/decimal-encoded field elements, full JWT compact-serialization strings, and base64-encoded RSA-2048 modulus values, alongside a `Vec<ProveCredential>` (one per JWT). The request carries **no** artifact paths.
2. **Trust gate** (`ArtifactSet::load(manifest, dir)`): Reads the seven on-disk bundle files, parses `circuit.ar1cs` via `ark_ar1cs::format::ArcsFile::read`, and verifies every hash claim in `manifest.json`:
   - `arcs.body_blake3() == manifest.ar1cs_blake3`
   - sha256 of each binary artifact == `manifest.artifacts.<slot>.sha256`
   - Mismatch returns `ArtifactError::HashMismatch { field, expected, got }` and the prover never sees the bytes.
3. **`Prover::from_artifact(set)`**: Takes ownership of the `(pk, vk, pvk, arcs, cfg)` bundle. No further validation runs inside the prover.
4. **`service::prove(&set, &request)`** — pre-batch and per-credential:
   1. `groth16::prover::adapter::prove_request_to_decoded(&req, &cfg)` → `(SharedDecoded, Vec<CredentialDecoded>)` (validates the config, checks shapes, decodes wire strings).
   2. Pre-batch: parse each credential's JWT for sub/iss/aud → `derive_x_from_secret` → `x_list`; `derive_selector_from_x_list_and_anchor` → `selector` + `one_positions`.
   3. Per credential: `circuit_input::{build_anchor_stage, build_jwt_stage, build_audience_stage, build_merkle_witness, compute_public_inputs}` assemble a fresh `ZkapCircuitInput<F>`.
   4. `ZkapCircuit::from_input(circuit_input)` wraps it as a `ConstraintSynthesizer`.
   5. `ark_ar1cs::synthesize_full_assignment::<_, F>(circuit)` returns the `[F::ONE, instance..., witness...]` vector.
   6. `ark_ar1cs::prove::<BN254, _>(&pk, &arcs, &full_assignment, OsRng)` produces the Groth16 proof. The function runs an internal R1CS preflight (`Az ⊙ Bz == Cz`) before calling `Groth16::create_proof_with_reduction_and_matrices`.
5. **Output**: Solidity-compatible proof component strings and split public-input lists per JWT (`ZkapProofResult` → `ProofComponents`). Verifier checks against public inputs without the JWT, either on-chain (`Groth16Verifier.sol`) or via `Groth16::<BN254>::verify_proof(pvk, &proof, &inputs)` in process.

### Artifact identity binding

| Artifact         | Producer                                                   | Consumer                            | Identity claim                                        |
|------------------|------------------------------------------------------------|-------------------------------------|-------------------------------------------------------|
| `circuit.ar1cs`  | `setup()` → `ConstraintMatrices::from_cs` → `ArcsFile::from_matrices` | `ArtifactSet::load` (parses + checks `body_blake3`) | `manifest.ar1cs_blake3` (32-byte blake3 of canonical body) |
| `pk.bin`         | `setup()` → `ProvingKey::serialize_uncompressed`            | `ArtifactSet::load` (sha256-checked) | `manifest.artifacts.pk.sha256`                         |
| `vk.bin`         | `setup()` → `VerifyingKey::serialize_uncompressed`          | `ArtifactSet::load` (sha256-checked) | `manifest.artifacts.vk.sha256`                         |
| `pvk.bin`        | `setup()` → `PreparedVerifyingKey::serialize_uncompressed`  | `ArtifactSet::load` (sha256-checked) | `manifest.artifacts.pvk.sha256`                        |
| `config.json`    | `setup()` (mirrors the `CircuitConfig` argument)            | `ArtifactSet::load` (sha256-checked, then parsed) | `manifest.artifacts.circuit_config.sha256`              |
| `Groth16Verifier.sol` | `setup()` → `zkap_evm_verifier::SolidityContractGenerator` (optional) | `ArtifactSet::load` (sha256-checked when `Some`) | `manifest.artifacts.evm_verifier.sha256`                |
| `manifest.json`  | `cli::generate_setup` (CLI-owned)                           | The trust input itself              | (signs every other artifact above)                     |

`manifest.json` is the deployment trust boundary: any byte change in any other artifact, with the manifest unchanged, fails `ArtifactSet::load`. Conversely, a manifest claim that disagrees with the on-disk byte is rejected with the failing slot named in the error.

## Key Design Decisions

**Runtime CircuitConfig** (not compile-time generics): The circuit accepts CircuitConfig as a runtime parameter (n, k, tree_height, max_jwt_b64_len, etc.), not as compile-time type parameters. This allows a single binary to support multiple circuit configurations without recompilation—critical for platform bindings and server deployments where config is loaded from JSON.

**Poseidon Hash for Anchor Scheme**: The threshold anchor scheme uses Poseidon hashing with a Vandermonde matrix approach rather than traditional threshold cryptography. This is efficient in-circuit (Poseidon is field-arithmetic-optimized) and allows non-interactive threshold proofs. Parameters are cached globally via OnceLock to avoid recomputation.

**Manifest as the single trust gate**: All hash validation lives in `ArtifactSet::load(manifest, dir)`. `Prover::prove` re-validates nothing; this means every prove batch implicitly trusts whatever the loader returned, and any tamper test against the loader is the only place hash gating needs verification. The non-canonical `ArtifactSet::load_unverified` and `prove_from_unverified_paths` helpers exist for tests/dev tools and are documented in-line as bypassing the gate.

**Service Module Layout**: Service modules are split by responsibility. `groth16/prover/adapter.rs` decodes the wire-format `ProveRequest` (no path fields, no wasm runtime, no postcard). `groth16/prover/circuit_input.rs` hosts the per-credential stage builders that turn decoded inputs into `ZkapCircuitInput<F>`. `groth16/prover/prove.rs` orchestrates the pre-batch derive + per-credential streaming through ark-ar1cs. `artifact/` is the manifest-validated loader. `groth16/setup/` keeps only the trusted-setup `setup` function and the persisted CRS bundle helpers.

**OnceLock Cached Poseidon Parameters**: Poseidon configuration is expensive to construct. It is computed once lazily via `OnceLock::get_or_init` and shared across all modules (`service::poseidon_params()`). This eliminates redundant computation and is thread-safe.

## Service Module Map

```
service/src/
├── groth16/         Groth16 lifecycle parent (setup + prove)
│   ├── mod.rs           Module entry / re-exports
│   ├── setup/           Trusted setup
│   │   └── mod.rs           setup() + SetupOutput + SetupShape
│   └── prover/          Native ark-ar1cs prove pipeline
│       ├── mod.rs           Module entry / re-exports + RSA_2048_BYTES
│       ├── adapter.rs       prove_request_to_decoded (wire → SharedDecoded/CredentialDecoded)
│       ├── circuit_input.rs Per-credential stage builders (anchor / jwt / audience / merkle / public-inputs)
│       └── prove.rs         prove() free function — orchestrates pre-batch + per-credential streaming
├── artifact/        Manifest-validated bundle loader (single trust gate)
│   ├── mod.rs           Module entry / re-exports
│   ├── error.rs         ArtifactError (incl. HashMismatch { field, expected, got })
│   └── set.rs           ArtifactSet::load + ArtifactSet::load_unverified
├── anchor/          Poseidon anchor generation for threshold schemes
├── hash/            Standalone Poseidon hash utilities
├── jwt/             JWT parsing
├── dto/             Platform-agnostic DTOs (ProofComponents, ZkapProofResult, ...)
├── manifest.rs      Manifest schema + ManifestBuilder
├── crs.rs           CRS persistence — writes the 7-file bundle
├── error.rs         ApplicationError enum
└── lib.rs           Public API (setup, prove, ArtifactSet,
                                  ProveRequest, ProveResponse, ...)
```
