# Architecture

## High-Level Overview

zkap-circuit is a Rust library for generating Groth16 zero-knowledge proofs that verify JWT/OAuth tokens without revealing their contents. The circuit proves a valid JWT was issued by a known provider, enforces RSA-2048 signatures, and binds payloads cryptographically—all without exposing the token itself. It uses arkworks primitives on the BN254 curve and supports threshold schemes via Vandermonde-based anchor generation.

## Crate Dependency Graph

```
                       zkap-service ─────────────→ circuit ──→ gadget ──→ ark-utils
                            │                          ↑          ↑
                            │                          │          └─→ arkworks
                            ├──→ zkap-input-types      │
                            │       (V1 wire types)    │
                            ├──→ ark-ar1cs-format      │
                            ├──→ ark-ar1cs-zkey        │
                            ├──→ ark-ar1cs-wtns        │
                            └──→ ark-ar1cs-prover      │
                                                       │
        zkap-witness-wasm ─────────────────────────────┤
        (wasm32 witness-generator binary)              │
            │                                          │
            ├──→ ark-ar1cs-wasm-witness                │
            ├──→ ark-ar1cs-format                      │
            ├──→ zkap-input-types                      │
            └──→ circuit + gadget ──────────────────── ┘

             cli ──→ zkap-service
```

- **ark-utils**: Base layer (R1CS helpers, field arithmetic, EVM codegen)
- **gadget**: Circuit gadgets (feature-gated): SHA256, Poseidon, RSA, base64, Merkle tree, anchor, matrix
- **circuit**: Main ZkapCircuit, CircuitConfig, witness types, R1CS constraints
- **zkap-input-types**: V1 wire-format types (`ZkapInputV1`, `ZkapCircuitConfigV1`, canonical 32-byte BE field codec). Carries no `circuit`/`gadget` dependency so hosts can construct V1 payloads without the full circuit compile graph.
- **zkap-witness-wasm**: ZKAP-specific witness-generator artifact (compiled to `wasm32-unknown-unknown`). Consumes a postcard-encoded `ZkapInputV1`, reconstructs `ZkapCircuit::from_input` on the wasm side, and emits an `.arwtns` blob. Pairs with a `.arzkey` via the embedded `ar1cs_blake3`.
- **zkap-service**: Proof generation orchestration, public API. Loads the host-side `.arzkey`, reads the witness-generator wasm bytes, runs a host-side `ar1cs_blake3` fail-fast pair check, then drives the `ark-ar1cs` prover (`prove(.arzkey, .arwtns) → Groth16 Proof`).
- **cli**: Binary utilities (CRS generation, hash utilities)
- **ark-ar1cs-** crates: Circuit-agnostic byte interface (matrices `.ar1cs`, setup output `.arzkey`, witness `.arwtns`, prover, generic wasm-witness substrate). Imported as path dependencies from `../ark-ar1cs/crates/...` and bound to this repo's circuit identity by `ar1cs_blake3`.

## Crate Responsibilities

**ark-utils** provides low-level R1CS constraint helpers (array selection, field arithmetic, comparison), packing/decomposition utilities for witness construction, and EVM bytecode codegen for public input verification. It has no zkap-specific logic—purely reusable constraint gadgetry.

**gadget** implements feature-gated ZK circuit gadgets: SHA256 hashing, Poseidon hashing with parameter caching, RSA-2048 signature verification, base64 decoding with table lookup, Merkle tree traversal using Poseidon, Vandermonde matrix operations for the anchor scheme, and bigint arithmetic for RSA. All gadgets are constraint-based (use `Var` types) and integrate with arkworks.

**circuit** defines the main ZkapCircuit struct, CircuitConfig (runtime parameters like n/k/max_jwt_b64_len/tree_height), and witness types (JwtWitness, AnchorWitness, MerkleWitness, AudienceWitness). It orchestrates all gadgets into a single R1CS constraint system that proves JWT validity, threshold membership, issuer membership, and audience membership without exposing the JWT itself.

**zkap-service** is the public API layer that orchestrates proof generation end-to-end. It parses JWTs, validates requests, builds circuit witness, invokes Groth16 proving/verification, and provides utilities for anchor generation and hash computation. All request/response types (RawProofRequest, ProofRequest) are defined here and serializable for platform bindings.

The crate is split into two build profiles via the `proof` Cargo feature (enabled by default):
- **With `proof`** (default): full Groth16 proving stack, including `ark-groth16`, `ark-serialize`, `memmap2`, `jsonwebtoken`, and hash crates. Use for native server-side proof generation.
- **Without `proof`** (`default-features = false`): lightweight, WASM-compatible build. Only witness construction, DTOs, and data types are included. Proof generation functions are unavailable. Use for browser or mobile targets where proving happens server-side.

**cli** provides two binary utilities: `generate_crs` for structured reference string generation and `generate_hash` for standalone Poseidon hash computation for testing and setup.

## Data Flow

A proof is generated end-to-end as follows (V1 byte API + wasm
witness-generator runtime):

1. **`RawProofRequest`** (raw bytes): The host (binding crates in
   `zkap-zkp`, the `cli` binary, etc.) supplies a `RawProofRequest`
   populated with raw byte buffers — BE-encoded 32-byte field
   elements, full JWT byte buffers, RSA-2048 modulus / signature byte
   strings — plus a `pk_path` pointing at a `.arzkey` and a
   `wasm_path` pointing at the paired witness-generator `.wasm`.
2. **Validation** (`proof/request.rs`): `RawProofRequest::validate(k, n)`
   cross-checks per-JWT vector lengths, anchor cardinality
   (`n - k + 1`), and selector length (`n`). Bad shapes are rejected
   here, before any artifact is touched.
3. **V1 payload assembly** (`proof/mod.rs`): `CircuitConfig` is
   projected to wire-format `ZkapCircuitConfigV1`, and one
   `ZkapInputV1` is built per JWT. `zkap-input-types` is the single
   source of truth for the wire layout.
4. **`ProofGenerator::generate`**:
   1. `ArzkeyFile::read(pk_path)` (verifies the `.arzkey` envelope
      Blake3 trailer + self-consistency
      `arzkey.arcs().body_blake3() == header.ar1cs_blake3`).
   2. `std::fs::read(wasm_path)` (reads the witness-generator wasm
      bytes once into memory).
   3. **Host-side `ar1cs_blake3` fail-fast pair check**: instantiate
      the wasm runtime once, call `embedded_ar1cs_blake3()`, compare
      to `arzkey.header.ar1cs_blake3`. Mismatch returns
      `ApplicationError::InvalidFormat("ar1cs_blake3 mismatch: ...")`
      *before* the per-proof loop runs. The wasm-side
      `witness_generator` still enforces the same equality check
      internally as defense in depth. This is **not** a complete
      supply-chain defense against a malicious wasm — a hostile wasm
      can lie about its embedded blake3.
   4. For each input (per-proof allocator reset):
      1. Instantiate a fresh `DefaultRuntime` over the wasm bytes.
      2. `postcard::to_allocvec(&ZkapInputV1)`.
      3. Drive the wasm `witness_generator` ABI export, passing
         `arzkey.header.ar1cs_blake3` as the `host_blake3` parameter.
         The wasm side runs `ZkapInputV1::into_circuit_input →
         ZkapCircuit::from_input → generate_constraints` and emits
         a serialized `ArwtnsFile` over linear memory.
      4. `ArwtnsFile::read(wasm_output_bytes)` (envelope check).
      5. `ark_ar1cs_prover::prove(&arzkey, &arwtns, &mut rng)`.
         The prover runs `bind_check` (curve_id / `ar1cs_blake3` /
         instance+witness count / arzkey self-consistency) +
         `preflight::check_r1cs_satisfaction` before calling
         `Groth16::create_proof_with_reduction_and_matrices`.
5. **Output**: Solidity-compatible proof component strings and split
   public-input lists per JWT (`ZkapProofResult` →
   `ProofComponents`). Verifier can check against public inputs
   without the JWT.

### Artifact identity binding

| Artifact         | Producer                                                | Consumer                                | Identity field                                                                  |
|------------------|---------------------------------------------------------|-----------------------------------------|---------------------------------------------------------------------------------|
| `.ar1cs`         | `setup()` → `cs.to_matrices()` → `ArcsFile::from_matrices` | embedded inside `.arzkey`               | Blake3 of canonical body                                                        |
| `.arzkey`        | `setup()` → `crs.rs` → `ArzkeyFile::from_setup_output`     | `ProofGenerator::load_arzkey`           | `header.ar1cs_blake3`                                                           |
| `circuit.wasm`   | `crates/zkap-witness-wasm` `build-wasm.sh` (build.rs reads `AR1CS_WITNESS_ARZKEY_PATH` and bakes `EMBEDDED_AR1CS_BLAKE3`) | `ProofGenerator::generate` (loaded as bytes, instantiated by `DefaultRuntime`) | `EMBEDDED_AR1CS_BLAKE3`                                                         |
| `.arwtns`        | wasm `witness_generator` export                            | `ark_ar1cs_prover::prove`               | `header.ar1cs_blake3` (set from the host-supplied `host_blake3` parameter)      |

`ar1cs_blake3` is the single sanctioned cross-binding mechanism: the
same 32-byte hash appears as `arzkey.header.ar1cs_blake3`,
`EMBEDDED_AR1CS_BLAKE3` baked into the `.wasm`, and
`arwtns.header.ar1cs_blake3`. Any pairwise drift is rejected
structurally before the SNARK runs.

## Key Design Decisions

**Runtime CircuitConfig** (not compile-time generics): The circuit accepts CircuitConfig as a runtime parameter (n, k, tree_height, max_jwt_b64_len, etc.), not as compile-time type parameters. This allows a single binary to support multiple circuit configurations without recompilation—critical for platform bindings and server deployments where config is loaded from JSON.

**Poseidon Hash for Anchor Scheme**: The threshold anchor scheme uses Poseidon hashing with a Vandermonde matrix approach rather than traditional threshold cryptography. This is efficient in-circuit (Poseidon is field-arithmetic-optimized) and allows non-interactive threshold proofs. Parameters are cached globally via OnceLock to avoid recomputation.

**Service Crate Flat Module Structure**: Service modules (proof, anchor, hash, jwt, dto) are organized by responsibility, not by data type. Each module handles its own DTOs and logic: `proof/` manages RawProofRequest → ProofRequest → ZkapCircuitInput → Proof, `anchor/` handles Poseidon anchor generation, `hash/` provides standalone hash utilities, and `jwt/` parses and extracts witnesses. This avoids deep nesting and keeps request/response handling colocated with orchestration logic.

**OnceLock Cached Poseidon Parameters**: Poseidon configuration is expensive to construct. It is computed once lazily via OnceLock::get_or_init and shared across all modules (service::poseidon_params()). This eliminates redundant computation and is thread-safe.

## Service Module Map

```
service/src/
├── proof/         Prove, verify, setup orchestration
│   ├── request.rs     RawProofRequest validation
│   ├── types.rs       CircuitContext, AnchorContext, AudienceContext
│   ├── context.rs     Circuit input construction from witness
│   └── generator.rs   Groth16 proving and verification
├── anchor/        Poseidon anchor generation for threshold schemes
│   ├── poseidon.rs    generate_anchor (k-of-N aggregation)
│   └── types.rs       Secret, AnchorResult types
├── hash/          Standalone Poseidon hash utilities
│   └── mod.rs         generate_hash, generate_aud_hash, generate_leaf_hash
├── jwt/           JWT parsing and witness construction
│   ├── parser.rs      Parse JWT header/payload/signature
│   └── builder.rs     Build JwtWitness and ClaimIndices
├── dto/           Platform-agnostic data transfer objects
│   ├── proof.rs       Serializable proof/verify request/response
│   ├── anchor.rs      Serializable anchor request/response
│   └── hash.rs        Serializable hash request/response
├── crs.rs         CRS persistence (writes pk.arzkey [V1 prove path],
│                  pk.key/vk.key/pvk.key [legacy], Groth16Verifier.sol, config.json)
├── error.rs       ApplicationError enum (parse, validation, constraint failures)
└── lib.rs         Public API (prove, verify, setup, generate_anchor, generate_hash)
```
