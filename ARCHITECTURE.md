# Architecture

## High-Level Overview

zkap-circuit is a Rust library for generating Groth16 zero-knowledge proofs that verify JWT/OAuth tokens without revealing their contents. The circuit proves a valid JWT was issued by a known provider, enforces RSA-2048 signatures, and binds payloads cryptographically—all without exposing the token itself. It uses arkworks primitives on the BN254 curve and supports threshold schemes via Vandermonde-based anchor generation.

## Crate Dependency Graph

```
zkap-service ─────────→ circuit ─────────→ gadget ─────────→ ark-utils
     ↑                       ↑                   ↑
     │                       │                   └─→ arkworks
     └─── cli ───────────────┘
```

- **ark-utils**: Base layer (R1CS helpers, field arithmetic, EVM codegen)
- **gadget**: Circuit gadgets (feature-gated): SHA256, Poseidon, RSA, base64, Merkle tree, anchor, matrix
- **circuit**: Main ZkapCircuit, CircuitConfig, witness types, R1CS constraints
- **zkap-service**: Proof generation orchestration, public API
- **cli**: Binary utilities (CRS generation, hash utilities)

## Crate Responsibilities

**ark-utils** provides low-level R1CS constraint helpers (array selection, field arithmetic, comparison), packing/decomposition utilities for witness construction, and EVM bytecode codegen for public input verification. It has no zkap-specific logic—purely reusable constraint gadgetry.

**gadget** implements feature-gated ZK circuit gadgets: SHA256 hashing, Poseidon hashing with parameter caching, RSA-2048 signature verification, base64 decoding with table lookup, Merkle tree traversal using Poseidon, Vandermonde matrix operations for the anchor scheme, and bigint arithmetic for RSA. All gadgets are constraint-based (use `Var` types) and integrate with arkworks.

**circuit** defines the main ZkapCircuit struct, CircuitConfig (runtime parameters like n/k/max_jwt_b64_len/tree_height), and witness types (JwtWitness, AnchorWitness, MerkleWitness, AudienceWitness). It orchestrates all gadgets into a single R1CS constraint system that proves JWT validity, threshold membership, issuer membership, and audience membership without exposing the JWT itself.

**zkap-service** is the public API layer that orchestrates proof generation end-to-end. It parses JWTs, validates requests, builds circuit witness, invokes Groth16 proving/verification, and provides utilities for anchor generation, hash computation, and CRS manifest validation. All request/response types (RawProofRequest, ProofRequest) are defined here and serializable for platform bindings.

**cli** provides two binary utilities: `generate_crs` for structured reference string generation and `generate_hash` for standalone Poseidon hash computation for testing and setup.

## Data Flow

A proof is generated end-to-end as follows:

1. **RawProofRequest** (JSON): User provides JWT, issuer Merkle root, audience list, and circuit config path.
2. **Validation**: Request is validated and loaded. CircuitConfig is deserialized and validated (k ≤ n, tree_height ≥ 1, etc.).
3. **ProofRequest**: Raw request is converted to ProofRequest, JWT is parsed, and witness is extracted (header, payload, signature bytes).
4. **Context Building** (jwt/builder.rs): JWT claims are decoded, payload boundaries are identified, RSA signature is prepared, and Merkle tree paths are retrieved.
5. **Circuit Input Construction** (proof/context.rs): All witness and constants are assembled into ZkapCircuitInput (CircuitConstants, CircuitPublicInputs, JwtWitness, AnchorWitness, MerkleWitness, AudienceWitness, MiscWitness).
6. **Groth16 Proving** (proof/generator.rs): Circuit is synthesized, witness is loaded into constraint variables, all R1CS constraints are checked, and a Groth16 proof is generated.
7. **Proof Output**: Proof is serialized and returned to caller. Verifier can check it against public inputs without the JWT.

## Key Design Decisions

**Runtime CircuitConfig** (not compile-time generics): The circuit accepts CircuitConfig as a runtime parameter (n, k, tree_height, max_jwt_b64_len, etc.), not as compile-time type parameters. This allows a single binary to support multiple circuit configurations without recompilation—critical for platform bindings and server deployments where config is loaded from JSON.

**Poseidon Hash for Anchor Scheme**: The threshold anchor scheme uses Poseidon hashing with a Vandermonde matrix approach rather than traditional threshold cryptography. This is efficient in-circuit (Poseidon is field-arithmetic-optimized) and allows non-interactive threshold proofs. Parameters are cached globally via OnceLock to avoid recomputation.

**Service Crate Flat Module Structure**: Service modules (proof, anchor, hash, jwt, dto) are organized by responsibility, not by data type. Each module handles its own DTOs and logic: `proof/` manages RawProofRequest → ProofRequest → ZkapCircuitInput → Proof, `anchor/` handles Poseidon anchor generation, `hash/` provides standalone hash utilities, and `jwt/` parses and extracts witnesses. This avoids deep nesting and keeps request/response handling colocated with orchestration logic.

**OnceLock Cached Poseidon Parameters**: Poseidon configuration is expensive to construct. It is computed once lazily via OnceLock::get_or_init and shared across all modules (service::poseidon_params()). This eliminates redundant computation and is thread-safe.

## Service Module Map

```
service/src/
├── proof/         Prove, verify, groth16_setup orchestration
│   ├── request.rs     RawProofRequest validation
│   ├── types.rs       ProofRequest, Proof, VerifyRequest types
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
├── error.rs       ApplicationError enum (parse, validation, constraint failures)
├── manifest.rs    CRS manifest validation (file path checks, keyset sync)
└── lib.rs         Public API (prove, verify, groth16_setup, generate_anchor, generate_hash)
```
