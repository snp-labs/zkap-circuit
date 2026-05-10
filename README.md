# zkap-circuit

A Rust library for generating Groth16 zero-knowledge proofs that verify JWT/OAuth tokens without revealing their contents. Built on [arkworks](https://github.com/arkworks-rs).

## Status

> **Experimental.** This library is under active development and has not reached a
> stable release. The API, circuit constraints, and serialisation formats may change
> without notice. It has not been battle-tested in production deployments. Use at your own risk.



## Features

- **JWT verification in ZK**: Proves a valid JWT was issued by a known provider without exposing the token
- **RSA-2048 signature verification**: Enforces `e = 65537` inside the circuit
- **Payload boundary binding**: Cryptographically binds the claimed payload region to the actual `.` separators
- **Threshold membership (k-of-N)**: Vandermonde-based anchor scheme for multi-party settings
- **Merkle tree issuer registry**: Proves the RSA public key belongs to a trusted issuer set
- **Audience allowlist**: Zero-knowledge membership check against a hashed audience list
- **Groth16 on BN254**: Proof-friendly field using `ark-bn254`

## Architecture

```
+----------------------------------------------------------+
|                   crates/service                         |
|   prove()  verify()  setup()  RawProofRequest             |
|   generate_anchor()  generate_hash()  generate_aud_hash()|
+------------------------+---------------------------------+
                         |
+---------------------+  |  +------------------------------+
|    crates/cli       |  |  |                              |
|  generate_crs (bin) |  |  |                              |
+---------------------+  |  |                              |
                         |  |                              |
+------------------------v--v------------------------------+
|                   crates/circuit                         |
|   ZkapCircuit     ZkapCircuitInput    CircuitConfig      |
+------------------------+---------------------------------+
                         |
+------------------------v---------------------------------+
|                   crates/gadget                          |
|                                                          |
|   anchor/poseidon    base64         bigint (RSA)         |
|   hashes/sha256      hashes/poseidon                     |
|   matrix             merkletree     signature/rsa        |
+------------------------+---------------------------------+
                         |
+------------------------v---------------------------------+
|                  crates/ark-utils                        |
|   R1CS constraint helpers, field arithmetic, EVM codegen |
+----------------------------------------------------------+
```

For platform-specific bindings (Node.js, WASM, iOS/Android), see [zkap-zkp](https://github.com/baerae-zkap/zkap-zkp)
(currently private; public release planned).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
# Full build — includes Groth16 proving, key loading, and all heavy dependencies
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit" }

# Lightweight build — WASM-compatible, no proving/verifying, no heavy arkworks deps
# Use this for platforms where proof generation happens server-side (browser, mobile)
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit", default-features = false }
```

The `proof` feature (enabled by default) pulls in Groth16 proving, key deserialization, and all heavyweight `ark-*` dependencies. Disable it for WASM targets or bindings that only need witness construction and data types.

To use individual gadgets with fine-grained features:

```toml
[dependencies]
gadget = { git = "https://github.com/snp-labs/zkap-circuit", features = ["full"] }
# Available features: anchor, base64, hashes-poseidon, hashes-sha256, merkletree, rsa, crypto, full
```

## Crate Overview

| Crate | Purpose | Key Types |
|---|---|---|
| `ark-utils` | R1CS helpers, field arithmetic utilities | `select_array_element` |
| `gadget` | ZK circuit gadgets (feature-gated) | `SHA256Gadget`, `Base64DecoderGadget`, `BigNatVar`, `VandermondeMatrixVar`, `PoseidonAnchorSchemeGadget` |
| `gadget::signature::rsa` | RSA-2048 witness and constraint types | `PublicKey`, `Signature`, `PublicKeyVar`, `SignatureVar` |
| `gadget::merkletree` | Poseidon Merkle tree | `MerkleTreeParams`, `MerkleTreeParamsVar` |
| `circuit` | Main circuit implementation | `ZkapCircuit`, `ZkapCircuitInput`, `CircuitPublicInputs`, `CircuitConfig` |
| `cli` | CRS generation and hash utilities | `generate_crs`, `generate_hash` (binaries) |
| `service` | Proof generation service layer | `prove`, `verify`, `setup`, `generate_anchor`, `generate_hash` |

## Quick Start

```rust
use std::path::Path;
use zkap_service::{
    generate_anchor, generate_aud_hash, generate_hash, generate_leaf_hash,
    load_circuit_config, Secret,
};

// Load circuit parameters from a JSON config file.
let config = load_circuit_config(Path::new("example.json"))
    .expect("Failed to load config");

// Always-available helpers (no proving artifacts required).
let h = generate_hash(vec!["0x1".into(), "0x2".into()]).unwrap();
let aud = generate_aud_hash(&config, vec!["my-audience".into()]).unwrap();
let leaf = generate_leaf_hash(&config, "https://issuer.example", "<base64 RSA N>").unwrap();
```

> The V1 prove path (`zkap_service::prove`) takes a `RawProofRequest`
> populated with raw bytes (BE-encoded field elements, full JWT bytes,
> RSA modulus / signature byte strings) plus a paired
> (`.arzkey`, witness-generator `.wasm`) bundle on disk. The
> stand-alone `groth16_proof` example is **temporarily disabled** while
> the V1 byte API rewrite lands (see [Examples and tests](#examples-and-tests)).
> For full type signatures and field semantics, see the
> [API Reference](docs/API_REFERENCE.md).

## Examples and tests

The `crates/service/examples/groth16_proof.rs` example targets the
legacy V0 hex/Base64 `RawProofRequest::new` shape and is currently
parked as `groth16_proof.rs.bak` while we rewrite it against the V1
byte API. Restoring a runnable end-to-end example (using a checked-in
small fixture `.arzkey` + `.wasm` pair) is a planned follow-up.

In the meantime, the canonical end-to-end exercise of the wasm
witness-generator + ark-ar1cs prove path is the integration test
`crates/zkap-witness-wasm/tests/wasm_to_prove.rs`. It freshly
generates a test `.arzkey`, rebuilds `zkap-witness-wasm` for
`wasm32-unknown-unknown` against that `.arzkey`, drives the four
ABI exports, and runs `prove` + `verify_proof` end-to-end:

```bash
# Builds the wasm32 artifact internally, takes ~1 minute on a clean tree.
cargo test -p zkap-witness-wasm --test wasm_to_prove --release
```

The same test suite also covers the host-side
`ar1cs_blake3` mismatch fail-fast path
(`host_rejects_wasm_with_mismatched_ar1cs_blake3`).

## Pre-built CRS Artifacts

The `dist/` directory ships two layouts at the moment; consumers
should pick the layout that matches the API they are using:

- **V1 layout** (current prove path):
  - `dist/1-of-1/` — single-signer (N=1, K=1)
  - `dist/3-of-3/` — three-of-three (N=3, K=3)
  - Files: `circuit.arzkey` (proving key + ARCS/R1CS identity envelope,
    `RawProofRequest::pk_path` points at this), `circuit.wasm`
    (the ZKAP-specific witness-generator artifact paired with
    `circuit.arzkey` via `ar1cs_blake3`), `config.json`.
- **Legacy layout** (V0 prove path, kept for the on-chain Solidity
  verifier consumers):
  - `dist/1of1/` — single-signer (N=1, K=1)
  - `dist/3of3/` — three-of-three (N=3, K=3)
  - Files: `pk.key` (uncompressed `ProvingKey<E>`, **not** consumed by
    the V1 `prove`), `Groth16Verifier.sol`, `config.json`.

Custom configurations can be generated via `setup()` or the
`generate_crs` CLI binary; both write a paired
(`pk.arzkey`, `pk.key`, `vk.key`, `pvk.key`, `Groth16Verifier.sol`,
`config.json`) bundle today. Cleaning the dist tree to a single
canonical layout is a planned follow-up.

## Building from Source

**Requirements**: Rust 1.85+ (stable, required for the 2024 edition)

```bash
git clone https://github.com/snp-labs/zkap-circuit.git
cd zkap-circuit

# Build
cargo build --release

# Run tests (258 tests across all crates)
cargo test

# Lint
cargo clippy -- -D warnings
```

**Circuit parameters** are configured at runtime via `CircuitConfig` (loaded from a JSON config file via `load_circuit_config`, or from the `config.json` written by `setup`):

| Parameter | Description |
|---|---|
| `n` | Total number of signers |
| `k` | Threshold (minimum signers required) |
| `max_jwt_b64_len` | Maximum JWT length in base64 bytes |
| `max_payload_b64_len` | Maximum payload length in base64 bytes |
| `max_aud_len` | Maximum `aud` claim length in bytes |
| `max_exp_len` | Maximum `exp` claim length in bytes |
| `max_iss_len` | Maximum `iss` claim length in bytes |
| `max_nonce_len` | Maximum `nonce` claim length in bytes |
| `max_sub_len` | Maximum `sub` claim length in bytes |
| `tree_height` | Issuer Merkle tree height (supports up to 2^height issuers) |
| `num_audience_limit` | Maximum allowed audience list size |
| `claims` | JWT claim names to extract (e.g. `["aud","exp","iss","nonce","sub"]`) |
| `forbidden_string` | String forbidden inside JWT claims (injection guard) |

An example configuration is provided in [`example.json`](example.json).

## Security

An external security audit (CSO review) was completed. Key findings addressed in the circuit:

- The RSA public exponent `e` is enforced equal to `65537` inside the R1CS circuit via `enforce_equal_when_carried`, preventing substitution of weak exponents.
- JWT payload boundaries are cryptographically bound to the `.` separator positions and the SHA-256 padding start index (`pad_start_byte_idx`), preventing an attacker from designating arbitrary byte regions as the payload.

Additional defense-in-depth constraints enforced by the circuit:
- Payload offset is enforced to be at least 1 (prevents field underflow on subtraction).
- Payload end index is range-checked against the buffer length (prevents buffer overrun).
- The random blinding factor is enforced non-zero (`random.enforce_not_equal(&zero)`).
- All selector indices are constrained to be boolean with exactly `k` set bits (cardinality check).
- The current signer index is range-checked to be less than `N`.

## Documentation

- [Example Guide](docs/EXAMPLE_GUIDE.md) — step-by-step proof lifecycle walkthrough with expected output
- [API Reference](docs/API_REFERENCE.md) — public function and type specifications
- [ARCHITECTURE.md](ARCHITECTURE.md) — crate dependencies, data flow, design decisions
- [Circuit Design](docs/CIRCUIT_DESIGN.md) — R1CS constraint structure and security properties
- [Performance](docs/PERFORMANCE.md) — benchmarks and resource requirements
- [Troubleshooting](docs/TROUBLESHOOTING.md) — common error diagnosis
- [CONTRIBUTING.md](CONTRIBUTING.md) — build instructions, PR process, commit conventions
- [SECURITY.md](SECURITY.md) — vulnerability reporting, known advisories, security design
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community guidelines

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

Bug reports, feature requests, and documentation improvements are welcome via [GitHub Issues](https://github.com/snp-labs/zkap-circuit/issues).

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
