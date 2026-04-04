# zkap-circuit

A Rust library for generating Groth16 zero-knowledge proofs that verify JWT/OAuth tokens without revealing their contents. Built on [arkworks](https://github.com/arkworks-rs).

## Features

- **JWT verification in ZK**: Proves a valid JWT was issued by a known provider without exposing the token
- **RSA-2048 signature verification**: Enforces `e = 65537` inside the circuit ([ZKAPCIR-001])
- **Payload boundary binding**: Cryptographically binds the claimed payload region to the actual `.` separators ([ZKAPCIR-002])
- **Threshold membership (k-of-N)**: Vandermonde-based anchor scheme for multi-party settings
- **Merkle tree issuer registry**: Proves the RSA public key belongs to a trusted issuer set
- **Audience allowlist**: Zero-knowledge membership check against a hashed audience list
- **Groth16 on BN254**: Proof-friendly field using `ark-bn254`
- **CSO-audited**: External security audit completed

## Architecture

```
+----------------------------------------------------------+
|                   crates/service                         |
|   prove()  verify()  groth16_setup()  RawProofRequest    |
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

For platform-specific bindings (Node.js, WASM, iOS/Android), see [zkap-circuit-bindings](https://github.com/baerae-zkap/zkap-circuit-bindings).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit" }
```

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
| `service` | Proof generation service layer | `prove`, `verify`, `groth16_setup`, `generate_anchor`, `generate_hash` |

## Quick Start

```rust
use zkap_service::{CircuitConfig, groth16_setup, prove, verify, RawProofRequest};
use std::path::PathBuf;

// 1. Load circuit parameters from a JSON manifest
let config = zkap_service::manifest::load_params_from_manifest("keys/manifest.json".as_ref())?;

// 2. Trusted setup (run once, produces proving/verifying keys)
let setup = groth16_setup(&config)?;

// 3. Generate a proof
let request = RawProofRequest::new(
    PathBuf::from("keys/pk.bin"),
    jwts,           // K JWT tokens
    pk_ops,         // K RSA public key moduli (Base64)
    merkle_paths,   // K Merkle authentication paths
    leaf_indices,   // K leaf indices
    root,           // Merkle root
    anchor,         // Anchor values + hanchor
    h_sign_user_op, // UserOperation hash
    random,         // Blinding factor
    aud_list,       // Audience hashes
);
let (proofs, public_inputs) = prove(&config, request)?;

// 4. Verify
let is_valid = verify(&setup.pvk, &proofs[0], &public_inputs[0])?;
assert!(is_valid);
```

## Building from Source

**Requirements**: Rust 1.80+ (stable, 2024 edition)

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

**Circuit parameters** are configured at runtime via `CircuitConfig` (or loaded from a JSON manifest):

| Parameter | Description |
|---|---|
| `n` | Total number of signers |
| `k` | Threshold (minimum signers required) |
| `max_jwt_b64_len` | Maximum JWT length in base64 bytes |
| `max_payload_b64_len` | Maximum payload length in base64 bytes |
| `tree_height` | Issuer Merkle tree height (supports up to 2^height issuers) |
| `num_audience_limit` | Maximum allowed audience list size |

## Security

An external security audit (CSO review) was completed. Key findings addressed in the circuit:

- **[ZKAPCIR-001]** The RSA public exponent `e` is enforced equal to `65537` inside the R1CS circuit via `enforce_equal_when_carried`, preventing substitution of weak exponents.
- **[ZKAPCIR-002]** JWT payload boundaries are cryptographically bound to the `.` separator positions and the SHA-256 padding start index (`pad_start_byte_idx`), preventing an attacker from designating arbitrary byte regions as the payload.

Additional defense-in-depth constraints enforced by the circuit:
- Payload offset is enforced to be at least 1 (prevents field underflow on subtraction).
- Payload end index is range-checked against the buffer length (prevents buffer overrun).
- The random blinding factor is enforced non-zero (`random.enforce_not_equal(&zero)`).
- All selector indices are constrained to be boolean with exactly `k` set bits (cardinality check).
- The current signer index is range-checked to be less than `N`.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — crate dependencies, data flow, design decisions
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
