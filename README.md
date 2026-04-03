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
- **Multi-platform bindings**: NAPI (Node.js), WASM (browser), UniFFI (iOS/Android)
- **CSO-audited**: External security audit completed

## Architecture

```
+----------------------------------------------------------+
|                     Bindings Layer                       |
|                                                          |
|   bindings/napi        bindings/wasm    bindings/uniffi  |
|   (Node.js / npm)      (Browser)        (iOS / Android)  |
+------------------------+---------------------------------+
                         |
+------------------------v---------------------------------+
|                   crates/service                         |
|   generate_baerae_proof()    RawProofRequest             |
|   create_poseidon_anchor()   poseidon_hash()             |
+------------------------+---------------------------------+
                         |
+------------------------v---------------------------------+
|                   crates/circuit                         |
|   BaeraeLightWeightCircuit    BaeraeCircuitInput         |
|   CircuitPublicInputs         ZkPasskeyConfig            |
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
|   R1CS constraint system helpers, field utilities        |
+----------------------------------------------------------+
```

## Installation

### Rust

Add to your `Cargo.toml`:

```toml
[dependencies]
zkpasskey-service = { git = "https://github.com/snp-labs/zkap-circuit" }
```

To use individual gadgets with fine-grained features:

```toml
[dependencies]
gadget = { git = "https://github.com/snp-labs/zkap-circuit", features = ["full"] }
# Available features: anchor, base64, hashes-poseidon, hashes-sha256, merkletree, rsa, crypto, full
```

### Node.js (npm)

Pre-built NAPI binaries are distributed per platform. Install from the release artifacts:

```bash
npm install @snp-labs/zkap-circuit
```

Or build from source (requires Rust toolchain and `zig` for cross-compilation):

```bash
./build.sh --napi-only -e macos-arm64   # native build
./build.sh --napi-only -e linux-x64     # cross-compile
```

### WASM (browser)

Build from source using `wasm-pack`:

```bash
./build.sh --napi-only -e wasm   # produces bindings/wasm/pkg/
```

Then import the generated package via your bundler or load it directly in a browser.

## Quick Start (Node.js, 3 minutes)

This example generates a Groth16 proof from a JWT using the pre-built NAPI binding.

**Step 1**: Generate a proving key (one-time setup, outputs to `./output/keys/`):

```bash
./build.sh --keys-only
```

**Step 2**: Generate a proof:

```js
const { napiGenerateProof } = require('@snp-labs/zkap-circuit');

// All field elements are hex-encoded BN254 scalar field elements.
const result = napiGenerateProof({
  // Path to the Groth16 proving key produced by generate_baerae_crs
  pkPath: './output/keys/baerae.pk',

  // One raw JWT string per prover (header.payload.signature, base64url-encoded)
  jwts: ['eyJhbGci...'],

  // RSA-2048 public keys in PEM format (one per JWT)
  pkOps: ['-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----'],

  // Merkle authentication paths for the issuer-public key leaves
  // Each entry is an array of hex field elements, one per tree level
  merklePaths: [['0xabc...', '0xdef...']],

  // Leaf indices in the issuer Merkle tree (u32)
  leafIndices: [0],

  // Merkle root (hex field element)
  root: '0x1234...',

  // Threshold anchor values (k-of-N Vandermonde scheme, hex field elements)
  anchor: ['0xaaaa...', '0xbbbb...'],

  // Poseidon hash of the user-operation being authorized
  hSignUserOp: '0xcccc...',

  // Non-zero random blinding factor (BN254 scalar, keep secret)
  random: '0xdddd...',

  // Allowed audience list (hex Poseidon hashes of each audience string)
  audList: ['0xeeee...'],
});

// result.proofs          -- serialized Groth16 proof per JWT
// result.sharedInputs   -- public inputs shared across all provers
// result.partialRhsList -- partial RHS values for threshold aggregation
// result.jwtExpList     -- expiry timestamps extracted from each JWT
console.log('Proof generated. Public inputs:', result.sharedInputs);
```

## Crate Overview

| Crate | Purpose | Key Types |
|---|---|---|
| `ark-utils` | R1CS helpers, field arithmetic utilities | `select_array_element` |
| `gadget` | ZK circuit gadgets (feature-gated) | `SHA256Gadget`, `Base64DecoderGadget`, `BigNatVar`, `VandermondeMatrixVar`, `PoseidonAnchorSchemeGadget` |
| `gadget::signature::rsa` | RSA-2048 witness and constraint types | `PublicKey`, `Signature`, `PublicKeyVar`, `SignatureVar` |
| `gadget::merkletree` | Poseidon Merkle tree | `MerkleTreeParams`, `MerkleTreeParamsVar` |
| `circuit` | Main circuit implementation | `BaeraeLightWeightCircuit`, `BaeraeCircuitInput`, `CircuitPublicInputs`, `ZkPasskeyConfig` |
| `service` | Proof generation service layer | `generate_baerae_proof`, `RawProofRequest`, `create_poseidon_anchor`, `poseidon_hash` |
| `bindings/napi` | Node.js NAPI bindings | `napiGenerateProof`, `GenerateProofReq`, `GenerateProofRes` |
| `bindings/wasm` | WebAssembly bindings | wasm-pack output |
| `bindings/uniffi` | iOS / Android UniFFI bindings | Swift / Kotlin generated interfaces |

## Building from Source

**Requirements**: Rust (stable, 2024 edition), `cargo`, `npm`, `zig` (cross-compilation only)

```bash
# Full build: key generation + NAPI bindings for all platforms
./build.sh

# Native platform only
./build.sh -e macos-arm64      # Apple Silicon
./build.sh -e linux-x64        # Linux x86_64

# Key generation only (no NAPI)
./build.sh --keys-only

# NAPI bindings only (skip key generation)
./build.sh --napi-only -e macos-arm64

# Configure circuit parameters (default: N=3, K=3)
./build.sh -n 5 -k 3

# Dry-run: validate configuration without building
./build.sh --dry-run -e linux-x64

# CI mode: auto-approve missing Rust target installation
./build.sh --yes -e linux-x64
```

**Circuit parameters** (configure via environment variables or `build.sh` flags):

| Variable | Default | Description |
|---|---|---|
| `ZK_N` | 3 | Total number of signers |
| `ZK_K` | 3 | Threshold (minimum signers required) |
| `ZK_MAX_JWT_B64_LEN` | 1024 | Maximum JWT length in base64 bytes |
| `ZK_MAX_PAYLOAD_B64_LEN` | 896 | Maximum payload length in base64 bytes |
| `ZK_TREE_HEIGHT` | 16 | Issuer Merkle tree height (supports up to 2^16 issuers) |
| `ZK_NUM_AUDIENCE_LIMIT` | 5 | Maximum allowed audience list size |

Output is written to `./output/`:

```
output/
  keys/           # Groth16 proving and verification keys
  napi/<env>/     # Platform-specific NAPI .node files
  *.tar.gz        # Release archive
```

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

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

Bug reports, feature requests, and documentation improvements are welcome via GitHub Issues at [snp-labs/zkap-circuit](https://github.com/snp-labs/zkap-circuit/issues).

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.