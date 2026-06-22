# zkap-circuit

ZKAP core circuit and proving workspace.

This repository is the source of truth for the ZKAP statement, CRS bundle
format, and artifact trust boundary. It implements the Rust circuit that proves
JWT/OAuth validity without revealing the token, plus the setup/prove service
layer, CLI utilities, WASM witness artifact, and EVM verifier code generation.

Platform SDKs for Node.js, browser WASM, iOS, Android, and React Native live in
the sibling `zkap-zkp` repository. This repository owns the protocol/circuit
contract that those SDKs wrap.

## Status

> **Experimental.** This workspace is under active development. Public APIs,
> circuit constraints, CRS bundle layout, and serialization formats may change
> before a stable release.

## What This Repository Owns

- **ZK statement**: JWT/OAuth validity, issuer membership, threshold anchor
  membership, audience allowlist membership, and execution binding.
- **Circuit implementation**: arkworks R1CS over BN254, with RSA-2048,
  SHA-256, Poseidon, base64, Merkle, and anchor gadgets.
- **Trusted setup output**: `circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`,
  `Groth16Verifier.sol`, `config.json`, optional `witness_gen.wasm`, and
  `manifest.json`.
- **Artifact trust boundary**: `ArtifactSet::load_signed` and
  `ArtifactSet::load_unsigned` validate manifest claims before proving.
- **Service API**: setup, host-side hash/anchor helpers, witness synthesis, and
  the free `prove(&ArtifactSet, &ProveRequest)` entry point.
- **CLI utilities**: `generate_setup`, `generate_hash`, and `generate_witness_gen_sidecar`.

## Crates

| Crate | Purpose |
|---|---|
| `crates/service` | Public service API: setup/prove, `ArtifactSet`, manifest validation, DTOs, hash/anchor/JWT helpers |
| `crates/circuit` | Main `ZkapCircuit`, `CircuitConfig`, witness and public-input types |
| `crates/gadget` | Reusable circuit gadgets: Poseidon, SHA-256, RSA, base64, Merkle, anchor, matrix |
| `crates/ark-codec` | arkworks field/string/affine codec helpers |
| `crates/ark-r1cs-helpers` | R1CS comparison, packing, select, and slice helpers |
| `crates/cli` | `generate_setup`, `generate_hash`, and `generate_witness_gen_sidecar` binaries |
| `crates/witness-gen-wasm` | wasm32 C ABI witness generator artifact |
| `crates/zkap-evm-verifier` | Solidity Groth16 verifier codegen |

## Public API Snapshot

Host-side helper APIs are always available:

```rust
use std::path::Path;
use zkap_service::{
    AnchorSecret, AudienceHashRequest, GenerateAnchorRequest, HashRequest,
    IssuerKeyHashRequest, generate_anchor, generate_audience_hashes,
    generate_issuer_key_hash, generate_poseidon_hash, load_circuit_config,
};

let config = load_circuit_config(Path::new("example.json"))?;

let hash = generate_poseidon_hash(HashRequest {
    field_elements: vec!["0x1".into(), "0x2".into()],
})?;

let audiences = generate_audience_hashes(
    &config,
    AudienceHashRequest {
        audiences: vec!["my-audience".into()],
    },
)?;

let issuer_leaf = generate_issuer_key_hash(
    &config,
    IssuerKeyHashRequest {
        issuer: "https://issuer.example".into(),
        rsa_modulus_b64: "<base64 RSA modulus>".into(),
    },
)?;

let anchor = generate_anchor(
    &config,
    GenerateAnchorRequest {
        secrets: vec![AnchorSecret {
            subject: "user_0".into(),
            issuer: "https://issuer.example".into(),
            audience: "my-audience".into(),
        }],
    },
)?;
```

Claim helper inputs are raw strings. The service wraps claim values in JSON
quotes internally to match the bytes extracted from JWT payloads inside the
circuit.

## Artifact Loading And Proving

`manifest.json` is the deployment trust boundary. The prove path does not
re-read or re-validate artifacts; it trusts the `ArtifactSet` returned by the
loader.

```rust
use std::path::Path;
use ed25519_dalek::VerifyingKey;
use zkap_service::{ArtifactSet, ProveRequest, manifest::Manifest, prove};

let dir = Path::new("dist/release-local/1-of-1");
let manifest: Manifest = serde_json::from_slice(&std::fs::read(dir.join("manifest.json"))?)?;

// Production path for signed bundles.
let verifying_key: VerifyingKey = /* load the 32-byte ed25519 public key */;
let set = ArtifactSet::load_signed(&manifest, dir, &verifying_key)?;

let request: ProveRequest = /* host-provided credential batch */;
let response = prove(&set, &request)?;
let public_inputs = response.public_inputs_for(0);
```

Use `ArtifactSet::load_unsigned(&manifest, dir)` only for unsigned legacy
bundles, CI fixtures, or environments where the manifest is authenticated out
of band. It still validates sha256 and `ar1cs_blake3` claims, but it does not
verify the manifest signature.

Verify a proof with the free `verify(&ArtifactSet, &Proof<BN254>, &[F])` entry
point. It uses the prepared verifying key bundled in the `ArtifactSet` and
returns `Ok(true)` on a passing pairing check, `Ok(false)` on failure. The
`pk`/`vk`/`pvk` fields of `ArtifactSet` are `pub(crate)`; external callers
verify through `verify` rather than borrowing them.

## Generating A CRS Bundle

```bash
cargo run --release -p zkap-cli --bin generate_setup -- \
  --config example.json \
  --output crs/<name> \
  --circuit-id zkap-main-v1
```

This writes:

```
circuit.ar1cs
pk.bin
vk.bin
pvk.bin
Groth16Verifier.sol
config.json
manifest.json
```

Optional flags:

- `--witness-gen-wasm <path>` copies `witness_gen.wasm` into the bundle as a
  plain unsigned file. It is not a manifest artifact; its integrity is tracked
  by the separate `witness_gen.json` sidecar.
- `--signing-key <path>` signs `manifest.json` with a raw 32-byte ed25519
  secret key seed.
- `--verifying-key-out <path>` writes the corresponding raw 32-byte ed25519
  public key.

## Building From Source

Requirements: Rust stable with the workspace MSRV (`1.86`) and the
`wasm32-unknown-unknown` target from `rust-toolchain.toml`.

```bash
cargo build --release --workspace --locked
cargo test -p zkap-service --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

CI-grade workspace test sweep:

```bash
cargo nextest run --profile ci --cargo-profile release-tests --workspace --locked
```

Circuit integration test:

```bash
cargo nextest run --profile ci --cargo-profile release-tests \
  -p circuit --features integration-tests \
  --test groth16_integration --locked
```

WASM witness artifact:

```bash
bash scripts/ci/build-wasm-artifact.sh stage-wasm/witness_gen.wasm
```

## Documentation

- [API Reference](docs/API_REFERENCE.md) — current service API and DTOs
- [Example Guide](docs/EXAMPLE_GUIDE.md) — setup/prove/verify lifecycle
- [Architecture](ARCHITECTURE.md) — crate responsibilities and data flow
- [Circuit Design](docs/CIRCUIT_DESIGN.md) — R1CS constraints and security properties
- [Performance](docs/PERFORMANCE.md) — benchmark notes and resource guidance
- [Troubleshooting](docs/TROUBLESHOOTING.md) — common error diagnosis
- [Security](SECURITY.md) — vulnerability reporting and known advisories

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
