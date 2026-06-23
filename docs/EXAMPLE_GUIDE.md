# Example Guide: Setup -> Load -> Prove -> Verify

This guide describes the current ZKAP proof lifecycle. It is written as an
integration flow, not as a single in-tree runnable example binary.

## 1. Build Or Obtain A CRS Bundle

For a new circuit configuration, run trusted setup through the CLI:

```bash
cargo run --release -p zkap-cli --bin generate_setup -- \
  --config example.json \
  --output crs/example \
  --circuit-id zkap-main-v1
```

This produces:

```text
crs/example/
  circuit.ar1cs
  pk.bin
  vk.bin
  pvk.bin
  Groth16Verifier.sol
  config.json
  manifest.json
```

Optional production signing:

```bash
cargo run --release -p zkap-cli --bin generate_setup -- \
  --config example.json \
  --output crs/example \
  --circuit-id zkap-main-v1 \
  --signing-key signing.key \
  --verifying-key-out verifying.key
```

Optional WASM witness artifact:

```bash
bash scripts/ci/build-wasm-artifact.sh stage-wasm/witness_gen.wasm

cargo run --release -p zkap-cli --bin generate_setup -- \
  --config example.json \
  --output crs/example \
  --circuit-id zkap-main-v1 \
  --witness-gen-wasm stage-wasm/witness_gen.wasm
```

## 2. Load The Bundle

Signed production bundle:

```rust
use std::path::Path;
use ed25519_dalek::VerifyingKey;
use zkap_service::{ArtifactSet, manifest::Manifest};

let dir = Path::new("crs/example");
let manifest: Manifest = serde_json::from_slice(&std::fs::read(dir.join("manifest.json"))?)?;
let verifying_key_bytes = std::fs::read("verifying.key")?;
let verifying_key = VerifyingKey::from_bytes(
    verifying_key_bytes.as_slice().try_into().expect("32-byte ed25519 key"),
)?;

let set = ArtifactSet::load_signed(&manifest, dir, &verifying_key)?;
```

Unsigned fixture or out-of-band authenticated manifest:

```rust
let set = ArtifactSet::load_unsigned(&manifest, dir)?;
```

Both loaders validate artifact sha256 claims and `ar1cs_blake3`. Only
`load_signed` verifies manifest authenticity.

## 3. Prepare Helper Outputs

The service helper APIs accept raw claim strings and add JWT JSON quotes
internally where needed.

### Nonce / generic Poseidon hash

```rust
use zkap_service::{HashRequest, generate_poseidon_hash};

let nonce = generate_poseidon_hash(HashRequest {
    field_elements: vec![h_sign_user_op.clone(), random.clone()],
})?;
```

### Audience allowlist

```rust
use zkap_service::{AudienceHashRequest, generate_audience_hashes};

let audience_hashes = generate_audience_hashes(
    &set.cfg,
    AudienceHashRequest {
        audiences: vec!["my-client-id".into()],
    },
)?;
```

Use `audience_hashes.audience_hashes` as the padded per-slot list and
`audience_hashes.audience_list_hash` as `h_aud_list`.

### Issuer-key Merkle leaves

```rust
use zkap_service::{IssuerKeyHashRequest, generate_issuer_key_hash};

let leaf = generate_issuer_key_hash(
    &set.cfg,
    IssuerKeyHashRequest {
        issuer: "https://accounts.example".into(),
        rsa_modulus_b64,
    },
)?;
```

Build the issuer Merkle tree from these leaf hashes. The resulting Merkle root
and per-credential authentication paths go into `ProveRequest`.

### Threshold anchor

```rust
use zkap_service::{
    AnchorSecret, GenerateAnchorRequest, generate_anchor,
};

let anchor = generate_anchor(
    &set.cfg,
    GenerateAnchorRequest {
        secrets: vec![
            AnchorSecret {
                subject: "user_0".into(),
                issuer: "https://accounts.example".into(),
                audience: "my-client-id".into(),
            },
            // ... exactly set.cfg.n entries
        ],
    },
)?;
```

Use `anchor.anchor_evaluations` in `ProveRequest::anchor`.
`anchor.hanchor` is returned for callers that need to compare or log the public
input; `prove` recomputes it from `anchor` and does not accept caller-supplied
`hanchor`.

## 4. Assemble `ProveRequest`

`ProveRequest` carries no artifact paths. Artifact identity has already been
checked by `ArtifactSet::load_signed` or `ArtifactSet::load_unsigned`.

```rust
use zkap_service::{ProveCredential, ProveRequest};

let request = ProveRequest {
    random,
    h_sign_user_op,
    anchor: anchor.anchor_evaluations,
    merkle_root,
    credentials: vec![
        ProveCredential {
            jwt,
            rsa_modulus_b64,
            merkle_path,
            merkle_leaf_idx,
        },
        // ... exactly set.cfg.k credentials
    ],
};
```

Boundary validation checks:

- `credentials.len() == set.cfg.k`
- `anchor.len() == set.cfg.n - set.cfg.k + 1`
- each `merkle_path.len() == set.cfg.tree_height`
- each `merkle_leaf_idx < 2^set.cfg.tree_height`
- RSA modulus base64 decodes to 256 bytes
- field strings parse as BN254 Fr values

## 5. Prove

```rust
use zkap_service::prove;

let response = prove(&set, &request)?;
```

The prove path:

1. Decodes and validates the request.
2. Derives witness bundles from JWT claims, Merkle paths, audience hashes, and
   anchor data.
3. Synthesizes full assignments.
4. Calls `ark_ar1cs::prove_with_mode(..., VerifyAfter)` once per credential.
5. Returns `ProveResponse`.

The prove path does not re-check artifact hashes.

## 6. Verify

```rust
use zkap_service::verify;

let public_inputs_hex = response.public_inputs_for(0);
// Convert the hex strings to Vec<F> using the same field codec used by the host.
let public_inputs: Vec<F> = /* decode public_inputs_hex */;

let ok = verify(&set, &proof, &public_inputs)?;
assert!(ok);
```

`verify` returns `Ok(true)` on a passing pairing check, `Ok(false)` on
failure.

Public input order:

```text
[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]
```

## 7. Useful Checks

For documentation/API changes:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

For service loader/prove changes:

```bash
cargo test -p zkap-service --locked
```

For full CI parity:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo nextest run --profile ci --cargo-profile release-tests --workspace --locked
```
