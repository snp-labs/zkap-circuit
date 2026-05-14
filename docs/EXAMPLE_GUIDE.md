# Example Guide: Proof Lifecycle Walkthrough

A step-by-step guide to running the complete setup → prove → verify lifecycle.

## Prerequisites

- Rust 1.85+ (stable, required for the 2024 edition)
- Release mode build (`--release` is required)

## Run the Example

```bash
git clone https://github.com/snp-labs/zkap-circuit.git
cd zkap-circuit
cargo run -p zkap-service --example groth16_proof --release
```

> **`--release` is required.** Debug mode is orders of magnitude slower due to
> unoptimized field arithmetic.

## Expected Output

```
=== ZKAP Groth16 Proof Lifecycle Example ===

[Step 1] Creating circuit configuration (N=6, K=3)...
  Circuit params: JWT max=1024B, payload max=640B, tree_height=4

[Step 2] Running Groth16 trusted setup (CRS generation)...
  Setup complete: 9 public inputs, CRS written to /tmp/zkap-example

[Step 3] Generating 3 RSA-2048 keys and signing JWTs...
  JWT[0]: sub=user_0, signed with RSA-2048
  JWT[1]: sub=user_1, signed with RSA-2048
  JWT[2]: sub=user_2, signed with RSA-2048

[Step 4] Building issuer Merkle tree (height=4)...
  Tree root: 20702506484442991074...
  3 merkle proofs extracted

[Step 5] Generating threshold anchor (N=6, K=3)...
  Anchor: 4 evals, hanchor computed via generate_hash()

[Step 6] Generating 3 Groth16 proofs via prove() API...
  Proof 1/3 generated
  Proof 2/3 generated
  Proof 3/3 generated

[Step 7] Verifying proofs...
  Proof 1/3: VALID
  Proof 2/3: VALID
  Proof 3/3: VALID
  Tampered proof: INVALID (expected)

=== All steps completed successfully! ===
```

## What Each Step Does

The example exercises all 7 public API functions of `zkap-service`:

| Step | API Function(s) | What Happens |
|------|-----------------|--------------|
| 1 | `CircuitConfig::from(RawCircuitConfig)` | Build circuit parameters: N=6 total credentials, K=3 threshold, tree height 4 |
| 2 | **`setup()`** | Groth16 trusted setup — generates the 7-file bundle (`circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`, `Groth16Verifier.sol`, `config.json`, plus `manifest.json` from the CLI) |
| 3 | **`generate_hash()`** | Compute nonce = Poseidon(h_sign_user_op, random). Also generates 3 RSA-2048 key pairs and signs JWTs |
| 4 | **`generate_leaf_hash()`** | Compute Merkle leaf hash for each (issuer, RSA public key) pair, then build the Merkle tree |
| 5 | **`generate_anchor()`** + **`generate_hash()`** | Generate threshold anchor from N secrets (K real + N-K dummy), then chain-hash into hanchor |
| 6 | **`generate_aud_hash()`** + **`Prover::prove()`** | Compute audience hashes, assemble `ProofRequest`, generate K Groth16 proofs via `ArtifactSet::load` → `Prover::from_artifact` → `Prover::prove` |
| 7 | `Groth16::<Bn254>::verify_proof` | Verify each proof against public inputs by handing the bundled `PreparedVerifyingKey` borrow to `ark_groth16::Groth16::verify_proof`. Also demonstrates that a tampered proof fails |

## Understanding the Input Flow

The `ProofRequest` carries no artifact paths; the bundle reaches the
prover through `ArtifactSet::load(manifest, dir)`. Each field of the
request comes from a specific preparation step:

```
  setup() / cli generate_setup
    └→ dist/<shape>/{circuit.ar1cs, pk.bin, vk.bin, pvk.bin,
                     Groth16Verifier.sol, config.json, manifest.json}
       (loaded by `ArtifactSet::load(manifest, dir)`)

  RSA key generation + JWT signing
    ├→ per_jwt[i].jwt_bytes
    ├→ per_jwt[i].rsa_modulus_be       (RSA-2048 modulus, 256 BE bytes)
    └→ per_jwt[i].rsa_signature_be     (RSA-2048 signature, 256 BE bytes)

  generate_leaf_hash() → Merkle tree
    ├→ per_jwt[i].merkle_leaf_sibling_hash_be
    ├→ per_jwt[i].merkle_auth_path_be  (tree_height - 1 entries)
    ├→ per_jwt[i].merkle_leaf_idx
    └→ shared.merkle_root_be           (Merkle root, 32 BE bytes)

  generate_anchor() + generate_hash()
    ├→ shared.anchor_values_be         (n - k + 1 evaluations, 32 BE bytes each)
    ├→ shared.anchor_known_x_be        (k known x values)
    ├→ shared.anchor_selector          (n bytes, cardinality = k)
    └→ per_jwt[i].anchor_current_idx

  Application-specific
    ├→ shared.h_sign_user_op_be        (UserOperation binding)
    └→ shared.random_be                (blinding factor, must be non-zero)
```

## Using Pre-built CRS

The example runs `setup()` each time, but for repeated use you can
skip the trusted setup by loading the pre-built bundle from `dist/`:

- `dist/1-of-1/` — single-signer configuration (N=1, K=1)
- `dist/3-of-3/` — three-of-three configuration (N=3, K=3)

```rust
use std::path::Path;
use zkap_service::{ArtifactSet, Prover};
use zkap_service::manifest::Manifest;

let dir = Path::new("dist/1-of-1");
let manifest_bytes = std::fs::read(dir.join("manifest.json"))?;
let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
let set = ArtifactSet::load(&manifest, dir)?;          // single trust gate
let prover = Prover::from_artifact(set);
let proofs = prover.prove(&request, &mut rand::rngs::OsRng)?;
```

## Next Steps

- **Integrate into your project** — See [API Reference](API_REFERENCE.md)
  for detailed function signatures, parameters, error handling, and type specs.
- **Understand the circuit** — See [Circuit Design](CIRCUIT_DESIGN.md)
  for constraint structure and security properties.
- **Diagnose errors** — See [Troubleshooting](TROUBLESHOOTING.md)
  for common error messages and solutions.

## Source

[`crates/service/examples/groth16_proof.rs`](../crates/service/examples/groth16_proof.rs)
