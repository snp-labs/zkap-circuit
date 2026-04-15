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
| 2 | **`setup()`** | Groth16 trusted setup — generates pk.key, vk.key, pvk.key, Groth16Verifier.sol, config.json |
| 3 | **`generate_hash()`** | Compute nonce = Poseidon(h_sign_user_op, random). Also generates 3 RSA-2048 key pairs and signs JWTs |
| 4 | **`generate_leaf_hash()`** | Compute Merkle leaf hash for each (issuer, RSA public key) pair, then build the Merkle tree |
| 5 | **`generate_anchor()`** + **`generate_hash()`** | Generate threshold anchor from N secrets (K real + N-K dummy), then chain-hash into hanchor |
| 6 | **`generate_aud_hash()`** + **`prove()`** | Compute audience hashes, assemble `RawProofRequest`, generate K Groth16 proofs |
| 7 | **`verify()`** | Verify each proof against public inputs. Also demonstrates that a tampered proof fails |

## Understanding the Input Flow

Each input to `RawProofRequest` comes from a specific preparation step:

```
  setup()
    └→ pk_path                    (path to pk.key)

  RSA key generation + JWT signing
    ├→ jwts                       (K signed JWT strings)
    └→ pk_ops                     (K RSA moduli, Base64)

  generate_leaf_hash() → Merkle tree
    ├→ merkle_paths               (K authentication paths)
    ├→ leaf_indices               (K leaf positions)
    └→ root                       (Merkle root)

  generate_anchor() + generate_hash()
    ├→ anchor_evals               (N-K+1 polynomial evaluations)
    └→ hanchor                    (chain hash of anchor_evals)

  Application-specific
    ├→ user_op_hash               (UserOperation binding)
    └→ random                     (blinding factor)

  generate_aud_hash()
    └→ aud_hash_list              (per-audience hashes)
```

## Using Pre-built CRS

The example runs `setup()` each time, but for repeated use you can skip the
trusted setup by using pre-built CRS artifacts in `dist/`:

- `dist/1of1/` — single-signer configuration (N=1, K=1)
- `dist/3of3/` — three-of-three configuration (N=3, K=3)

Load the config and point `pk_path` to the pre-built `pk.key` file instead of
calling `setup()`.

## Next Steps

- **Integrate into your project** — See [API Reference](API_REFERENCE.md)
  for detailed function signatures, parameters, error handling, and type specs.
- **Understand the circuit** — See [Circuit Design](CIRCUIT_DESIGN.md)
  for constraint structure and security properties.
- **Diagnose errors** — See [Troubleshooting](TROUBLESHOOTING.md)
  for common error messages and solutions.

## Source

[`crates/service/examples/groth16_proof.rs`](../crates/service/examples/groth16_proof.rs)
