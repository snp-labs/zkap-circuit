# Troubleshooting

Common errors and their solutions when working with zkap-circuit.

## Build Errors

### `error[E0658]: edition 2024 is not yet stable`

**Cause:** Rust version is too old.
**Fix:** Install Rust 1.85+ (`rustup update stable`).

### Linker errors on macOS (Apple Silicon)

**Cause:** Missing Xcode command-line tools.
**Fix:** `xcode-select --install`

## Runtime Errors

### Extremely slow execution / hangs during setup or prove

**Cause:** Running in debug mode.
**Fix:** Always use `--release`. Debug field arithmetic is orders of magnitude slower than release mode.

```bash
# Wrong — will be extremely slow
cargo run --example groth16_proof

# Correct
cargo run -p zkap-service --example groth16_proof --release
```

### `All input vectors must have length K=...`

**Cause:** `ProofRequest` vector field lengths do not match `config.k`.
**Fix:** Ensure `jwts`, `pk_ops`, `merkle_paths`, and `leaf_indices` all have exactly K entries.

### `Invalid anchor_evals length: expected ..., got ...`

**Cause:** `anchor_evals` length does not equal N - K + 1.
**Fix:** Check that `generate_anchor()` output has the correct number of evaluations for your `(n, k)` configuration. For example, with N=6 and K=3, `anchor_evals` must have 4 entries.

### `JWT parsing failed`

**Cause:** Invalid JWT format or missing required claims.
**Fix:** Verify that the JWT:
- Is a valid `header.payload.signature` string (Base64url-encoded, dot-separated)
- Contains all claims listed in `config.claims` (default: `aud`, `exp`, `iss`, `nonce`, `sub`)
- Uses RS256 algorithm (`{"alg":"RS256","typ":"JWT"}`)

### `Input audience count (...) exceeds the limit (...)`

**Cause:** `aud_list` passed to `generate_aud_hash()` has more entries than `config.num_audience_limit`.
**Fix:** Reduce the audience list or increase `num_audience_limit` in the config. Changing `num_audience_limit` requires re-running `setup()` to generate new CRS artifacts.

### `Proof generation failed` / constraint not satisfied

**Cause:** Circuit witness is inconsistent with public inputs. This is the most common proof failure.
**Fix:** Check each of these in order:

1. **JSON quote mismatch** — The circuit extracts JWT claim values with surrounding `"` characters. All hash inputs must match. See [JSON Quote Gotcha](#json-quote-gotcha) below.
2. **Merkle root mismatch** — The `root` in `ProofRequest` must match the tree built from `generate_leaf_hash()` results.
3. **hanchor mismatch** — `hanchor` must be the chain hash of `anchor_evals` computed via `generate_hash()`.
4. **Audience hash mismatch** — `aud_hash_list` must come from `generate_aud_hash().individual`.
5. **Config mismatch** — The `CircuitConfig` passed to `prove()` must be identical to the one used in `setup()`.

### `verify()` returns `false`

**Cause:** Public inputs do not match those embedded in the proof.
**Fix:** Use `ZkapProofResult::public_inputs_for(index)` to construct the correct 8-element input vector. Do not reorder, omit, or modify elements.

```rust
// Correct
let inputs = proof_result.public_inputs_for(0);
let valid = verify(&ctx, &proof_result.proofs[0], &inputs)?;

// Wrong — manually constructing inputs risks ordering errors
let inputs = vec![hanchor, root, ...];
```

### `Failed to read config` / `Failed to parse config`

**Cause:** The JSON config file is missing, malformed, or contains invalid values.
**Fix:** Verify the file exists and matches the `RawCircuitConfig` schema. See [`example.json`](../example.json) for a complete example.

## JSON Quote Gotcha

The circuit extracts JWT claim values **with JSON quote characters**. When using `generate_leaf_hash()`, `generate_anchor()`, and `generate_aud_hash()`, claim values must be wrapped in escaped quotes:

```rust
// Correct — matches what the circuit extracts from the JWT payload
let iss = "\"https://accounts.google.com\"";
let secret = Secret {
    sub: "\"user_0\"".into(),
    iss: "\"https://accounts.google.com\"".into(),
    aud: "\"my-app\"".into(),
};

// Wrong — will produce different hashes, causing proof failure
let iss = "https://accounts.google.com";
let secret = Secret {
    sub: "user_0".into(),       // missing quotes
    iss: "issuer".into(),       // missing quotes
    aud: "my-app".into(),       // missing quotes
};
```

This is the single most common cause of proof generation failures. If `prove()` returns a constraint error, check quotes first.

## Getting Help

If the above does not resolve your issue, open a GitHub issue:

- [Bug report](https://github.com/snp-labs/zkap-circuit/issues/new?template=bug_report.md) — for general bugs
- [Proof failure report](https://github.com/snp-labs/zkap-circuit/issues/new?template=proof_failure.md) — for proof generation or verification failures (includes environment and config fields)
