# Troubleshooting

Common errors and their solutions when working with zkap-circuit.

## Build Errors

### `error[E0658]: edition 2024 is not yet stable`

**Cause:** Rust version is too old.
**Fix:** Install a stable Rust toolchain satisfying the workspace MSRV (`1.86`;
`rustup update stable`).

### Linker errors on macOS (Apple Silicon)

**Cause:** Missing Xcode command-line tools.
**Fix:** `xcode-select --install`

## Runtime Errors

### Extremely slow execution / hangs during setup or prove

**Cause:** Running in debug mode.
**Fix:** Always use `--release`. Debug field arithmetic is orders of magnitude slower than release mode.

Use `cargo run --release ...` for CLI/setup commands and release-profile test
commands for prove-heavy paths.

### `All input vectors must have length K=...`

**Cause:** `ProofRequest::credentials.len()` does not match `config.k`.
**Fix:** Ensure `credentials` has exactly K entries.

### `invalid prove request at anchor: ...`

**Cause:** `ProveRequest::anchor` length does not equal N - K + 1.
**Fix:** Check that `generate_anchor()` output has the correct number of
`anchor_evaluations` for your `(n, k)` configuration. For example, with N=6
and K=3, `anchor_evaluations` must have 4 entries.

### `JWT parsing failed`

**Cause:** Invalid JWT format or missing required claims.
**Fix:** Verify that the JWT:
- Is a valid `header.payload.signature` string (Base64url-encoded, dot-separated)
- Contains all claims listed in `config.claims` (default: `aud`, `exp`, `iss`, `nonce`, `sub`)
- Uses RS256 algorithm (`{"alg":"RS256","typ":"JWT"}`)

### `Input audience count (...) exceeds the limit (...)`

**Cause:** `AudienceHashRequest::audiences` passed to `generate_audience_hashes()` has more entries than `config.num_audience_limit`.
**Fix:** Reduce the audience list or increase `num_audience_limit` in the config. Changing `num_audience_limit` requires re-running `setup()` to generate new CRS artifacts.

### `Proof generation failed` / constraint not satisfied

**Cause:** Circuit witness is inconsistent with public inputs. This is the most common proof failure.
**Fix:** Check each of these in order:

1. **Raw claim / quote boundary mismatch** — helper APIs expect raw claim strings and add JSON quotes internally. Do not pre-wrap values in escaped quotes. See [Claim Quote Boundary](#claim-quote-boundary) below.
2. **Merkle root mismatch** — The `merkle_root` in `ProveRequest` must match the tree built from `generate_issuer_key_hash()` results.
3. **Anchor mismatch** — `ProveRequest::anchor` must come from `generate_anchor().anchor_evaluations`.
4. **Audience hash mismatch** — Audience public inputs must come from `generate_audience_hashes().audience_hashes` and `.audience_list_hash`.
5. **Config mismatch** — `ArtifactSet::cfg` must be the config used during setup.

### `Groth16::verify_proof` returns `false`

**Cause:** Public inputs do not match those embedded in the proof.
**Fix:** Use `ProveResponse::public_inputs_for(index)` to construct the correct 8-element input vector. Do not reorder, omit, or modify elements.

```rust
// Correct
let input_hex = prove_response.public_inputs_for(0);
let inputs = decode_public_inputs(input_hex)?;
let valid = ark_groth16::Groth16::<BN254>::verify_proof(&set.pvk, &proof, &inputs)?;

// Wrong — manually constructing inputs risks ordering errors
let inputs = vec![hanchor, root, ...];
```

### `Failed to read config` / `Failed to parse config`

**Cause:** The JSON config file is missing, malformed, or contains invalid values.
**Fix:** Verify the file exists and matches the `RawCircuitConfig` schema. See [`example.json`](../example.json) for a complete example.

## Claim Quote Boundary

The circuit extracts JWT claim values with JSON quote characters. Current
service helper APIs accept **raw** claim values and add those quotes internally:

```rust
use zkap_service::{
    AnchorSecret, AudienceHashRequest, IssuerKeyHashRequest,
    generate_audience_hashes, generate_issuer_key_hash,
};

// Correct — raw values, no escaped JSON quotes.
let secret = AnchorSecret {
    subject: "user_0".into(),
    issuer: "https://accounts.google.com".into(),
    audience: "my-app".into(),
};
let aud = AudienceHashRequest { audiences: vec!["my-app".into()] };
let leaf = IssuerKeyHashRequest {
    issuer: "https://accounts.google.com".into(),
    rsa_modulus_b64,
};
```

Do not pass values like `"\"my-app\""`. That double-quotes the claim relative
to the circuit and can cause proof failures.

## Getting Help

If the above does not resolve your issue, open a GitHub issue:

- [Bug report](https://github.com/snp-labs/zkap-circuit/issues/new?template=bug_report.md) — for general bugs
- [Proof failure report](https://github.com/snp-labs/zkap-circuit/issues/new?template=proof_failure.md) — for proof generation or verification failures (includes environment and config fields)
