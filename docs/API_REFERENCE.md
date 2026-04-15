# API Reference

Public API of the `zkap-service` crate.

All functions return `Result<T, ApplicationError>`.
Field-element parameters accept decimal strings or `0x`-prefixed hex strings.

For the full proof lifecycle walkthrough, see the [Example Guide](EXAMPLE_GUIDE.md).

---

## Functions — Always Available

### `load_circuit_config`

```rust
pub fn load_circuit_config(path: &Path) -> Result<CircuitConfig, ApplicationError>
```

Load and validate a [`CircuitConfig`](#circuitconfig) from a JSON file.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `path` | `&Path` | Path to a JSON file in `RawCircuitConfig` format, or a `config.json` written by `setup()` |

**Errors:**
- `InvalidFormat` — File not found, invalid JSON, or validation failure (e.g. `k > n`, `tree_height < 1`).

**Example:**
```rust
use std::path::Path;
use zkap_service::load_circuit_config;

let config = load_circuit_config(Path::new("example.json"))?;
assert!(config.k <= config.n);
```

---

### `generate_hash`

```rust
pub fn generate_hash(messages: Vec<String>) -> Result<String, ApplicationError>
```

Compute a Poseidon hash of one or more field-element strings.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `messages` | `Vec<String>` | One or more field-element strings (hex or decimal) |

**Returns:** `0x`-prefixed hex string representing the hash result.

**Errors:**
- `InvalidFormat` — A string could not be parsed as a field element.

**Example:**
```rust
use zkap_service::generate_hash;

let h = generate_hash(vec!["42".into(), "123".into()])?;
assert!(h.starts_with("0x"));

// Deterministic: same inputs always produce the same hash
let h2 = generate_hash(vec!["42".into(), "123".into()])?;
assert_eq!(h, h2);
```

**Lifecycle context:** Used in Step 3 (nonce = Poseidon(h_sign_user_op, random)) and Step 5 (hanchor chain hash of anchor evaluations).

---

### `generate_aud_hash`

```rust
pub fn generate_aud_hash(
    params: &CircuitConfig,
    aud_list: Vec<String>,
) -> Result<AudHashResult, ApplicationError>
```

Compute per-audience Poseidon hashes and a combined audience-list hash.

Each audience string is padded to `params.max_aud_len` and individually hashed. The list is padded with `params.forbidden_string` up to `params.num_audience_limit`. All individual hashes are then hashed together to produce `h_aud_list`.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `params` | `&CircuitConfig` | Circuit configuration |
| `aud_list` | `Vec<String>` | Audience strings (must include JSON quotes if circuit extracts with quotes) |

**Returns:** [`AudHashResult`](#audhashresult) with `individual` hashes and `combined` hash.

**Errors:**
- `InvalidFormat` — `aud_list.len()` exceeds `params.num_audience_limit`.

**Example:**
```rust
use zkap_service::{generate_aud_hash, load_circuit_config};
use std::path::Path;

let config = load_circuit_config(Path::new("example.json"))?;
let result = generate_aud_hash(&config, vec!["\"my-audience\"".into()])?;
// Padded to num_audience_limit
assert_eq!(result.individual.len(), config.num_audience_limit as usize);
assert!(result.combined.starts_with("0x"));
```

**Lifecycle context:** Used in Step 6. Pass `result.individual` as `aud_hash_list` in `RawProofRequest`.

---

### `generate_leaf_hash`

```rust
pub fn generate_leaf_hash(
    params: &CircuitConfig,
    iss: &str,
    pk_b64: &str,
) -> Result<String, ApplicationError>
```

Compute a Merkle tree leaf hash from an (issuer, RSA public key) pair.

The issuer string is padded to `params.max_iss_len`. The Base64-encoded RSA modulus is decoded and converted to BigNat limbs. Both are concatenated and hashed with Poseidon.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `params` | `&CircuitConfig` | Circuit configuration |
| `iss` | `&str` | Issuer string. **Must include JSON quotes** if the circuit extracts claims with quotes (e.g. `"\"https://accounts.google.com\""`) |
| `pk_b64` | `&str` | RSA public key modulus, Base64-encoded |

**Returns:** `0x`-prefixed hex string (leaf field element).

**Errors:**
- `InvalidFormat` — Invalid Base64 in `pk_b64`.

**Example:**
```rust
use zkap_service::{generate_leaf_hash, load_circuit_config};
use std::path::Path;

let config = load_circuit_config(Path::new("example.json"))?;
let leaf = generate_leaf_hash(&config, "\"https://accounts.google.com\"", &pk_b64)?;
assert!(leaf.starts_with("0x"));
```

**Lifecycle context:** Used in Step 4 to compute leaf hashes for building the issuer Merkle tree.

---

### `generate_anchor`

```rust
pub fn generate_anchor(
    params: &CircuitConfig,
    secrets: Vec<Secret>,
) -> Result<GenerateAnchorResCore, ApplicationError>
```

Generate threshold anchor polynomial evaluations from JWT claim secrets.

Each [`Secret`](#secret)'s `(sub, iss, aud)` is hashed via Poseidon into a scalar `x`. The resulting `x` values are combined using the Vandermonde-based anchor scheme to produce polynomial evaluations. The anchor encodes threshold membership without revealing which K of the N credentials were used.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `params` | `&CircuitConfig` | Circuit configuration (uses `n`, `k`, max claim lengths) |
| `secrets` | `Vec<Secret>` | Exactly N secrets (K real + N-K dummy). **Claim values must include JSON quotes** |

**Returns:** [`GenerateAnchorResCore`](#generateanchorrescore) with N-K+1 anchor evaluations (hex strings).

**Errors:**
- `InvalidFormat` — Claim padding exceeds max length.
- `CryptographicError` — Anchor scheme failure (e.g. dimension mismatch).

**Example:**
```rust
use zkap_service::{generate_anchor, load_circuit_config, Secret};
use std::path::Path;

let config = load_circuit_config(Path::new("example.json"))?;
let secrets = vec![
    Secret { sub: "\"user_0\"".into(), iss: "\"https://issuer.com\"".into(), aud: "\"my-app\"".into() },
    Secret { sub: "\"user_1\"".into(), iss: "\"https://issuer.com\"".into(), aud: "\"my-app\"".into() },
    Secret { sub: "\"user_2\"".into(), iss: "\"https://issuer.com\"".into(), aud: "\"my-app\"".into() },
    // ... N-K dummy secrets
];
let result = generate_anchor(&config, secrets)?;
// result.anchor has N-K+1 evaluations
```

**Lifecycle context:** Used in Step 5. After generating the anchor, compute `hanchor` by chaining `generate_hash()` calls over the evaluations:

```rust
let mut hanchor = generate_hash(vec![result.anchor[0].clone()])?;
for v in &result.anchor[1..] {
    hanchor = generate_hash(vec![hanchor, v.clone()])?;
}
```

---

## Functions — `proof` Feature (default)

These functions are only available when the `proof` feature is enabled (it is enabled by default).

### `setup`

```rust
pub fn setup(
    params: &CircuitConfig,
    output_dir: &Path,
) -> Result<SetupOutput, ApplicationError>
```

Perform Groth16 trusted setup and persist all artifacts to `output_dir`.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `params` | `&CircuitConfig` | Circuit configuration |
| `output_dir` | `&Path` | Directory to write CRS artifacts |

**Output files:**

| File | Contents |
|------|----------|
| `pk.key` | Proving key (uncompressed binary) |
| `vk.key` | Verifying key (uncompressed binary) |
| `pvk.key` | Prepared verifying key (uncompressed binary) |
| `Groth16Verifier.sol` | Solidity on-chain verifier contract |
| `config.json` | Input `params` serialized as JSON |

**Returns:** [`SetupOutput`](#setupoutput) for immediate use with `prove()` and `verify()`.

**Errors:**
- `InvalidFormat` — Groth16 setup failed.

**Lifecycle context:** Step 2 — run once per configuration. For pre-built keys, see `dist/` in the repository root.

---

### `prove`

```rust
pub fn prove(
    params: &CircuitConfig,
    raw: RawProofRequest,
) -> Result<ZkapProofResult, ApplicationError>
```

Generate Groth16 proofs via a 4-step internal pipeline:

1. **Validate & parse** — `RawProofRequest` → `ProofRequest`: checks vector lengths, parses field elements and JWT tokens.
2. **Build context** — Constructs anchor and audience contexts.
3. **Build circuit inputs** — Assembles one `ZkapCircuitInput` per JWT token.
4. **Generate proofs** — Runs `Groth16::prove` for each circuit input.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `params` | `&CircuitConfig` | Circuit configuration (must match the one used in `setup()`) |
| `raw` | `RawProofRequest` | See [`RawProofRequest`](#rawproofrequest) |

**Returns:** [`ZkapProofResult`](#zkapproofresult) containing K proofs and public inputs.

**Errors:**
- `InvalidFormat` — Vector length mismatch (e.g. `jwts.len() != K`), invalid field element string, JWT parsing failure.
- `ProofGenerationFailed` — Groth16 proving failed (constraint not satisfied, proving key mismatch).

**Lifecycle context:** Step 6 — the core proof generation call.

---

### `verify`

```rust
pub fn verify(
    ctx: &VerifyingContext,
    proof: &ProofComponents,
    public_inputs: &[String],
) -> Result<bool, ApplicationError>
```

Verify a single Groth16 proof against public inputs.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `ctx` | `&VerifyingContext` | From `SetupOutput::verifying_context()` |
| `proof` | `&ProofComponents` | A single proof from `ZkapProofResult::proofs` |
| `public_inputs` | `&[String]` | 8-element hex string array. Use `ZkapProofResult::public_inputs_for(index)` to construct |

**Returns:** `true` if valid, `false` if invalid.

**Errors:**
- `ParseError` — A public input string could not be parsed as a field element.
- `InvalidFormat` — Verifier internal failure.

**Lifecycle context:** Step 7 — verify each of the K proofs individually.

---

## Types

### `CircuitConfig`

Runtime circuit parameters. Load from JSON via `load_circuit_config()` or construct from `RawCircuitConfig` via `Into`.

| Field | Type | Description |
|-------|------|-------------|
| `n` | `u64` | Total number of credentials (N) |
| `k` | `u64` | Threshold — minimum credentials required (K) |
| `max_jwt_b64_len` | `u64` | Maximum JWT length in Base64 bytes |
| `max_payload_b64_len` | `u64` | Maximum payload length in Base64 bytes |
| `max_aud_len` | `u64` | Maximum `aud` claim length |
| `max_exp_len` | `u64` | Maximum `exp` claim length |
| `max_iss_len` | `u64` | Maximum `iss` claim length |
| `max_nonce_len` | `u64` | Maximum `nonce` claim length |
| `max_sub_len` | `u64` | Maximum `sub` claim length |
| `tree_height` | `u64` | Merkle tree height (supports up to 2^h issuers) |
| `num_audience_limit` | `u64` | Maximum audience list size |
| `claims` | `Vec<Vec<u8>>` | JWT claim names to extract |
| `forbidden_string` | `Vec<u8>` | Padding / injection guard string |

**Validation rules** (enforced by `validate()`):
- `k >= 1`, `k <= n`, `n >= 1`
- `tree_height >= 1`
- `max_payload_b64_len <= max_jwt_b64_len`
- `num_audience_limit >= 1`
- `claims` must be non-empty

**JSON format** (`RawCircuitConfig`): String-typed fields (`claims` as `Vec<String>`, `forbidden_string` as `String`). See [`example.json`](../example.json) for a complete example.

---

### `RawProofRequest`

Unvalidated proof request received from the outside world. All fields are strings for cross-platform compatibility.

| Field | Type | Cardinality | Description |
|-------|------|-------------|-------------|
| `pk_path` | `PathBuf` | 1 | Path to proving key file (pk.key from `setup()`) |
| `jwts` | `Vec<String>` | K | JWT token strings |
| `pk_ops` | `Vec<String>` | K | RSA public key moduli (Base64-encoded) |
| `merkle_paths` | `Vec<Vec<String>>` | K | Merkle authentication paths (field-element strings) |
| `leaf_indices` | `Vec<u64>` | K | Merkle leaf indices |
| `root` | `String` | 1 | Merkle root (hex or decimal field-element string) |
| `anchor_evals` | `Vec<String>` | N-K+1 | Anchor polynomial evaluations from `generate_anchor()` |
| `hanchor` | `String` | 1 | Chain hash of `anchor_evals` via `generate_hash()` |
| `user_op_hash` | `String` | 1 | Signed UserOperation hash (hex or decimal) |
| `random` | `String` | 1 | Blinding factor (hex or decimal, must be non-zero) |
| `aud_hash_list` | `Vec<String>` | variable | Per-audience hashes from `generate_aud_hash().individual` |

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `new(...)` | `Self` | Construct from all fields (no validation) |
| `token_count()` | `usize` | Number of JWT tokens |

---

### `Secret`

JWT claim triple for anchor generation. Implements `serde::Serialize` + `Deserialize`.

| Field | Type | Description |
|-------|------|-------------|
| `sub` | `String` | JWT subject claim (with JSON quotes) |
| `iss` | `String` | JWT issuer claim (with JSON quotes) |
| `aud` | `String` | JWT audience claim (with JSON quotes) |

---

### `SetupOutput`

Output of `setup()`. Not serializable — use the persisted key files for storage.

| Method | Returns | Description |
|--------|---------|-------------|
| `verifying_context()` | `VerifyingContext` | Opaque handle for `verify()` |
| `public_input_count()` | `usize` | Number of public inputs in the verifying key (includes constant "1" element) |

---

### `VerifyingContext`

Opaque handle wrapping a Groth16 prepared verifying key. Obtained from `SetupOutput::verifying_context()`. Not serializable — intended for in-process use only.

---

### `ProofComponents`

Groth16 proof in Solidity-compatible hex string format. Implements `serde::Serialize` + `Deserialize`.

| Field | Type | Description |
|-------|------|-------------|
| `a` | `[String; 2]` | BN254 G1 affine point `[x, y]` |
| `b` | `[String; 4]` | BN254 G2 affine point `[bx_c1, bx_c0, by_c1, by_c0]` |
| `c` | `[String; 2]` | BN254 G1 affine point `[x, y]` |

---

### `ZkapProofResult`

Complete proof output. Implements `serde::Serialize` + `Deserialize`.

| Field | Type | Description |
|-------|------|-------------|
| `proofs` | `Vec<ProofComponents>` | K proof components |
| `shared_inputs` | `Vec<String>` | 6 shared public inputs: `[hanchor, h_a, root, h_sign_user_op, lhs, h_aud_list]` |
| `jwt_exp_list` | `Vec<String>` | Per-proof JWT expiration timestamps |
| `verification_rhs_list` | `Vec<String>` | Per-proof verification RHS values |

| Method | Returns | Description |
|--------|---------|-------------|
| `public_inputs_for(index)` | `Vec<String>` | Reconstruct 8-element public input vector for proof at `index` |

**Public input layout** (8 elements, order matters for on-chain verification):

```
[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]
 ─────────────shared_inputs──────────────────  ──per-proof──  ──shared──
         [0]   [1]   [2]        [3]               [4]    [5]     [4]     [5]
                                                   ↑      ↑       ↑       ↑
                                             jwt_exp_list  │  shared[4] shared[5]
                                                   verification_rhs_list
```

---

### `AudHashResult`

Audience hash result. Implements `serde::Serialize` + `Deserialize`.

| Field | Type | Description |
|-------|------|-------------|
| `individual` | `Vec<String>` | Per-audience Poseidon hashes (hex strings, padded to `num_audience_limit`) |
| `combined` | `String` | Combined hash of all individual hashes (h_aud_list, hex string) |

---

### `GenerateAnchorResCore`

Anchor generation result.

| Field | Type | Description |
|-------|------|-------------|
| `anchor` | `Vec<String>` | N-K+1 anchor polynomial evaluations (hex strings) |

---

### `ApplicationError`

Top-level error enum. All public functions return this type.

| Variant | Description |
|---------|-------------|
| `InvalidFormat(String)` | Input format or parameter violation |
| `InternalError` | Internal processing error |
| `Other(String)` | Miscellaneous error |
| `CryptographicError(String)` | Cryptographic operation failed |
| `PoseidonHashError` | Poseidon hash evaluation failed |
| `FieldParsingError(FieldParseError)` | Field element parsing failed |
| `TextEncodingError(String)` | Text encoding error |
| `ParseError(String)` | General parse error |
| `ProofGenerationFailed(String)` | Groth16 proving failed |
| `VerifyFailed` | Proof verification failed |

---

## Feature Flags

| Feature | Default | Effect |
|---------|---------|--------|
| `proof` | **on** | Enables `setup`, `prove`, `verify` and heavyweight arkworks dependencies |
| `use-optimized` | off | Streaming prover for memory-constrained environments (e.g. iOS) |

Without `proof`: only hash/anchor functions, data types, and `load_circuit_config` are available. Use this for platforms where proof generation happens server-side.

```toml
# Full build (default)
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit" }

# Lightweight build (no proving)
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit", default-features = false }
```
