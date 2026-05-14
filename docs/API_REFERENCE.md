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

**Lifecycle context:** Used in Step 6. Pass `result.individual` as the audience-hash list when assembling the per-JWT byte buffers that flow into `ProofRequest`.

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
    rng: &mut dyn rand::RngCore,
    ptau: Option<&Path>,
) -> Result<SetupOutput, ApplicationError>
```

Perform Groth16 trusted setup and persist the 7-file CRS bundle to `output_dir`.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `params` | `&CircuitConfig` | Circuit configuration |
| `output_dir` | `&Path` | Directory to write CRS artifacts |
| `rng` | `&mut dyn RngCore` | Caller-supplied randomness (`OsRng` in production, `ChaCha20Rng` from a fixed seed for reproducible CI runs) |
| `ptau` | `Option<&Path>` | Stage-2 placeholder; always `None` today, returns an explicit error if `Some(_)` |

**Output files** (6 written by `setup` itself; `manifest.json` is added by the `generate_setup` CLI binary):

| File | Contents |
|------|----------|
| `circuit.ar1cs` | R1CS matrices in ark-ar1cs canonical envelope (`ArcsFile`) |
| `pk.bin` | Proving key — arkworks `CanonicalSerialize` uncompressed |
| `vk.bin` | Verifying key — arkworks `CanonicalSerialize` uncompressed |
| `pvk.bin` | Prepared verifying key — arkworks `CanonicalSerialize` uncompressed |
| `Groth16Verifier.sol` | Solidity on-chain verifier contract |
| `config.json` | Input `params` serialized as JSON |

**Returns:** [`SetupOutput`](#setupoutput) for immediate use (e.g. through `SetupOutput::into_artifact_set()` → `Prover::from_artifact`).

**Errors:**
- `InvalidFormat` — Groth16 setup failed, or `ptau = Some(_)`.

**Lifecycle context:** Step 2 — run once per configuration. For pre-built bundles, see `dist/` in the repository root.

---

### `Prover` (native ar1cs prove flow)

```rust
pub struct Prover { /* pk, vk, pvk, arcs, cfg */ }

impl Prover {
    pub fn from_artifact(set: ArtifactSet) -> Self;

    pub fn prove<R: Rng + CryptoRng>(
        &self,
        req: &ProofRequest,
        rng: &mut R,
    ) -> Result<ZkapProofResult, ApplicationError>;

    pub fn verifying_key(&self) -> &VerifyingKey<BN254>;
    pub fn prepared_verifying_key(&self) -> &PreparedVerifyingKey<BN254>;
    pub fn circuit_config(&self) -> &CircuitConfig;
}
```

Canonical post-migration prove entry point. Internally chains:

1. `witness::build_input(&req, &self.cfg)` → `Vec<ZkapInputV1>`
2. `witness::into_circuit_input(v1)` → `ZkapCircuitInput<F>`
3. `ZkapCircuit::from_input(circuit_input)` → `ConstraintSynthesizer`
4. `ark_ar1cs::synthesize_full_assignment(circuit)` → `[F::ONE, instance…, witness…]`
5. `ark_ar1cs::prove(&self.pk, &self.arcs, &full_assignment, rng)` → `Proof<BN254>`

**Trust gating** lives entirely in [`ArtifactSet::load`](#artifactsetload). `Prover::prove` performs no manifest lookup, no `arcs.body_blake3` recompute, and no sha256 re-check. The `Manifest`/`hash` validation is the loader's job; `Prover` trusts the set that built it.

**Returns:** [`ZkapProofResult`](#zkapproofresult) containing K proofs and public inputs.

**Errors:**
- `InvalidFormat` — `ProofRequest` shape mismatch surfaced through `ZkapWitnessError` (anchor cardinality, RSA length, JWT decode, …).
- `ProofGenerationFailed` — `synthesize_full_assignment` failed or `ark_ar1cs::prove` rejected the assignment at R1CS preflight.

**Non-canonical shortcut:**

```rust
pub fn prove_from_unverified_paths<R: Rng + CryptoRng>(
    bundle_dir: &Path,
    req: &ProofRequest,
    rng: &mut R,
) -> Result<ZkapProofResult, ApplicationError>;
```

Loads `pk.bin`, `vk.bin`, `pvk.bin`, `circuit.ar1cs`, `config.json` from `bundle_dir` via [`ArtifactSet::load_unverified`](#artifactset) (no manifest hash gating) and forwards to `Prover::from_artifact` + `Prover::prove`. **Tests / dev tools only**; production callers MUST use `ArtifactSet::load(manifest, dir)` + `Prover::from_artifact` + `Prover::prove`.

---

### Verifying a proof

There is no `zkap_service::verify` wrapper — call `ark_groth16::Groth16::verify_proof` directly:

```rust
use ark_groth16::Groth16;
use circuit::types::BN254;

let pvk = prover.prepared_verifying_key();          // or set.pvk, or setup_output.prepared_verifying_key()
let proof: Proof<BN254>          = /* from Prover::prove via dto reconstruction */;
let public_inputs: Vec<F>        = /* per-proof 8-element instance vector */;
let ok = Groth16::<BN254>::verify_proof(pvk, &proof, &public_inputs)?;
```

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

### `ProofRequest` / `SharedFields` / `PerJwtFields`

Native-path proof request — carries **no** artifact paths. The post-migration request describes only the credentials being proven; the CRS bundle reaches the prover through [`ArtifactSet::load`](#artifactsetload) (canonical) or `ArtifactSet::load_unverified` (non-canonical shortcut).

```rust
pub struct ProofRequest {
    pub shared: SharedFields,
    pub per_jwt: Vec<PerJwtFields>,
}

pub struct SharedFields {
    pub random_be: [u8; 32],
    pub h_sign_user_op_be: [u8; 32],
    pub anchor_values_be: Vec<[u8; 32]>,       // len = n - k + 1
    pub anchor_known_x_be: Vec<[u8; 32]>,      // len = k
    pub anchor_selector: Vec<u8>,              // len = n, cardinality = k
    pub merkle_root_be: [u8; 32],
}

pub struct PerJwtFields {
    pub jwt_bytes: Vec<u8>,
    pub rsa_modulus_be: Vec<u8>,               // exactly 256 bytes
    pub rsa_signature_be: Vec<u8>,             // exactly 256 bytes
    pub anchor_current_idx: u64,
    pub merkle_leaf_sibling_hash_be: [u8; 32],
    pub merkle_auth_path_be: Vec<[u8; 32]>,    // len = tree_height - 1
    pub merkle_leaf_idx: u64,
}
```

`ProofRequest::validate(k, n)` re-applies the shape invariants; the same checks run again inside `witness::build_input` and `witness::into_circuit_input` defensively.

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

Output of `setup()`. Not serializable — use the persisted bundle files for storage. Convert to an [`ArtifactSet`](#artifactsetload) in-memory via `SetupOutput::into_artifact_set()` to feed `Prover::from_artifact` without going through disk.

| Method | Returns | Description |
|--------|---------|-------------|
| `prepared_verifying_key()` | `&PreparedVerifyingKey<BN254>` | Borrow for direct `Groth16::verify_proof` calls |
| `public_input_count()` | `usize` | Number of public inputs in the verifying key (includes constant "1" element) |
| `into_artifact_set()` | `ArtifactSet` | Hand `(pk, vk, pvk, arcs, cfg)` straight to `Prover::from_artifact` |

---

### `ArtifactSet::load`

```rust
pub struct ArtifactSet {
    pub pk:   ProvingKey<BN254>,
    pub vk:   VerifyingKey<BN254>,
    pub pvk:  PreparedVerifyingKey<BN254>,
    pub arcs: ArcsFile<F>,
    pub cfg:  CircuitConfig,
}

impl ArtifactSet {
    pub fn load(manifest: &Manifest, dir: &Path) -> Result<Self, ArtifactError>;
    pub fn load_unverified(dir: &Path)            -> Result<Self, ArtifactError>;
}
```

Manifest-validated CRS bundle loader. `load(manifest, dir)` is the **single trust gate** for the prove path; it asserts:

* `ArcsFile::read(circuit.ar1cs)` succeeds.
* `arcs.body_blake3() == manifest.ar1cs_blake3`.
* `sha256(circuit.ar1cs / pk.bin / vk.bin / pvk.bin / config.json) == manifest.artifacts.<slot>.sha256`.
* If `manifest.artifacts.evm_verifier` is `Some`, `sha256(Groth16Verifier.sol) == manifest.artifacts.evm_verifier.sha256`.

Any disagreement returns `ArtifactError::HashMismatch { field, expected, got }` with the failing manifest path named in `field`.

`load_unverified(dir)` is the non-canonical, caller-trusted shortcut: it reads the same files but runs **no** sha256 / `ar1cs_blake3` / `evm_verifier` validation. Use only in tests, dev tools, and caller-trusted environments.

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
| `proof` | **on** | Enables `setup`, `Prover`, `ArtifactSet`, and the heavyweight `ark-ar1cs` / `ark-groth16` dependencies |

Without `proof`: only hash/anchor functions, data types, and `load_circuit_config` are available. Use this for platforms where proof generation happens server-side.

```toml
# Full build (default)
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit" }

# Lightweight build (no proving)
zkap-service = { git = "https://github.com/snp-labs/zkap-circuit", default-features = false }
```
