# API Reference

Public API of the `zkap-service` crate.

The current service surface is always available after the 2026-05 refactor:
the old `proof` / `dev-unverified-artifacts` feature split was removed.

For the proof lifecycle, see [Example Guide](EXAMPLE_GUIDE.md).

## Helper Functions

### `load_circuit_config`

```rust
pub fn load_circuit_config(path: &Path) -> Result<CircuitConfig, ApplicationError>
```

Loads a JSON `CircuitConfig` and runs `CircuitConfig::validate()`.

### `generate_poseidon_hash`

```rust
pub fn generate_poseidon_hash(
    request: HashRequest,
) -> Result<HashResponse, ApplicationError>
```

Computes a Poseidon hash over field-element strings. Each input accepts either
`0x`-prefixed lowercase big-endian hex or decimal.

```rust
use zkap_service::{HashRequest, generate_poseidon_hash};

let result = generate_poseidon_hash(HashRequest {
    field_elements: vec!["0x1".into(), "42".into()],
})?;
assert!(result.hash.starts_with("0x"));
```

### `generate_audience_hashes`

```rust
pub fn generate_audience_hashes(
    config: &CircuitConfig,
    request: AudienceHashRequest,
) -> Result<AudienceHashResponse, ApplicationError>
```

Computes one Poseidon hash per audience slot and a combined
`audience_list_hash`. Inputs are raw audience strings; the service adds JSON
quotes internally before padding/hashing so the bytes match the circuit's JWT
claim extraction.

```rust
use zkap_service::{AudienceHashRequest, generate_audience_hashes};

let result = generate_audience_hashes(
    &config,
    AudienceHashRequest {
        audiences: vec!["my-client-id".into()],
    },
)?;
assert_eq!(result.audience_hashes.len(), config.num_audience_limit as usize);
```

### `generate_issuer_key_hash`

```rust
pub fn generate_issuer_key_hash(
    config: &CircuitConfig,
    request: IssuerKeyHashRequest,
) -> Result<IssuerKeyHashResponse, ApplicationError>
```

Computes the issuer-key Merkle leaf hash for an issuer plus RSA-2048 modulus.
`issuer` is a raw string; the service adds JSON quotes internally.
`rsa_modulus_b64` must decode to exactly 256 bytes.

```rust
use zkap_service::{IssuerKeyHashRequest, generate_issuer_key_hash};

let leaf = generate_issuer_key_hash(
    &config,
    IssuerKeyHashRequest {
        issuer: "https://accounts.example".into(),
        rsa_modulus_b64: rsa_n_b64,
    },
)?;
assert!(leaf.hash.starts_with("0x"));
```

### `generate_anchor`

```rust
pub fn generate_anchor(
    config: &CircuitConfig,
    request: GenerateAnchorRequest,
) -> Result<GenerateAnchorResponse, ApplicationError>
```

Generates threshold anchor polynomial evaluations and their sequential
Poseidon chain hash `hanchor`.

`request.secrets.len()` must equal `config.n`. `AnchorSecret` fields are raw
claim strings; the service adds JSON quotes internally.

```rust
use zkap_service::{
    AnchorSecret, GenerateAnchorRequest, generate_anchor,
};

let anchor = generate_anchor(
    &config,
    GenerateAnchorRequest {
        secrets: vec![AnchorSecret {
            subject: "user_0".into(),
            issuer: "https://accounts.example".into(),
            audience: "my-client-id".into(),
        }],
    },
)?;
assert_eq!(
    anchor.anchor_evaluations.len(),
    (config.n - config.k + 1) as usize,
);
```

## Setup

### `setup`

```rust
pub fn setup(
    params: &CircuitConfig,
    output_dir: &Path,
    rng: SetupRng,
    ptau: Option<&Path>,
) -> Result<SetupOutput, ApplicationError>
```

Runs Groth16 trusted setup and writes the setup artifacts that the CLI later
wraps in `manifest.json`.

`SetupRng` is typed:

| Variant | Use |
|---|---|
| `SetupRng::OsRng` | Production setup. Uses the OS CSPRNG. |
| `SetupRng::ChaCha20 { seed }` | Deterministic test/reproducible setup only. |

`ptau` is a Stage 2 placeholder and must be `None` today.

Files written by `setup()`:

| File | Contents |
|---|---|
| `circuit.ar1cs` | R1CS matrices in the ark-ar1cs envelope |
| `pk.bin` | Groth16 proving key |
| `vk.bin` | Groth16 verifying key |
| `pvk.bin` | Prepared verifying key |
| `Groth16Verifier.sol` | Solidity verifier |
| `config.json` | Circuit config used for setup |

The `generate_setup` CLI writes `manifest.json` and may attach
`witness_gen.wasm`.

## Artifact Loading

### `ArtifactSet`

```rust
pub struct ArtifactSet {
    pub pk: ProvingKey<BN254>,
    pub vk: VerifyingKey<BN254>,
    pub pvk: PreparedVerifyingKey<BN254>,
    pub prepared_arcs: PreparedArcs<F>,
    pub cfg: CircuitConfig,
    pub witness_gen_wasm: Option<Vec<u8>>,
}
```

`ArtifactSet` is the in-memory bundle consumed by `prove`.

### `ArtifactSet::load_signed`

```rust
pub fn load_signed(
    manifest: &Manifest,
    dir: &Path,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<ArtifactSet, ArtifactError>
```

Production loader for signed bundles. It verifies:

- `manifest.signature` exists and verifies against `verifying_key`.
- sha256 of every manifest-listed artifact matches.
- `circuit.ar1cs` parses as `ArcsFile`.
- Parsed `.ar1cs` matrices are prepared once as `PreparedArcs`.
- `.ar1cs` body Blake3 matches `manifest.ar1cs_blake3`.

### `ArtifactSet::load_unsigned`

```rust
pub fn load_unsigned(
    manifest: &Manifest,
    dir: &Path,
) -> Result<ArtifactSet, ArtifactError>
```

Loader for unsigned legacy bundles, CI fixtures, or deployments that
authenticate the manifest out of band. It performs the same artifact sha256 and
`ar1cs_blake3` validation as `load_signed`, but it does not verify manifest
authenticity.

### Timed Loaders

```rust
pub fn load_signed_with_timing(
    manifest: &Manifest,
    dir: &Path,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(ArtifactSet, ArtifactLoadTiming), ArtifactError>

pub fn load_unsigned_with_timing(
    manifest: &Manifest,
    dir: &Path,
) -> Result<(ArtifactSet, ArtifactLoadTiming), ArtifactError>
```

Timed loaders have identical validation semantics. The timing value is
diagnostic only.

## Proving

### `prove`

```rust
pub fn prove(
    artifact: &ArtifactSet,
    request: &ProveRequest,
) -> Result<ProveResponse, ApplicationError>
```

Generates one Groth16 proof per credential in `request.credentials`.

`prove` does not load artifacts and does not verify manifest claims. The trust
gate is the loader that created the `ArtifactSet`.

Internal flow:

1. Decode and validate `ProveRequest` against `artifact.cfg`.
2. Derive anchor selectors and per-credential witness bundles.
3. Build a full assignment for each credential.
4. Call `ark_ar1cs::prove_with_mode` with `artifact.pk`, `artifact.prepared_arcs`, `OsRng`, and `VerifyAfter`.
5. Return `ProveResponse`.

## Verification

There is no `zkap_service::verify` wrapper. Call arkworks directly:

```rust
use ark_groth16::Groth16;
use circuit::types::BN254;

let proof = /* reconstruct or retain ark_groth16::Proof<BN254> */;
let public_inputs = /* Vec<F> matching ProveResponse::public_inputs_for(i) */;
let ok = Groth16::<BN254>::verify_proof(&artifact_set.pvk, &proof, &public_inputs)?;
```

## DTOs

### `CircuitConfig`

Runtime circuit parameters. Important fields:

| Field | Meaning |
|---|---|
| `n` | Total credential slots |
| `k` | Required threshold |
| `max_jwt_b64_len` | Maximum JWT length in base64 bytes |
| `max_payload_b64_len` | Maximum payload length in base64 bytes |
| `max_aud_len` / `max_exp_len` / `max_iss_len` / `max_nonce_len` / `max_sub_len` | Claim length bounds |
| `tree_height` | Issuer Merkle tree height |
| `num_audience_limit` | Audience allowlist slot count |
| `claims` | Claim names extracted by the circuit |
| `forbidden_string` | Padding / injection guard string |

### Hash DTOs

```rust
pub struct HashRequest {
    pub field_elements: Vec<String>,
}

pub struct HashResponse {
    pub hash: String,
}

pub struct AudienceHashRequest {
    pub audiences: Vec<String>,
}

pub struct AudienceHashResponse {
    pub audience_hashes: Vec<String>,
    pub audience_list_hash: String,
}

pub struct IssuerKeyHashRequest {
    pub issuer: String,
    pub rsa_modulus_b64: String,
}

pub struct IssuerKeyHashResponse {
    pub hash: String,
}
```

### Anchor DTOs

```rust
pub struct AnchorSecret {
    pub subject: String,
    pub issuer: String,
    pub audience: String,
}

pub struct GenerateAnchorRequest {
    pub secrets: Vec<AnchorSecret>,
}

pub struct GenerateAnchorResponse {
    pub anchor_evaluations: Vec<String>,
    pub hanchor: String,
}
```

### Prove DTOs

```rust
pub struct ProveRequest {
    pub random: String,
    pub h_sign_user_op: String,
    pub anchor: Vec<String>,
    pub merkle_root: String,
    pub credentials: Vec<ProveCredential>,
}

pub struct ProveCredential {
    pub jwt: String,
    pub rsa_modulus_b64: String,
    pub merkle_path: Vec<String>,
    pub merkle_leaf_idx: u64,
}
```

Shape checks:

- `credentials.len() == config.k`
- `anchor.len() == config.n - config.k + 1`
- each `merkle_path.len() == config.tree_height`
- each `merkle_leaf_idx < 2^config.tree_height`

### `ProveResponse`

```rust
pub struct ProveResponse {
    pub proofs: Vec<ProofComponents>,
    pub shared_public_inputs: SharedPublicInputs,
    pub jwt_exp: Vec<String>,
    pub verification_rhs: Vec<String>,
}

impl ProveResponse {
    pub fn public_inputs_for(&self, index: usize) -> Vec<String>;
}
```

Public input order:

```text
[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]
```

### `ProofComponents`

Solidity-compatible Groth16 proof components:

```rust
pub struct ProofComponents {
    pub a: [String; 2],
    pub b: [String; 4],
    pub c: [String; 2],
}
```

## Error Types

All public APIs return `ApplicationError` except artifact loaders, which return
`ArtifactError`.

Common `ApplicationError` variants:

- `InvalidFormat`
- `InvalidFieldElement`
- `AudienceLimitExceeded`
- `InvalidClaimValue`
- `InvalidBase64`
- `InvalidRsaModulus`
- `AnchorDimensionMismatch`
- `InvalidProveRequest`
- `ProofGenerationFailed`

Common `ArtifactError` variants:

- `Io`
- `MissingArtifact`
- `HashMismatch`
- `ArcsFormat`
- `Deserialize`
- `Signature`
