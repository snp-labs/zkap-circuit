# API Reference

Public API of the `zkap-service` crate.

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

### `derive_selector`

```rust
pub fn derive_selector(
    config: &CircuitConfig,
    secrets: &[AnchorSecret],
    anchor_evaluations: &[String],
) -> Result<Vec<u8>, ApplicationError>
```

Derives the length-`n` `0/1` anchor selector marking which anchor positions the
caller's `secrets` cover (the selector sums to `k`). `anchor_evaluations` are the
field-element strings (hex or decimal) from a `generate_anchor` response or an
on-chain anchor. Wraps `derive_selector_from_x_list_and_anchor` with string
decoding; it is the public entry point for server-side backup membership-verify.

```rust
use zkap_service::{AnchorSecret, derive_selector};

let selector = derive_selector(&config, &secrets, &anchor.anchor_evaluations)?;
assert_eq!(selector.len(), config.n as usize);
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

`ptau` is reserved; passing `Some(_)` returns an error.

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

### `SetupOutput`

```rust
pub struct SetupOutput {
    pub shape: SetupShape,
    // pk / vk / pvk / arcs are pub(crate)
}

impl SetupOutput {
    pub fn prepared_verifying_key(&self) -> &PreparedVerifyingKey<BN254>;
    pub fn public_input_count(&self) -> usize;
}
```

Returned by `setup`. The key material (`pk`/`vk`/`pvk`/`arcs`) is `pub(crate)`
and persisted internally by `setup`; only `shape` is `pub`. Most callers should
verify via `verify` rather than borrowing `prepared_verifying_key()`.

### `SetupShape`

```rust
pub struct SetupShape {
    pub num_instance: u64,   // includes the constant-1 wire
    pub num_witness: u64,
    pub num_constraints: u64,
}
```

Constraint-system counts of the synthesized circuit; mirrors `manifest::Shape`.

## Artifact Loading

### `ArtifactSet`

```rust
pub struct ArtifactSet {
    pub(crate) pk: ProvingKey<BN254>,
    pub(crate) vk: VerifyingKey<BN254>,
    pub(crate) pvk: PreparedVerifyingKey<BN254>,
    pub(crate) prepared_arcs: PreparedArcs<F>,
    pub cfg: CircuitConfig,
    pub witness_gen_wasm: Option<Vec<u8>>,
}
```

Only `cfg` and `witness_gen_wasm` are `pub`; `pk`, `vk`, `pvk`, and
`prepared_arcs` are `pub(crate)` and are not accessible to external callers.

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

## Manifest

A CRS bundle is described by a `manifest.json`. The loaders
(`ArtifactSet::load_signed` / `load_unsigned`) consume a `Manifest`; the
`generate_setup` CLI produces one. A manifest carries per-file sha256 claims,
the `ar1cs_blake3` body hash, the constraint-system shape, setup provenance, and
an optional ed25519 signature. `witness_gen.wasm` is intentionally NOT a
manifest artifact — its integrity is tracked by the separate `witness_gen.json`
sidecar.

### `ManifestBuilder`

```rust
impl ManifestBuilder {
    pub fn new(circuit_id: impl Into<String>, circuit_tag: impl Into<String>) -> Self;
    pub fn with_ar1cs_blake3(self, hex: impl Into<String>) -> Self;
    pub fn with_shape(self, num_instance: u64, num_witness: u64, num_constraints: u64) -> Self;
    pub fn with_public_input_names(self, names: Vec<String>) -> Self;
    pub fn with_artifact(self, key: ArtifactKey, entry: ArtifactEntry) -> Self;
    pub fn with_setup_provenance(self, p: SetupProvenance) -> Self;
    pub fn with_build(self, build: BuildMetadata) -> Self;
    pub fn build(self) -> Result<Manifest, BuilderError>;
}
```

Required before `build()`: `with_ar1cs_blake3`, `with_shape`,
`with_public_input_names`, `with_setup_provenance`, `with_build`, and
`with_artifact` for each of `Ar1cs` / `Pk` / `Vk` / `Pvk` / `CircuitConfig`
(the `EvmVerifier` artifact is optional). `build()` derives
`toxic_waste_disclosure` from the provenance.

```rust
use zkap_service::manifest::{ManifestBuilder, ArtifactKey, SetupProvenance};

let manifest = ManifestBuilder::new("zkap-main-v1", circuit_tag)
    .with_ar1cs_blake3(ar1cs_blake3_hex)
    .with_shape(num_instance, num_witness, num_constraints)
    .with_public_input_names(
        zkap_service::PUBLIC_INPUT_NAMES.iter().map(|s| s.to_string()).collect(),
    )
    .with_artifact(ArtifactKey::Ar1cs, ar1cs_entry)
    // … Pk, Vk, Pvk, CircuitConfig …
    .with_setup_provenance(SetupProvenance::OsRng)
    .with_build(build_metadata)
    .build()?;
```

### Signing

```rust
pub fn sign_manifest(
    manifest: &mut Manifest,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), ManifestError>;

pub fn verify_manifest(
    manifest: &Manifest,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), ManifestError>;

impl Manifest {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, ManifestError>;
}
```

`sign_manifest` writes `manifest.signature` over the canonical compact-JSON
payload (every non-signature field participates, so adding a field
automatically brings it under the signature). `verify_manifest` checks that
signature.

### Schema types

| Type | Purpose |
|---|---|
| `Manifest` | top-level document: version, circuit id/tag, curve, proof system, `ar1cs_blake3`, `shape`, `public_input_names`, `artifacts`, `setup_provenance`, `toxic_waste_disclosure`, `build`, optional `signature` |
| `Shape` | constraint-system counts (`num_instance` / `num_witness` / `num_constraints`) |
| `Artifacts` | per-file block: `ar1cs` / `pk` / `vk` / `pvk` / `circuit_config` (required) + optional `evm_verifier` |
| `ArtifactEntry` | one file: `path`, `sha256`, `size`, `kind`, optional `schema_owner` / `schema_ref` |
| `ArtifactKey` | builder slot selector: `Ar1cs` / `Pk` / `Vk` / `Pvk` / `EvmVerifier` / `CircuitConfig` |
| `SetupProvenance` | randomness provenance: `OsRng` / `Seed { seed }` / `Ceremony { ptau, phase2_attestations }` (kebab-case `kind` tag) |
| `ToxicWasteDisclosure` | trust model derived from the provenance |
| `BuildMetadata` | repo / commit / `ark_ar1cs_rev` / rustc / RFC3339 `built_at` |
| `PtauRef`, `Phase2Attestation`, `ContributionPublicKeyJson` | Stage 2 ceremony provenance — schema-accepted but not emitted by the Stage 1 setup binary |

### Helpers

```rust
pub fn compute_circuit_tag(circuit_id: &str, cfg_canonical_bytes: &[u8]) -> String;
pub fn canonical_json_bytes(value: &serde_json::Value) -> Vec<u8>;
pub fn derive_toxic_waste_disclosure(p: &SetupProvenance) -> ToxicWasteDisclosure;
```

`compute_circuit_tag` produces `{circuit_id}__{first_8_hex_of_sha256(cfg)}` —
the same tag used for the dist subdirectory and `manifest.circuit_tag`.
`canonical_json_bytes` emits deterministic key-sorted JSON bytes.

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

`prove` is the one-shot composition of the two halves below:
`synthesize_witnesses` then `prove_bundles(.., PreflightMode::VerifyAfter)`.

### `prove_bundles`

```rust
pub fn prove_bundles(
    artifact: &ArtifactSet,
    bundles: Vec<WitnessBundle>,
    mode: PreflightMode,
) -> Result<ProveResponse, ApplicationError>
```

The circuit-agnostic half of proving: turns pre-synthesized `WitnessBundle`s
into a `ProveResponse`. Callers that obtain bundles out of band (e.g. from the
`zkap-witness-gen-wasm` ABI) use this directly and never depend on `ark_ar1cs`.

The per-bundle loop runs in parallel via rayon (enabled only by the
`native-witness` feature) and is **order-preserving** — output proof order
matches input bundle order, which the on-chain semantics rely on. Like `prove`,
it re-verifies nothing; the loader is the trust gate.

### `synthesize_witnesses`

```rust
pub fn synthesize_witnesses(
    cfg: &CircuitConfig,
    request: &ProveRequest,
) -> Result<Vec<WitnessBundle>, ApplicationError>
```

The circuit-dependent half: validates `request` against `cfg` and produces one
`WitnessBundle` per credential. Pair with `prove_bundles` for a split prove
pipeline, or call `prove` for the one-shot path.

### `PreflightMode`

Preflight policy for `prove_bundles` (mirrors `ark_ar1cs::PreflightMode` so
callers select the behaviour without importing `ark_ar1cs`).

| Variant | Behaviour |
|---|---|
| `VerifyAfter` (default) | Generate the proof, then verify it against `pk.vk` before returning. The `prove` default. |
| `StrictPreflight` | Check every R1CS row for satisfaction *before* proving; skip the post-proof verify. |

## Verification

### `verify`

```rust
pub fn verify(
    artifact: &ArtifactSet,
    proof: &Proof<BN254>,
    public_inputs: &[F],
) -> Result<bool, ApplicationError>
```

Returns `Ok(true)` if the pairing check passes, `Ok(false)` if it fails.

`proof` is `ark_groth16::Proof<BN254>`, re-exported as `zkap_service::Proof` so
callers can name the proof type without depending on `ark-groth16` directly.

```rust
use zkap_service::verify;

// `response.public_inputs_for(0)` returns hex strings; decode them to
// `Vec<F>` with the same field codec the host used.
let public_inputs: Vec<F> = /* decode response.public_inputs_for(0) */;
let ok = verify(&set, &proof, &public_inputs)?;
assert!(ok);
```

Canonical usage: `let ok = zkap_service::verify(&set, &proof, &public_inputs)?;`

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

### `WitnessBundle`

```rust
pub struct WitnessBundle {
    pub full_assignment: Vec<F>,
    pub public_inputs: Vec<F>,
}
```

Circuit-agnostic witness emitted by `synthesize_witnesses` and consumed by
`prove_bundles`. Both vectors are `Vec<F>`, so a wasm generator can
`CanonicalSerialize` them and a native host can `CanonicalDeserialize` and prove
without linking constraint code.

### `SharedPublicInputs`

```rust
pub struct SharedPublicInputs {
    pub hanchor: String,
    pub h_a: String,
    pub root: String,
    pub h_sign_user_op: String,
    pub lhs: String,
    pub h_aud_list: String,
}
```

The public-input values shared across every proof in a batch (slots 0–3, 6, 7).
The per-proof slots — `jwt_exp` (4) and `partial_rhs` (5) — live on
`ProveResponse` (`jwt_exp` / `verification_rhs`) instead.

### Public Input Layout

The canonical 8-slot wire order is defined once by `PublicInputSlot` /
`PUBLIC_INPUTS` (the single source of truth), with names in
`PUBLIC_INPUT_NAMES`:

| Index | `PublicInputSlot` | Wire name |
|---|---|---|
| 0 | `Hanchor` | `hanchor` |
| 1 | `Ha` | `h_a` |
| 2 | `Root` | `root` |
| 3 | `HSignUserOp` | `h_sign_user_op` |
| 4 | `JwtExp` | `jwt_exp` |
| 5 | `PartialRhs` | `partial_rhs` |
| 6 | `Lhs` | `lhs` |
| 7 | `HAudList` | `h_aud_list` |

`PublicInputSlot::name()` and `::index()` map a slot to its wire name and
position. This order matches the witness vector, the manifest
`public_input_names`, and `ProveResponse::public_inputs_for`. Note: slot 5's
canonical wire name is `partial_rhs`; the `ProveResponse` struct exposes the
same per-proof value as its `verification_rhs` field.

## Witness-Gen Sidecar

`witness_gen.wasm` ships independently of the CRS bundle, described by a
`witness_gen.json` sidecar produced by the `generate_witness_gen_sidecar` CLI.
The sidecar pairs a wasm with the CRS shapes it may serve, keyed on
`ar1cs_blake3`. For the CLI flags, the release model, and the publish/consume
how-to, see [Witness Generator](WITNESS_GEN.md).

### `WitnessGenSidecar`

```rust
pub struct WitnessGenSidecar {
    pub version: String,
    pub sha256: String,                       // 64-char lowercase hex
    pub compatible_ar1cs_blake3: Vec<String>, // non-empty
    pub circuit_commit: Option<String>,
    pub circuit_id: Option<String>,
}

impl WitnessGenSidecar {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SidecarError>;
    pub fn validate(&self) -> Result<(), SidecarError>;
    pub fn verify_wasm_sha(&self, wasm_bytes: &[u8]) -> Result<(), SidecarError>;
    pub fn require_compatible(&self, crs_ar1cs_blake3: &str) -> Result<(), SidecarError>;
    pub fn is_compatible(&self, crs_ar1cs_blake3: &str) -> bool;
}
```

The contract is fail-closed: parse → `validate` → `verify_wasm_sha` →
`require_compatible` before trusting a downloaded wasm. `sha256` is
distribution-integrity; `compatible_ar1cs_blake3` gates which CRS shapes the
wasm pairs with; `circuit_commit` / `circuit_id` are non-gating provenance.
Failures surface as `SidecarError`.

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
- `ArcsFormat`
- `Deserialize`
- `HashMismatch`
- `Signature`

`CircuitConfigError` (returned by `CircuitConfig::validate`, surfaced through
`load_circuit_config`) variants:

- `InvalidK`
- `KExceedsN`
- `InvalidN`
- `InvalidTreeHeight`
- `PayloadExceedsJwt`
- `InvalidNumAudienceLimit`
- `EmptyClaims`

Manifest and sidecar helpers have their own error types: `ManifestError`
(signing / canonical encoding), `BuilderError` (missing builder field or
artifact), and `SidecarError` (witness-gen sidecar parse / validation).
