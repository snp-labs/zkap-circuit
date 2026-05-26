# Architecture

## Repository Role

`zkap-circuit` is the ZKAP core circuit and artifact-contract workspace. It
owns the Rust implementation of the statement, the trusted setup output shape,
the manifest-validated loading boundary, and the proof-generation pipeline.

It is not the platform SDK. Node.js, browser WASM, iOS, Android, and React
Native packaging live in `zkap-zkp`, which consumes this workspace through the
service crate and generated artifacts.

## Dependency Graph

```text
                       zkap-service
                         |      |
                         |      +--> ark-ar1cs
                         |             (ArcsFile, synthesize_full_assignment, prove)
                         |
                         +--> circuit --> gadget --> ark-r1cs-helpers
                         |        |          |
                         |        |          +--> arkworks
                         |        +--> ark-codec
                         |
                         +--> zkap-evm-verifier

                       zkap-cli --> zkap-service
                       zkap-witness-gen-wasm --> zkap-service DTO/circuit path
```

## Crate Responsibilities

### `crates/service`

Public API and proof orchestration. It owns:

- DTO boundary (`HashRequest`, `AudienceHashRequest`, `IssuerKeyHashRequest`,
  `GenerateAnchorRequest`, `ProveRequest`, `ProveResponse`).
- Host-side helpers:
  - `generate_poseidon_hash`
  - `generate_audience_hashes`
  - `generate_issuer_key_hash`
  - `generate_anchor`
  - `load_circuit_config`
- Trusted setup: `setup`.
- Artifact loading: `ArtifactSet::load_signed` and
  `ArtifactSet::load_unsigned`.
- Witness synthesis and proving: `synthesize_witnesses`,
  `synthesize_witnesses_streaming`, and the free
  `prove(&ArtifactSet, &ProveRequest)`.

The prove function does not perform manifest lookup or hash validation. The
loader is the only trust gate.

### `crates/circuit`

Defines `ZkapCircuit`, `CircuitConfig`, witness structures, public input
layout, and the R1CS constraints. The circuit proves:

- JWT validity under RS256.
- RSA public exponent is fixed to 65537.
- Payload boundaries match the actual JWT separators.
- Issuer RSA key membership in a Poseidon Merkle tree.
- Threshold membership through the Vandermonde anchor scheme.
- Audience allowlist membership.
- Binding to `h_sign_user_op` and non-zero `random`.

### `crates/gadget`

Reusable constraint gadgets: Poseidon, SHA-256, RSA/bignat, base64, Merkle,
matrix, and anchor logic. Feature flags keep individual gadget families
available for focused checks, but the service proof path uses the full set it
needs directly.

### `crates/ark-codec`

Field, string, and affine codec helpers shared across service, circuit, CLI,
and bindings.

### `crates/ark-r1cs-helpers`

R1CS comparison, packing, select, and slice helpers.

### `crates/cli`

Thin CLI layer:

- `generate_setup`: runs `zkap_service::setup`, writes the CRS bundle, emits
  `manifest.json`, and optionally signs it.
- `generate_hash`: operator/dev utility for Poseidon audience and issuer-key
  leaf hashes.

### `crates/witness-gen-wasm`

`wasm32-unknown-unknown` C ABI witness generator. This is the only production
crate that locally allows unsafe code because exported raw-pointer ABI
functions require it.

### `crates/zkap-evm-verifier`

Solidity Groth16 verifier codegen from arkworks verifying keys. It does not own
circuit or proof-generation logic.

## Artifact Trust Boundary

The CRS bundle is a directory of named artifacts:

```text
circuit.ar1cs
pk.bin
vk.bin
pvk.bin
Groth16Verifier.sol
config.json
manifest.json
witness_gen.wasm      # optional
```

`manifest.json` records sha256 claims for the files and an `ar1cs_blake3`
claim for the canonical `.ar1cs` body. It may also carry an ed25519 signature.

There are two caller-facing loaders:

- `ArtifactSet::load_signed(manifest, dir, verifying_key)`
  - Verifies the ed25519 manifest signature.
  - Verifies sha256 claims for `circuit.ar1cs`, `pk.bin`, `vk.bin`, `pvk.bin`,
    `config.json`, optional `Groth16Verifier.sol`, and optional
    `witness_gen.wasm`.
  - Verifies `ar1cs_blake3`.
  - Preferred for production signed bundles.
- `ArtifactSet::load_unsigned(manifest, dir)`
  - Verifies the same sha256 and `ar1cs_blake3` claims.
  - Does not verify manifest authenticity.
  - Intended for unsigned legacy bundles, CI fixtures, or deployments that
    authenticate the manifest out of band.

After either loader succeeds, the prove path trusts the returned `ArtifactSet`.
`prove` does not recompute artifact hashes and does not verify manifest
signatures.

### Loader Performance Contract

Once signature/hash gates pass, key material may be deserialized through
arkworks' unchecked canonical path. At that point the manifest-authenticated
bytes are the artifact identity. A wrong-but-authentic key cannot produce a
valid proof for the expected circuit; that failure belongs to prove/verify, not
artifact loading.

`ArtifactLoadTiming` and the `*_with_timing` loader variants expose diagnostic
cold-load timings without changing validation semantics.

## Prove Data Flow

1. Caller loads a manifest and CRS bundle through `ArtifactSet::load_signed`
   or `ArtifactSet::load_unsigned`.
2. Caller submits `ProveRequest` with no artifact paths. It contains only
   shared field strings, anchor evaluations, Merkle root, and `k`
   `ProveCredential` entries.
3. `prove_request_to_decoded(&req, &cfg)` validates:
   - `CircuitConfig::validate`.
   - `credentials.len() == k`.
   - `anchor.len() == n - k + 1`.
   - `merkle_path.len() == tree_height`.
   - `merkle_leaf_idx < 2^tree_height`.
   - field/base64/JWT wire encodings.
4. `synthesize_witnesses` derives per-credential witness bundles:
   - parse JWT claims.
   - derive anchor x values and selector positions.
   - build anchor, JWT, audience, Merkle, and public-input stages.
   - synthesize full assignment `[F::ONE, instance..., witness...]`.
5. `prove(&set, &request)` calls `ark_ar1cs::prove(&pk, &arcs, &full, OsRng)`
   for each credential bundle.
6. `ProveResponse` contains Solidity-compatible proof components plus shared
   and per-proof public inputs.

## Verification

This crate intentionally does not wrap verification. Callers verify with
arkworks directly:

```rust
ark_groth16::Groth16::<BN254>::verify_proof(
    &artifact_set.pvk,
    &proof,
    &public_inputs,
)?;
```

The public input order is fixed:

```text
[hanchor, h_a, root, h_sign_user_op, jwt_exp, verification_rhs, lhs, h_aud_list]
```

Use `ProveResponse::public_inputs_for(index)` to reconstruct that vector for a
proof in a batch.

## Key Design Decisions

- **Runtime `CircuitConfig`**: circuit size parameters are runtime data, not
  Rust generics, so the same binary can load multiple setup shapes.
- **Manifest as trust gate**: all artifact identity checks happen before
  proving. This keeps the hot prove path simple and explicit.
- **Free `prove` function**: there is no public `Prover` struct in the current
  API. The in-memory `ArtifactSet` is passed directly into `prove`.
- **No in-crate verify wrapper**: verification is a one-line arkworks call and
  remains caller-owned.
- **Raw claim helper inputs**: hash/anchor helper APIs accept raw claim strings
  and add JSON quotes internally, matching in-circuit JWT extraction.
- **Optional signed manifests**: unsigned manifests remain supported for
  legacy/fixture workflows, but production signed bundles should use
  `load_signed`.
