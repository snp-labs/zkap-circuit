# Witness Generator (`witness_gen.wasm`)

How the WebAssembly witness generator is packaged, published, and paired with a
CRS bundle. For the Rust types, see the
[Witness-Gen Sidecar](API_REFERENCE.md#witness-gen-sidecar) section of the API
reference.

## Why it ships separately

`witness_gen.wasm` is a shape-agnostic witness generator (a wasm32 cdylib). It
is **not** part of the signed CRS bundle and is **not** a `manifest.json`
artifact. The reasoning:

- The wasm carries no circuit trust. Groth16 soundness plus the on-chain
  public-input pins enforce correctness regardless of which generator produced
  the witness. A tampered wasm can only make proving fail, not forge a proof.
- Decoupling lets a witness-side fix be re-published **without** regenerating
  the CRS (no new trusted setup). Pairing is keyed on the circuit's
  `ar1cs_blake3`, not on a version string, so a fresh wasm that was preflighted
  against an unchanged circuit pairs with the existing CRS.

Integrity and compatibility instead travel in a small JSON sidecar,
`witness_gen.json`, alongside the wasm in its own release channel.

## `witness_gen.json` schema

Produced by `generate_witness_gen_sidecar`, consumed by
[`WitnessGenSidecar`](API_REFERENCE.md#witnessgensidecar):

```json
{
  "version": "v0.1.1-rc.4",
  "sha256": "<sha256(witness_gen.wasm), 64-char lowercase hex>",
  "compatible_ar1cs_blake3": ["<1-of-1 ar1cs_blake3>", "<3-of-3 ar1cs_blake3>"],
  "circuit_commit": "<source commit, optional>",
  "circuit_id": "<circuit id, optional>"
}
```

| Field | Role |
|---|---|
| `sha256` | **Integrity** — distribution guard over the wasm bytes. Not a circuit-trust claim. |
| `compatible_ar1cs_blake3` | **Compatibility** — the `ar1cs_blake3` of every CRS shape this wasm was preflighted against. Must be non-empty; gates which CRS the wasm may pair with. |
| `circuit_commit` / `circuit_id` | **Provenance** — informational only, never gating. |

## CLI: `generate_witness_gen_sidecar`

Hashes a pre-built wasm and records the CRS shapes it is compatible with.

```text
generate_witness_gen_sidecar \
  --witness-gen-wasm <path>     # wasm to hash + describe (required)
  --version <ver>               # e.g. v0.1.1-rc.4 (required; free text, not gating)
  --bundle <dir>                # CRS bundle dir whose manifest.json supplies an
                                #   ar1cs_blake3; repeatable, pass once per shape (required)
  [--output <path>]             # default: <dir of --witness-gen-wasm>/witness_gen.json
  [--circuit-commit <sha>]      # provenance only
  [--circuit-id <id>]           # provenance only
```

`--bundle` is required at least once; each directory's `manifest.json`
contributes one entry to `compatible_ar1cs_blake3`. The standalone binary and
`generate_setup --witness-gen-version` both call the same
`zkap_cli::build_witness_gen_sidecar`, but this binary is the entry point for
the **decoupled republish** path (no CRS keygen).

## How-to: publish

This is what CI's `publish-witness-gen` job runs (`.github/workflows/release.yml`).
It builds the sidecar from the per-shape bundle manifests, then creates a
`witness-gen-v<ver>` GitHub release carrying the wasm + sidecar:

```sh
generate_witness_gen_sidecar \
  --witness-gen-wasm witness_gen.wasm \
  --version "v0.1.1-rc.4" \
  --bundle dist/release-local/1-of-1 \
  --bundle dist/release-local/3-of-3 \
  --circuit-commit "$GIT_SHA" \
  --circuit-id zkap-main \
  --output witness_gen.json

gh release create "witness-gen-v0.1.1-rc.4" \
  --title "witness-gen-v0.1.1-rc.4" \
  witness_gen.wasm witness_gen.json
```

The CRS release (`v<ver>`) asserts it carries **no** `witness_gen.wasm`; the
wasm lives only in the companion `witness-gen-v<ver>` release. The
`witness-gen-v*` tag does not match the `v*` push trigger, so publishing it
never re-triggers a release.

## How-to: consume (pair a wasm with a CRS)

Before trusting a downloaded wasm, validate the sidecar and confirm it pairs
with your CRS. The contract is fail-closed — every check is a hard error.

```rust
use zkap_service::{WitnessGenSidecar, manifest::Manifest};

// The CRS side: load the manifest you already trust.
let manifest: Manifest = serde_json::from_slice(&std::fs::read(crs_dir.join("manifest.json"))?)?;

// The witness-gen side: load + validate the sidecar.
let wasm_bytes = std::fs::read(wg_dir.join("witness_gen.wasm"))?;
let sidecar = WitnessGenSidecar::from_json(&std::fs::read(wg_dir.join("witness_gen.json"))?)?; // parse + validate
sidecar.verify_wasm_sha(&wasm_bytes)?;                 // integrity: sha256 matches the bytes
sidecar.require_compatible(&manifest.ar1cs_blake3)?;   // compatibility: this CRS shape is listed

// Safe to feed `wasm_bytes` to the witness generator for this CRS.
```

`from_json` runs `validate` (schema: 64-hex `sha256`, non-empty 64-hex
`compatible_ar1cs_blake3`). Use `is_compatible(&manifest.ar1cs_blake3)` for a
non-erroring boolean check. Failures surface as
[`SidecarError`](API_REFERENCE.md#witnessgensidecar).

## See also

- [API Reference → Witness-Gen Sidecar](API_REFERENCE.md#witness-gen-sidecar) — the `WitnessGenSidecar` / `SidecarError` types.
- [PERFORMANCE.md](PERFORMANCE.md) — building and optimising the wasm.
