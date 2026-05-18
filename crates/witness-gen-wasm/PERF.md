# `zkap-witness-gen-wasm` — performance baseline

This document records the **measurement infrastructure** added in PR-1a
of the cross-platform SDK plan and the **first set of numbers** taken on
the implementor's workstation. It is intentionally a baseline, not a
target; PR-1b (CI gates) and Step 2 (perf optimisations) build on top of
it.

## What is measured

The bench suite lives at `benches/synthesize.rs` and is driven by
`cargo bench -p zkap-witness-gen-wasm` (cargo bench inherits `[profile.release]`
automatically — passing `--release` errors out). The integration test
at `tests/parity.rs` cross-checks the canonical-serialize output of
the two axes for byte-for-byte equivalence.

### Axes

| Mode | Status | Notes |
|---|---|---|
| **rlib (native)** | landed | Direct call into `zkap_witness_gen_wasm::synthesize_witness_bytes`. Host-arch baseline. |
| **wasmtime cranelift JIT** | landed | Load `target/wasm32-unknown-unknown/release/zkap_witness_gen_wasm.wasm` under `wasmtime::Engine::default()` and drive the C ABI exports (`wg_alloc` / `synthesize_witness` / `wg_last_output_ptr` / `wg_dealloc`). The canonical wasm path for Node and dev. |
| **wasmtime AOT (`.cwasm`)** | deferred | Gated behind `feature = "wasmtime_aot"`. Would model the mobile-iOS AOT requirement (per the OQ3 amendment). Not blocking PR-1a — the precompile path needs a stable `Engine::precompile_module` + `Module::deserialize` choice and decision around storage location for the `.cwasm` blob; cleaner to land in its own PR alongside the iOS toolchain wiring. |
| **wasmtime pulley interpreter** | deferred | Gated behind `feature = "wasmtime_pulley"`. The 26.x wasmtime release we currently pin does ship pulley, but switching strategies inside one `Engine` requires the right `Config::strategy(Strategy::Pulley)` call plus a separate compile, which is more API-surface change than fits in the measurement-infra PR. Tracked as part of the mobile fallback exploration. |

### Workload variants

`k ∈ {1, 3, 5}` (number of credentials per batch). The bench config
keeps `tree_height = 4` and `n = k` (all real, zero anchor dummies)
so per-k numbers scale linearly with the unavoidable per-credential
cost. JWT / payload / aud / iss / sub / nonce / exp max-lengths are
held at the same values as the e2e test config so the constraint
shape is representative.

### Cold vs warm

- **warm** — criterion's standard `iter`. The wasmtime instance is
  primed with one un-measured call (so any first-touch JIT allocator
  / linear-memory page-faulting cost lands outside the measurement
  region) and then reused across iterations.
- **cold** — criterion's `iter_batched(BatchSize::PerIteration)`. The
  wasmtime instance is rebuilt per iteration from the same compiled
  `Module`; only `Instance::new` + first-touch buffers fall inside
  the measured region. The rlib axis runs the same per-iteration
  cloning pattern so the comparison stays apples-to-apples (the
  setup cost on the native side is essentially free).

## Fixture strategy

**Chosen: Path A** — bench-side fixture lift. `benches/common/mod.rs`
re-derives a fully-valid `(CircuitConfig, ProveRequest)` pair from
deterministic seeds: real RSA-2048 keypairs, real `RS256` JWT
signatures, real anchor evaluations from `generate_anchor`, real
Poseidon-hashed issuer-key Merkle tree of `2^tree_height` leaves.

The lift is ≈150 lines of pure input-construction code, reused
between the bench and the parity test via `#[path = "..."]`. No
fixture JSON files are checked in — the bench rebuilds them per
process. Constructing the fixture takes ~1 s per `k` (RSA-2048
keygen dominates); this happens once outside any `bench_function`
closure, so it doesn't pollute the timing.

We considered Path B (consume `proof_fixture.json` written by
`crates/service/tests/gen_proof_fixture.rs`) but that fixture is
camelCase-encoded for sdk-node and would require either a parallel
snake_case fixture or a serialization shim. Path A is closer to the
input the rlib + wasm crates actually deserialize, so we picked it.

## Baseline measurements

Hardware: Apple Silicon (Darwin 25.5.0, aarch64 host), release
profile (`lto = true`, `panic = abort` for non-test artifacts).
Numbers are mean ± criterion's reported standard deviation; consult
`target/criterion/**/report/index.html` for full distributions.

**Baseline run** — `cargo bench -p zkap-witness-gen-wasm`, 2026-05-18 on the
implementor's Apple Silicon laptop. Cell values are criterion's point
estimate ± half-width of the 95% CI, all in **ms**. Full distributions
at `target/criterion/**/report/index.html`. AOT / pulley rows stay
`deferred` until those axes are wired up (see "Axes" above).

| Mode             | k=1 cold        | k=1 warm        | k=3 cold        | k=3 warm        | k=5 cold        | k=5 warm        |
|------------------|-----------------|-----------------|-----------------|-----------------|-----------------|-----------------|
| rlib (native)    | 123.03 ± 0.18   | 122.89 ± 0.19   | 372.80 ± 1.15   | 378.85 ± 0.62   | 623.79 ± 1.31   | 622.82 ± 1.57   |
| wasmtime JIT     | 256.45 ± 0.94   | 257.87 ± 2.44   | 769.89 ± 1.34   | 750.17 ± 0.62   | 1287.7 ± 3.90   | 1255.7 ± 1.50   |
| wasmtime AOT     | deferred        | deferred        | deferred        | deferred        | deferred        | deferred        |
| wasmtime pulley  | deferred        | deferred        | deferred        | deferred        | deferred        | deferred        |

**Key observations from the first run:**

1. **Cold ≈ Warm on both axes.** rlib delta within noise (instance
   setup on native is essentially free). wasmtime cold/warm gap ≤ 3%
   — `wasmtime::Instance::new` + first-touch buffers cost is
   negligible relative to the witness synthesis itself. Implication
   for Step 2 Tier 3: instance pooling / module pre-instantiation
   only pays off if the per-call cost drops well below current values;
   on this baseline it would be a wash.

2. **wasmtime / rlib ≈ 2.0x consistently** — 2.08x at k=1, 1.98x at
   k=3, 2.02x at k=5. cranelift JIT overhead is multiplicative and
   stable. Step 2 Tier 1 (`wasm-opt -O3` + SIMD via
   `target-feature=+simd128`) should bring this ratio under ~1.5x to
   justify the ABI work in Tier 2 (CircuitConfig caching, bincode
   variant).

3. **Linear scaling per credential.** rlib: ~123 ms/cred; wasmtime:
   ~255 ms/cred. No per-batch fixed cost worth optimizing. The lever
   is per-credential synthesis (RSA verify, Poseidon, Merkle path),
   not batch setup.

4. **wasmtime k=5 cold = 1.29 s** on a desktop-class host. Mobile UX
   implications: the CEO-review acceptance criterion (`cold-start +
   k=3 witness gen ≤ 2s on mid-tier device`) is plausible for rlib
   (k=3 = 373 ms — comfortable) but tight for wasmtime (k=3 = 770 ms
   — leaves ~1.2 s budget for mobile arch slowdown vs Apple Silicon).
   Real-device measurement on aarch64 mobile chips needed before
   confidence in that gate.

5. **Sample variance is small.** Most CI half-widths < 2 ms even on
   ~125 ms means. criterion's default sample_size=100 is comfortable
   for this workload — PR-1b's SLA gate can use baseline + 10% slack
   as an absolute threshold without statistical noise concerns.

### Wasm binary size

Informational, not a perf metric per se, but worth tracking next to
the runtime numbers — the cdylib's `.wasm` size bounds the
download-and-instantiate path on browser/RN/mobile clients.

```text
$ ls -l target/wasm32-unknown-unknown/release/zkap_witness_gen_wasm.wasm
1,039,908 bytes (~1.0 MB, pre-wasm-opt)
```

Step 2 Tier 1 (`wasm-opt -O3 --enable-simd --enable-bulk-memory ...`)
typically removes 15–30% from this number. Post-optimization size lands
in PERF.md after that PR.

## What this baseline does NOT yet measure

- **aarch64 mobile arch.** All numbers above run wasmtime on the
  host (typically Apple Silicon laptop). Real device measurement —
  iOS AOT + Android JIT/AOT — is a follow-up after the SDK plumbing
  exists.
- **Per-credential synth time / sub-step breakdown.** The bench
  times the public entry point (`synthesize_witness_bytes` /
  `synthesize_witness`). Internal steps (claim extraction, RSA
  verify, Poseidon hashes, Merkle path replay) are not separately
  profiled here; that's a Step 2+ scope.
- **Memory footprint.** Linear memory peak / RSS deltas are not
  reported. wasmtime exposes the hooks; we'd add them when the
  mobile target surfaces a constraint.
- **End-to-end prove time.** Witness synthesis is one half of the
  prove pipeline; the other half (Groth16 prover) lives in
  `crates/service`. End-to-end timings are tracked elsewhere.
- **AOT cwasm / pulley axes** (see "Axes" above).

## Reproducing

```bash
# Prereq: install the wasm32 target.
rustup target add wasm32-unknown-unknown

# 1. Build the cdylib the bench / parity test load.
cargo build --target wasm32-unknown-unknown --release -p zkap-witness-gen-wasm

# 2. Confirm parity (rlib == wasmtime, byte-for-byte).
cargo test --release -p zkap-witness-gen-wasm --test parity

# 3. Run the criterion suite. ~10-15 min on first run. NOTE: cargo bench
#    inherits [profile.release] automatically; passing --release errors
#    out ("unexpected argument '--release'").
cargo bench -p zkap-witness-gen-wasm

# 4. Open the HTML report.
open target/criterion/report/index.html
```
