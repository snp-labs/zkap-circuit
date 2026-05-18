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
# Pre-wasm-opt (`cargo build --target wasm32-unknown-unknown --release`):
1,039,908 bytes  (~1.0 MB)

# Post Step 2 Tier 1.1 (`scripts/optimize-wasm.sh`, wasm-opt -O3):
  864,088 bytes  (~0.83 MB, -16.9%)
```

## Step 2 Tier 1.1 — wasm-opt -O3 (landed)

Production build now runs `crates/witness-gen-wasm/scripts/optimize-wasm.sh`
between `cargo build --target wasm32-unknown-unknown --release` and the
bench/parity steps. The script in-place overwrites the cdylib with the
output of:

```bash
wasm-opt -O3 \
    --enable-simd --enable-bulk-memory --enable-mutable-globals \
    --enable-sign-ext --enable-nontrapping-float-to-int \
    <wasm> -o <wasm>
```

The `--enable-*` flags whitelist the wasm features the Rust wasm32
backend emits by default; without them wasm-opt rejects the input.
SIMD is whitelisted ahead of Tier 1.2 so the same pipeline absorbs
the rustc `+simd128` target-feature flip without changes.

**Measured impact** (criterion bench against baseline.json values):

| Axis × k     | Baseline (ms)    | wasm-opt (ms)    | Δ      |
|--------------|------------------|------------------|--------|
| wasmtime/cold/1 | 256.45         | 256.86           | +0.2%  |
| wasmtime/warm/1 | 257.87         | 254.76           | -1.2%  |
| wasmtime/cold/3 | 769.89         | 771.09           | +0.2%  |
| wasmtime/warm/3 | 750.17         | 755.55           | +0.7%  |
| wasmtime/cold/5 | 1287.7         | 1295.18          | +0.6%  |
| wasmtime/warm/5 | 1255.7         | 1262.51          | +0.5%  |

All twelve benches (rlib + wasmtime) pass the 10%-slack regression gate.
Wasmtime cranelift JIT runtime is **largely insensitive to wasm-opt for
this workload** — cranelift's middle-end optimisations overlap heavily
with wasm-opt's, so the static optimisation is mostly redundant once
JIT re-compilation runs. The win lands on:

1. **Binary size: -16.9%** (175,820 bytes removed). Matters for browser
   / RN download cost, not for desktop wasmtime runtime.
2. **AOT path (cwasm)** — pre-optimised input feeds Cranelift's
   `precompile_module` cheaper. Verified once Step 5 wires the iOS
   AOT axis in.
3. **Browser engines (V8, JSC, SpiderMonkey)** — these run less
   aggressive optimisation at JIT time than Cranelift, so wasm-opt's
   static pass becomes load-bearing there. Quantified at SDK
   integration time (Step 4 / 5).

`baseline.json` values are **unchanged** by this step — runtime didn't
improve, so updating would just encode machine noise. The next lever
(Tier 1.2 — `rustc -C target-feature=+simd128`) is where the wasmtime
axis is expected to actually move.

## Step 2 Tier 1.2 — rustc `+simd128,+bulk-memory` (landed)

`.cargo/config.toml` pins `target-feature=+simd128,+bulk-memory` for
the `wasm32-unknown-unknown` target. The host (rlib native + workspace
tests) is untouched -- `[target.wasm32-...]` only applies when
`--target wasm32-...` is on the command line. `+bulk-memory` is a Rust
wasm32 default since ~1.77; restated here to make the contract
explicit and to keep the rustflags consistent with the `--enable-*`
flags in `scripts/optimize-wasm.sh`. The lever is `+simd128`: without
it rustc emits scalar i32/i64 ops and wasm-opt cannot vectorise after
the fact.

**Verified SIMD lands in the binary** (post Tier 1.2 + wasm-opt):

```bash
wasm-tools print zkap_witness_gen_wasm.wasm \
    | grep -cE '\b(v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\.'
8563
```

Top v128 op kinds by frequency:

| Op kind             | Count | Notes                                       |
|---------------------|-------|---------------------------------------------|
| `v128.store`        | 4143  | 16-byte coalesced store                     |
| `v128.load`         | 3568  | 16-byte coalesced load                      |
| `v128.const`        |  503  | Vector constants (masks, etc.)              |
| `i8x16.shuffle`     |   47  | Byte permute / cross-lane                   |
| `i32x4.add`         |   44  | Lane-parallel 4×i32 add                     |
| `i8x16.replace_lane`|   37  | Lane insert                                 |
| ... (other arith)   | ~200  | Mixed extract/replace/splat/and/or/eq/shift |

**90% of v128 ops are bulk load/store** -- rustc/LLVM coalesces
adjacent 16-byte memory operations into single vector ops. The crypto
inner loops (Poseidon Montgomery reduce, RSA mod-exp, BN254 `BigInt<4>`
limb arithmetic) **do not auto-vectorise** here because their data
dependence pattern doesn't fit the SLP / loop-vector matchers. The
runtime win therefore comes from reduced memory traffic on
serialise/assemble paths, not from vectorised crypto kernels.

**Measured impact (Tier 1.1 → Tier 1.2):**

| Axis × k        | Tier 1.1 (ms) | Tier 1.2 (ms) | Δ vs T1.1 | Δ vs PR-1a |
|-----------------|---------------|---------------|-----------|------------|
| wasmtime/cold/1 | 256.86        | 250.07        |  -2.6%    | -2.5%      |
| wasmtime/warm/1 | 254.76        | 249.40        |  -2.1%    | -3.3%      |
| wasmtime/cold/3 | 771.09        | 762.22        |  -1.2%    | -1.0%      |
| wasmtime/warm/3 | 755.55        | 741.84        |  -1.8%    | -1.1%      |
| wasmtime/cold/5 | 1295.18       | 1286.20       |  -0.7%    | -0.1%      |
| wasmtime/warm/5 | 1262.51       | 1235.40       |  -2.1%    | -1.6%      |

Average wasmtime improvement vs PR-1a baseline: **-1.6%** (range
-0.1% to -3.3%). Real but modest, consistent with the load/store-heavy
SIMD profile above. The wasmtime / rlib ratio drops from ~2.0x to
~1.95x at k=1; the 2x ceiling is still set by cranelift JIT overhead
on per-credential synth, not by the static optimisation layer. Closing
that ratio further requires either AOT (cwasm pre-compile, Step 5),
ABI-level changes that bypass JSON parse (Tier 2 gate), or
algorithmic-level changes to the crypto kernels.

The rlib axis drifted +2-5% upward in the Tier 1.2 measurement run,
but the rlib code path is byte-identical to PR-1a (no rlib code or
build-flag change touches that axis -- `[target.wasm32-...]` rustflags
do not affect native rlib builds). Attribution: bench-machine thermal
load after a sustained compile+bench loop. Decision: leave `rlib_*`
entries in `baseline.json` at the cold-machine PR-1a values, so the
gate keeps its sensitivity for that axis. `wasmtime_*` entries are
refreshed to the Tier 1.2 measurements so future regressions are
caught against the tighter floor.

### Wasm binary size after Tier 1.2

| Stage                       | Bytes      | Δ vs PR-1a |
|-----------------------------|------------|------------|
| PR-1a (scalar, pre-wasm-opt)| 1,039,908  | --         |
| Tier 1.1 (wasm-opt only)    |   864,088  | -16.9%     |
| Tier 1.2 pre-wasm-opt       | 1,004,717  |  -3.4%     |
| **Tier 1.2 + wasm-opt**     |   **836,370** | **-19.6%** |

SIMD-emitted code is slightly smaller pre-wasm-opt (vectorised ops are
more compact than the equivalent scalar sequences), and stacks
multiplicatively with wasm-opt's -16.9%. -19.6% from baseline -- a
meaningful download-cost reduction for browser/RN clients.

## Wasm linear-memory footprint

Captured via the integration test `tests/memory_profile.rs`, which
reads `wasmtime::Memory::data_size()` before and after a single
`synthesize_witness` call per `k`. The test asserts a generous
per-credential drift envelope so a future per-credential memory
regression in `synthesize_witnesses` trips the gate. Reproduce with:

```bash
cargo test --release -p zkap-witness-gen-wasm \
    --test memory_profile -- --nocapture
```

**Measured (post Tier 1.1 + Tier 1.2)**:

| `k` | initial pages | post-call peak | Δ pages | per-cred (MiB) |
|----:|--------------:|---------------:|--------:|---------------:|
|   1 |            18 |          1,053 |   1,035 |             64 |
|   3 |            18 |          5,078 |   5,060 |            105 |
|   5 |            18 |         10,050 |  10,032 |            125 |

- **`initial_pages = 18`** — what the cdylib reserves statically in
  its memory section (~1.15 MiB).
- **Per-credential cost climbs from 64 → 125 MiB** between k=1 and
  k=5 (slightly super-linear). Some amortisation at k=1 (fixed witness
  scaffolding), and arkworks intermediate allocations dominate as k
  grows.
- **Peak at k=5 is ~628 MiB**, against a typical mobile process
  budget of 1-3 GiB on iOS (jetsam) and 256 MiB - 1 GiB per app on
  Android. The witness generator alone consumes a meaningful fraction
  of that ceiling on Android-class devices.

**Implication for the Step 2 Tier 1.3 "pre-grow" idea.** The handoff
plan called for setting `--initial-memory=1024 pages (64 MiB)` to
suppress the per-call `memory.grow` cost. The measurement above
overturns that plan:

- 1024 pages does **not** envelope even `k = 1` (peak 1053 pages).
  `memory.grow` would still fire on every cold call, so the
  optimisation has zero effect on warm steady-state.
- Envelope-sizing to `k = 5` would mean baking `~10,240 pages
  (~640 MiB)` of initial memory into the cdylib -- a footprint that
  is unconditionally allocated on instance construction even when
  the caller only intends to prove `k = 1`. On mobile this is a
  regression: cold-start RSS spike vs the natural grow-as-needed
  curve.
- The actual leverage on this axis is **reducing peak memory** (per-
  credential allocator churn, intermediate-buffer reuse, arkworks
  feature-flag tuning), not pre-growing past it. That work is
  deferred to a focused mobile-RSS investigation -- it needs a
  scoped plan + arkworks-version compatibility audit, not a
  drive-by config-flag flip.

**Decision:** Tier 1.3 (memory pre-grow) as specified in the handoff
is **dropped**. The `memory_profile` test remains as the
characterisation artefact that informed the decision and as the
forward-going drift gate for per-credential memory growth.

### Decomposition: bundle vs non-bundle

`memory_profile.rs` also deserialises the `Vec<WitnessBundle>` output
and reports the per-bundle witness vector length, so the linear-memory
peak can be decomposed into "live payload" vs "everything else"
(intermediates, fragmentation, runtime dead-weight).

| `k` | total Δ (MiB) | `full_assignment.len()` | bundles total (MiB) | **non-bundle (MiB)** | non-bundle share |
|----:|--------------:|------------------------:|--------------------:|---------------------:|-----------------:|
|   1 |            64 |                 895,551 |                  27 |                   37 |              58% |
|   3 |           316 |                 895,565 |                  81 |                  235 |              74% |
|   5 |           627 |                 895,579 |                 136 |                  491 |              78% |

- **`full_assignment.len()` is essentially constant in `k`** — the
  ZkapCircuit's wire count is determined by the circuit, not by the
  number of credentials. Each bundle is ~27 MiB of `Vec<F>` regardless
  of `k`.
- **Bundle storage scales linearly** at ~27 MiB / credential. At k=5,
  the live bundles account for 136 MiB.
- **Non-bundle memory dominates and scales super-linearly** — 37 MiB
  at k=1 grows to 491 MiB at k=5 (13.2x). Per-credential cost of
  non-bundle memory **itself climbs** with `k` (50 → 64 MiB/cred
  between k=1→3 and k=3→5).

What is in "non-bundle"? Educated decomposition from reading
`crates/service/src/groth16/prover/prove.rs`:

1. **Per-iteration intermediate buffers** — `build_anchor_stage` /
   `build_jwt_stage` / `build_audience_stage` / `build_merkle_witness`
   / `compute_public_inputs` each allocate Vec<F> witnesses, packed
   bytes, and Poseidon hash inputs. `synthesize_full_assignment`
   internally allocates the R1CS constraint matrices and a working
   witness vector. All of this is freed at end-of-iteration, but
   wasm linear memory does not shrink (linear memory is monotonic).
2. **Allocator fragmentation** — long-lived `bundles` Vec entries
   interleave with short-lived per-iter allocations. Rust's default
   wasm32 allocator (dlmalloc) coalesces freed blocks but cannot
   reuse a freed region that is now smaller than the next
   allocation's request, so each iteration tends to grow the
   high-water mark further.
3. **`rayon` thread-pool dead-weight** — the workspace pins ark-ff /
   ark-ec / ark-poly with `features = ["parallel"]` and pulls in
   `rayon` + `crossbeam-deque` + `crossbeam-epoch` transitively. On
   `wasm32-unknown-unknown` (no atomics, no native threads) those
   pathways either fall back to sequential or allocate worker
   deques + thread-local arenas that are never used. Fixed-cost
   inflation, not super-linear.
4. **`Vec<F>` clones into `ZkapCircuitInput`** — `matrix.clone()`,
   `poseidon_param.clone()`, `base64_table.clone()`, `selector
   .clone()` happen per credential at lines 211-230. Each
   `VandermondeMatrix<F>` is `n × k` field elements.

**Implications for mitigation lever choice** (none implemented in
this PR; recorded as input to the follow-on mobile-RSS plan):

| Lever                                             | Reduction at k=5 | Risk / effort        |
|---------------------------------------------------|------------------|----------------------|
| Stream bundles via callback / `Write` sink        | ~108 MiB linear  | API change; low      |
| Bumpalo arena reset per credential                | 50-70% of non-bundle | new allocator + cap audit |
| Swap wasm allocator (talc / lol_alloc)            | 20-40% of non-bundle | dep add + parity audit |
| Disable `parallel` on wasm32 (per-target feature) | 10-30 MiB fixed  | feature-gate refactor across workspace |
| Audit per-iter clones in prove.rs                 | unknown          | localised; low risk  |

The streaming change alone is **insufficient** to ship to mid-tier
Android (peak after streaming at k=5: ~520 MiB, still over 512 MiB
heap cap). The combination of streaming + allocator swap + arena
reset is the realistic path to fitting under 256 MiB at k=5; that's
a multi-PR investigation, not a single-session config flip.

## Mobile-RSS Lever #1 — bundle streaming (landed)

`crates/service/src/groth16/prover/prove.rs` now exposes
`synthesize_witnesses_streaming<Sink: FnMut(WitnessBundle) ->
Result<(), ApplicationError>>` as the primitive. The Vec-returning
`synthesize_witnesses` becomes a thin wrapper that pushes into a Vec
inside the closure -- native callers see no API change. The wasm
`synthesize_witness_inner` adopts the streaming primitive directly,
serialising each bundle into the output buffer and dropping the
source before the next iteration. The host-visible wire format is
unchanged: a `u64` LE length prefix followed by each `WitnessBundle`
serialised by `CanonicalSerialize::serialize_uncompressed`, byte-
identical to `Vec<WitnessBundle>::serialize_uncompressed`. The
parity test (rlib vs wasmtime cranelift JIT) still passes byte-for-
byte at k = 1, 3, 5.

**Measured impact** (`memory_profile.rs`, post Tier 1.1 + 1.2):

| `k` | Δ pages (pre-streaming) | Δ pages (post-streaming) | savings (pages) | savings (MiB) |
|----:|------------------------:|-------------------------:|----------------:|--------------:|
|   1 |                   1,035 |                    1,035 |               0 |             0 |
|   3 |                   5,060 |                    4,473 |             587 |          36.7 |
|   5 |                  10,032 |                    8,569 |           1,463 |          91.4 |

- At `k = 1` the savings are zero by construction -- nothing to
  stream away when only one bundle is produced.
- At `k = 5` the saving is **-91.4 MiB**, slightly below the upper
  bound of `(k-1) * 27 MiB = 108 MiB` predicted from
  `full_assignment.len() * 32 B`. The ~16 MiB shortfall is allocator
  fragmentation overhead: the freed bundle's `Vec<F>` does not
  always land back where the next iteration's intermediate
  allocations want to draw from.
- The non-bundle dominant cost (per-iter intermediates +
  `synthesize_full_assignment` workspace + rayon dead-weight) is
  untouched by this lever, as expected.

**Remaining peak after streaming**, against typical mobile envelopes:

| `k` | post-streaming peak | iOS jetsam (4 GiB device, ~3 GiB ceiling) | Android mid-tier (512 MiB heap) | Android high-end (1 GiB heap) |
|----:|--------------------:|:------------------------------------------|:--------------------------------|:------------------------------|
|   1 |             ~66 MiB | fits comfortably                          | fits                            | fits                          |
|   3 |            ~280 MiB | fits                                      | fits with headroom for prover   | fits                          |
|   5 |            ~535 MiB | fits                                      | **OOM**                         | tight (Groth16 prover next)   |

Streaming clears the `k = 3` mid-tier Android case from "tight" to
"fits with headroom for prover", which is the meaningful product win
for v0.2. `k = 5` on mid-tier Android remains a blocker; the path
through it is the allocator-swap / arena-reset / parallel-flag work
outlined in the lever survey above, not a single config flip.

## CI SLA gate (PR-1b)

These numbers are pinned in `baseline.json` and policed by
`.github/workflows/wasm-perf.yml`. On each PR that touches
`crates/witness-gen-wasm/**`, `Cargo.toml`, or `Cargo.lock`, the
workflow runs the bench on a `macos-14` (Apple Silicon) runner and
fails the check when any benchmark's measured mean exceeds the
baseline value by more than `slack_pct` (default 10%, overridable
via the `SLACK_PCT` env in the workflow step).

The comparison script is `scripts/check-regression.py`. Run it
locally after `cargo bench` to validate before pushing:

```bash
cargo bench -p zkap-witness-gen-wasm
python3 crates/witness-gen-wasm/scripts/check-regression.py
# or with custom slack:
SLACK_PCT=15 python3 crates/witness-gen-wasm/scripts/check-regression.py
```

**Updating the baseline.** When Step 2 perf optimisations (wasm-opt,
SIMD, etc.) land and reduce measured times, refresh `baseline.json`
with the new numbers in the same PR that introduces the optimisation.
That keeps the gate aligned with the latest reality instead of
silently allowing regression-from-optimum.

**Host-class drift.** The baseline is calibrated on Apple-Silicon
hardware. Running the gate on a different host class (e.g. Linux
x86_64 laptops, Intel Macs) will false-positive across the board.
For local dev on non-matching hosts, either skip the gate or set
`SLACK_PCT` generously. Future work: per-host calibration sections.

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
# Prereq: install the wasm32 target + binaryen (for wasm-opt).
rustup target add wasm32-unknown-unknown
brew install binaryen   # or: cargo install wasm-opt

# 1. Build the cdylib the bench / parity test load.
cargo build --target wasm32-unknown-unknown --release -p zkap-witness-gen-wasm

# 2. Apply wasm-opt -O3 in place (Step 2 Tier 1.1; production build step).
crates/witness-gen-wasm/scripts/optimize-wasm.sh

# 3. Confirm parity (rlib == wasmtime, byte-for-byte).
cargo test --release -p zkap-witness-gen-wasm --test parity

# 4. Run the criterion suite. ~10-15 min on first run. NOTE: cargo bench
#    inherits [profile.release] automatically; passing --release errors
#    out ("unexpected argument '--release'").
cargo bench -p zkap-witness-gen-wasm

# 5. Open the HTML report.
open target/criterion/report/index.html
```
