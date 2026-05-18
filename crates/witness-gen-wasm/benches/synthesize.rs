//! Criterion bench suite for the witness-gen-wasm crate.
//!
//! Measures two canonical paths today:
//!
//! - **rlib (native)** — direct call into
//!   `zkap_witness_gen_wasm::synthesize_witness_bytes`.
//! - **wasmtime cranelift JIT** — load the cdylib build of this
//!   crate (`target/wasm32-unknown-unknown/release/
//!   zkap_witness_gen_wasm.wasm`) and invoke the C ABI exports.
//!
//! Two AOT/interpreter axes are scoped in but currently deferred —
//! see the `#[cfg(feature = "wasmtime_aot")]` /
//! `#[cfg(feature = "wasmtime_pulley")]` gates. PERF.md tracks the
//! rationale.
//!
//! Two measurement modes per axis × k:
//!
//! - **cold** — instance + buffer setup re-run per iteration
//!   (`iter_batched` + `BatchSize::PerIteration`).
//! - **warm** — instance reused across iterations (standard `iter`).
//!
//! Workload variants: `k ∈ {1, 3, 5}` (credentials per batch).
//!
//! Prereq: run
//!   `cargo build --target wasm32-unknown-unknown --release -p zkap-witness-gen-wasm`
//! before `cargo bench` so the wasm artifact is available.

// The workspace lints `missing_docs = "warn"`. The `criterion_group!`
// macro emits a top-level function (`benches`) without a doc comment,
// which trips the lint inside the macro expansion. Allowing here is
// the only way to keep `criterion_group!` clean — the macro is
// out-of-tree.
#![allow(missing_docs)]

mod common;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use common::wasm_runner::WasmModule;
use common::{build_fixture, fixture_json, wasm_artifact_path};

const KS: [u64; 3] = [1, 3, 5];

fn bench_rlib(c: &mut Criterion) {
    let mut group = c.benchmark_group("rlib_native");

    for &k in &KS {
        let (cfg, req) = build_fixture(k);
        let (req_json, cfg_json) = fixture_json(&cfg, &req);

        group.throughput(Throughput::Elements(k));

        // Warm: criterion's standard `iter` reuses the same inputs
        // across iterations.
        group.bench_with_input(BenchmarkId::new("warm", k), &k, |b, _| {
            b.iter(|| {
                zkap_witness_gen_wasm::synthesize_witness_bytes(&req_json, &cfg_json)
                    .expect("rlib synthesize must succeed")
            });
        });

        // Cold for rlib is a noop semantically (no instance to
        // re-instantiate), but we still measure with
        // `iter_batched(PerIteration)` so the comparison against the
        // wasm cold path is apples-to-apples.
        group.bench_with_input(BenchmarkId::new("cold", k), &k, |b, _| {
            b.iter_batched(
                || (req_json.clone(), cfg_json.clone()),
                |(req, cfg)| {
                    zkap_witness_gen_wasm::synthesize_witness_bytes(&req, &cfg)
                        .expect("rlib synthesize must succeed")
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

fn bench_wasmtime_jit(c: &mut Criterion) {
    let wasm = WasmModule::from_path(&wasm_artifact_path())
        .expect("compile wasm under wasmtime cranelift");

    let mut group = c.benchmark_group("wasmtime_jit");

    for &k in &KS {
        let (cfg, req) = build_fixture(k);
        let (req_json, cfg_json) = fixture_json(&cfg, &req);

        group.throughput(Throughput::Elements(k));

        // Warm: instance + JIT'd code reused across iterations.
        group.bench_with_input(BenchmarkId::new("warm", k), &k, |b, _| {
            let mut instance = wasm.instantiate().expect("warm-warmup instance must build");
            // Prime the instance with one call so any allocator
            // first-touch lands outside the measured region.
            let _ = instance
                .synthesize(&req_json, &cfg_json)
                .expect("warm-priming synthesize");

            b.iter(|| {
                instance
                    .synthesize(&req_json, &cfg_json)
                    .expect("wasm synthesize must succeed")
            });
        });

        // Cold: new instance per iteration (engine + module reused;
        // only `Instance::new` + first-touch buffers in the path).
        group.bench_with_input(BenchmarkId::new("cold", k), &k, |b, _| {
            b.iter_batched(
                || wasm.instantiate().expect("instantiate per cold iter"),
                |mut instance| {
                    instance
                        .synthesize(&req_json, &cfg_json)
                        .expect("wasm synthesize must succeed")
                },
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

// AOT cwasm + pulley interpreter benches are deferred — see PERF.md.
// They sit behind cargo features so a follow-up PR can light them up
// without touching this bench's signature.
#[cfg(feature = "wasmtime_aot")]
fn bench_wasmtime_aot(_c: &mut Criterion) {
    // Intentionally empty stub; wire up `Engine::precompile_module`
    // + `Module::deserialize` here when the AOT axis lands.
}

#[cfg(feature = "wasmtime_pulley")]
fn bench_wasmtime_pulley(_c: &mut Criterion) {
    // Intentionally empty stub; wire up the pulley interpreter
    // strategy here when the pulley axis lands.
}

criterion_group!(benches, bench_rlib, bench_wasmtime_jit);
criterion_main!(benches);
