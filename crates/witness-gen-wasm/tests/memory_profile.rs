//! Wasm linear-memory footprint characterisation under the wasmtime
//! cranelift JIT axis.
//!
//! The criterion bench measures wall-clock per-call cost only.
//! `memory.grow` is the dominant per-call linear-memory cost that
//! `Tier 1.3` (cdylib `--initial-memory` pre-grow) targets, but it
//! shows up in the runtime number only as a fraction of the cold-call
//! delta. This test reports the *direct* metric -- initial pages
//! baked into the cdylib + per-call peak pages -- so the Tier 1.3
//! effect can be verified independently of the cold/warm runtime
//! noise floor.
//!
//! Output is `eprintln!`-printed in a table; run with `--nocapture`
//! to see it:
//!
//! ```bash
//! cargo build --target wasm32-unknown-unknown --release \
//!     -p zkap-witness-gen-wasm
//! cargo test --release -p zkap-witness-gen-wasm \
//!     --test memory_profile -- --nocapture
//! ```
//!
//! Drift gate: per-credential page consumption stays within a generous
//! envelope. Catches O(k>1) memory blow-up regressions in `synthesize_
//! witnesses` without pinning the absolute number (which is workload-
//! and arkworks-version dependent).

#[path = "../benches/common/mod.rs"]
mod common;

use common::wasm_runner::{WASM_PAGE_SIZE, WasmModule};
use common::{build_fixture, fixture_json, wasm_artifact_path};

/// Generous upper bound on pages consumed per credential by
/// `synthesize_witnesses`. Current observation (post Tier 1.1 + 1.2):
/// ~2000 pages/credential = ~125 MiB/credential. The envelope here
/// (5000 pages = ~312 MiB / credential) catches blow-up regressions
/// while tolerating workload-dependent slop.
const PAGES_PER_CRED_ENVELOPE: usize = 5_000;

#[test]
fn memory_profile_k1_k3_k5() {
    let module = WasmModule::from_path(&wasm_artifact_path()).expect("load wasm");

    let initial_pages = module.instantiate().expect("init instance").memory_pages();

    let mut rows: Vec<(u64, usize, usize)> = Vec::new();
    for &k in &[1u64, 3, 5] {
        let (cfg, req) = build_fixture(k);
        let (req_json, cfg_json) = fixture_json(&cfg, &req);
        let mut instance = module.instantiate().expect("fresh instance per k");
        let pre_pages = instance.memory_pages();
        instance
            .synthesize(&req_json, &cfg_json)
            .expect("synth must succeed");
        let post_pages = instance.memory_pages();
        rows.push((k, pre_pages, post_pages));
    }

    eprintln!();
    eprintln!("=== wasm linear-memory profile (1 page = 64 KiB) ===");
    eprintln!(
        "  initial pages baked into cdylib: {initial_pages} ({} KiB)",
        initial_pages * WASM_PAGE_SIZE / 1024
    );
    eprintln!();
    eprintln!(
        "  {:>3}  {:>15}  {:>15}  {:>10}  {:>13}",
        "k", "pre-call pages", "post-call pages", "Δ pages", "MiB / cred"
    );
    eprintln!("  {}", "-".repeat(68));
    for (k, pre, post) in &rows {
        let delta = (*post as isize) - (*pre as isize);
        let mib_per_cred = (delta.max(0) as usize) * WASM_PAGE_SIZE / (*k as usize) / (1024 * 1024);
        eprintln!(
            "  {:>3}  {:>15}  {:>15}  {:>10}  {:>13}",
            k, pre, post, delta, mib_per_cred
        );
    }
    eprintln!();
    eprintln!(
        "  drift envelope: {PAGES_PER_CRED_ENVELOPE} pages/cred ({} MiB/cred)",
        PAGES_PER_CRED_ENVELOPE * WASM_PAGE_SIZE / (1024 * 1024)
    );
    eprintln!();

    // Drift gate: catch O(k>1) blow-ups in synthesize_witnesses without
    // pinning the absolute number (workload + arkworks-version
    // dependent). The envelope is generous (~2.5x current usage).
    for (k, pre, post) in &rows {
        let delta = (*post as isize - *pre as isize).max(0) as usize;
        let per_cred = delta / (*k as usize);
        assert!(
            per_cred <= PAGES_PER_CRED_ENVELOPE,
            "k={k}: {per_cred} pages/credential exceeds envelope {PAGES_PER_CRED_ENVELOPE} \
             -- investigate synthesize_witnesses for per-credential memory regression"
        );
    }
}
