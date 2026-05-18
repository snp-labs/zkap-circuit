//! Byte-for-byte parity between the rlib (native) and the wasm32
//! (wasmtime cranelift JIT) witness-gen paths.
//!
//! `CanonicalSerialize::serialize_uncompressed` on
//! `Vec<WitnessBundle>` is deterministic, so any divergence between
//! the two paths is a regression — either in the wasm build or in a
//! transitive dep that branches on `target_arch = "wasm32"`. This
//! test is the canonical guard.
//!
//! Prereq: the wasm cdylib must be built first —
//!
//!   cargo build --target wasm32-unknown-unknown --release \
//!       -p zkap-witness-gen-wasm
//!
//! Then:
//!
//!   cargo test --release -p zkap-witness-gen-wasm --test parity

#[path = "../benches/common/mod.rs"]
mod common;

use common::wasm_runner::WasmModule;
use common::{build_fixture, fixture_json, wasm_artifact_path};

fn parity_for_k(k: u64) {
    let (cfg, req) = build_fixture(k);
    let (req_json, cfg_json) = fixture_json(&cfg, &req);

    let native = zkap_witness_gen_wasm::synthesize_witness_bytes(&req_json, &cfg_json)
        .expect("native rlib synthesize");

    let wasm = WasmModule::from_path(&wasm_artifact_path()).expect("load wasm");
    let mut instance = wasm.instantiate().expect("instantiate wasm");
    let wasm_bytes = instance
        .synthesize(&req_json, &cfg_json)
        .expect("wasm synthesize");

    assert_eq!(
        native.len(),
        wasm_bytes.len(),
        "k={k}: native vs wasm output length mismatch ({} vs {})",
        native.len(),
        wasm_bytes.len()
    );
    assert!(
        native == wasm_bytes,
        "k={k}: native vs wasm bytes differ (first diff search needed)"
    );
}

#[test]
fn parity_k1() {
    parity_for_k(1);
}

#[test]
fn parity_k3() {
    parity_for_k(3);
}

#[test]
fn parity_k5() {
    parity_for_k(5);
}
