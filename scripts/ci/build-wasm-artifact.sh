#!/usr/bin/env bash
# Build + wasm-opt the zkap-witness-gen-wasm cdylib into <output_path>.
# optimize-wasm.sh is the single source of truth for wasm-opt flags.
# Used by ci.yml `wasm-build-smoke` (uploads artifact) and release.yml
# `build-wasm` (uploads artifact).
#
# Contract: optimize-wasm.sh reads the cdylib from a HARDCODED canonical
# path (`target/wasm32-unknown-unknown/release/zkap_witness_gen_wasm.wasm`,
# see optimize-wasm.sh:23). Its only argument is the OUTPUT target. We
# must therefore run `cargo build` first so the canonical input exists,
# then pass `$OUT` as the output destination.
set -euo pipefail
OUT="${1:?usage: $0 <output_path>}"
cargo build -p zkap-witness-gen-wasm --target wasm32-unknown-unknown --release --locked
mkdir -p "$(dirname "$OUT")"
bash crates/witness-gen-wasm/scripts/optimize-wasm.sh "$OUT"
