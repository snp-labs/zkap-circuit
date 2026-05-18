#!/usr/bin/env bash
# Post-build wasm-opt pass for the witness-gen-wasm cdylib.
#
# The crate is built via plain `cargo build --target wasm32-unknown-unknown
# --release -p zkap-witness-gen-wasm` (no wasm-pack), so `[package.metadata.
# wasm-pack.profile.release].wasm-opt` would be a no-op. This script is the
# canonical post-build optimisation step: it runs wasm-opt -O3 over the
# cdylib in place so both the parity test and the criterion bench load the
# production-representative binary.
#
# Step 2 Tier 1.1 of the cross-platform SDK plan. See PERF.md.
#
# Usage:
#   crates/witness-gen-wasm/scripts/optimize-wasm.sh           # in-place
#   crates/witness-gen-wasm/scripts/optimize-wasm.sh /tmp/out  # to a target
#
# Idempotent: re-running on an already-optimised binary is a (small) no-op.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../../.." && pwd)"
wasm="$repo_root/target/wasm32-unknown-unknown/release/zkap_witness_gen_wasm.wasm"
out="${1:-$wasm}"

if ! command -v wasm-opt >/dev/null 2>&1; then
    echo "error: wasm-opt not found on PATH" >&2
    echo "       install via 'cargo install wasm-opt' or 'brew install binaryen'" >&2
    exit 1
fi

if [[ ! -f "$wasm" ]]; then
    echo "error: cdylib missing at $wasm" >&2
    echo "       run 'cargo build --target wasm32-unknown-unknown --release -p zkap-witness-gen-wasm' first" >&2
    exit 1
fi

size_before=$(wc -c <"$wasm" | tr -d ' ')

# -O3 is wasm-opt's strongest size+speed pass (-Os is size-first).
# The --enable-* flags whitelist the wasm features the Rust wasm32 backend
# emits by default; without them wasm-opt rejects the input. SIMD is left
# enabled here because Tier 1.2 will also flip rustc's +simd128 target
# feature, and we want the pipeline ready for both.
wasm-opt \
    -O3 \
    --enable-simd \
    --enable-bulk-memory \
    --enable-mutable-globals \
    --enable-sign-ext \
    --enable-nontrapping-float-to-int \
    "$wasm" \
    -o "$out"

size_after=$(wc -c <"$out" | tr -d ' ')
delta_pct=$(awk -v b="$size_before" -v a="$size_after" 'BEGIN { printf "%.1f", (a-b)*100/b }')

printf "wasm-opt: %s\n" "$out"
printf "  before:  %'d bytes\n" "$size_before"
printf "  after:   %'d bytes\n" "$size_after"
printf "  delta:   %s%%\n" "$delta_pct"
