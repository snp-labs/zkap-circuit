#!/usr/bin/env bash
# Smoke (bundle witness_gen.wasm == freshly built wasm) + Parity (native rlib
# vs wasm bytes equal on toy fixtures k=1, k=3, k=5).
#
# NOTE: witness_gen.wasm is no longer a manifest artifact (the sha/signature
# byte-pin was removed — it carries no circuit trust). It ships as a plain
# unsigned file in the bundle, so the smoke step compares the bundle's copy to
# the freshly built wasm directly rather than to a manifest sha entry.
#
# Pre-condition: caller MUST pre-place the wasm at the canonical path
# `target/wasm32-unknown-unknown/release/zkap_witness_gen_wasm.wasm`
# because `wasm_artifact_path()` (crates/witness-gen-wasm/benches/common/mod.rs:274-291)
# is hardcoded — no env-var override is possible without changing crate
# source code (Non-goal 1 of this PR's spec).
#
# `$2` (<wasm_file>) is used ONLY for the Smoke step. Parity always reads
# the canonical hardcoded path.
#
# Parity validates wasm vs native rlib on the toy fixtures defined by
# `bench_config(k)` (common/mod.rs:57-79). This does NOT validate that
# the wasm produces correct output for the bundle's actual config.json.
# Bundle-circuit parity is a known coverage gap closed by Follow-up F2
# (R1CS preflight in CI).
set -euo pipefail
BUNDLE_DIR="${1:?usage: $0 <bundle_dir> <wasm_file>}"
WASM_PATH="${2:?usage: $0 <bundle_dir> <wasm_file>}"

# Smoke — witness_gen.wasm is a plain (unsigned, non-manifest) bundle file
# since the byte-pin was removed; verify the bundle copy matches the freshly
# built wasm.
MANIFEST="$BUNDLE_DIR/manifest.json"
BUNDLE_WASM="$BUNDLE_DIR/witness_gen.wasm"
if [ ! -f "$MANIFEST" ]; then echo "::error::missing $MANIFEST" >&2; exit 1; fi
if [ ! -f "$WASM_PATH" ]; then echo "::error::missing $WASM_PATH" >&2; exit 1; fi
if [ ! -f "$BUNDLE_WASM" ]; then
  echo "::error::bundle has no witness_gen.wasm at $BUNDLE_WASM" >&2
  exit 1
fi
WASM_SHA=$(sha256sum "$WASM_PATH" | awk '{print $1}')
BUNDLE_WASM_SHA=$(sha256sum "$BUNDLE_WASM" | awk '{print $1}')
if [ "$WASM_SHA" != "$BUNDLE_WASM_SHA" ]; then
  echo "::error::bundle witness_gen.wasm sha256 mismatch: built=$WASM_SHA bundle=$BUNDLE_WASM_SHA" >&2
  exit 1
fi
echo "Smoke OK: bundle witness_gen.wasm == built wasm sha256 = $WASM_SHA"

# Parity — explicit test names, count assertion.
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
cargo test --release -p zkap-witness-gen-wasm --test parity --locked -- \
  --ignored --exact parity_k1 parity_k3 parity_k5 2>&1 | tee "$LOG"
if ! grep -qE 'test result: ok\. 3 passed' "$LOG"; then
  echo "::error::parity test did not report 'test result: ok. 3 passed'. \
    Investigate silent-skip or test-rename." >&2
  exit 1
fi
echo "Parity OK: 3 tests (parity_k1, parity_k3, parity_k5) passed"
