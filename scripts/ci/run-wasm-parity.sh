#!/usr/bin/env bash
# Smoke (manifest hash == file hash) + Parity (native rlib vs wasm bytes
# equal on toy fixtures k=1, k=3, k=5).
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

# Smoke
MANIFEST="$BUNDLE_DIR/manifest.json"
if [ ! -f "$MANIFEST" ]; then echo "::error::missing $MANIFEST" >&2; exit 1; fi
if [ ! -f "$WASM_PATH" ]; then echo "::error::missing $WASM_PATH" >&2; exit 1; fi
WASM_SHA=$(sha256sum "$WASM_PATH" | awk '{print $1}')
MANIFEST_SHA=$(jq -r '.artifacts.witness_gen.sha256 // empty' "$MANIFEST")
if [ -z "$MANIFEST_SHA" ]; then
  echo "::error::manifest.json has no .artifacts.witness_gen.sha256 entry" >&2
  exit 1
fi
if [ "$WASM_SHA" != "$MANIFEST_SHA" ]; then
  echo "::error::wasm sha256 mismatch: file=$WASM_SHA manifest=$MANIFEST_SHA" >&2
  exit 1
fi
echo "Smoke OK: manifest.artifacts.witness_gen.sha256 == file sha256 = $WASM_SHA"

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
