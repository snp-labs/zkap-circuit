#!/usr/bin/env bash
#
# scripts/check-removed-api.sh
#
# Migration boundary red-phase check.
#
# Verifies that the legacy ark-ar1cs / .arzkey / wasm-witness surface area
# slated for removal by the 2026-05 boundary migration is absent from the
# working tree. Each rule searches for one residue symbol/path; any non-zero
# match is reported with line numbers and the script exits non-zero.
#
# This script is INTENTIONALLY EXPECTED RED during migration Commits 1-6,
# because the legacy code is still present in those commits. It is wired
# into CI as a required gate only at Commit 7 (cleanup); until then it is
# either skipped or run as an informational job.
#
# Usage:
#   bash scripts/check-removed-api.sh
#
# Exit status:
#   0 = every rule clean (post-migration goal state)
#   1 = at least one rule reported residue
#   2 = environment/setup error (e.g. rg missing)
#
# Excluded paths (every rule applies the same exclusion set):
#   - target/                         (build output)
#   - .git/                           (vcs metadata)
#   - .omc/, .gstack/, .claude/, .config/  (tooling state)
#   - docs/                           (planning/reference docs handle the
#                                      migration narrative separately)
#   - dist/                           (release artifact blobs, regenerated
#                                      by the post-migration generate_setup)
#   - Cargo.lock                      (auto-managed; references in the lock
#                                      file disappear after `cargo update`)
#   - scripts/check-removed-api.sh    (self-reference)
#   - scripts/check-bundle-layout.sh  (companion script, mentions same paths)

set -u
# Note: -e is intentionally NOT set; we want every rule to run so the
# report is cumulative even when an earlier rule fails.

if ! command -v rg >/dev/null 2>&1; then
  echo "scripts/check-removed-api.sh: ripgrep (rg) is required but not on PATH" >&2
  exit 2
fi

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "$REPO_ROOT" || exit 2

# Shared exclude globs.
COMMON_EXCLUDES=(
  --glob '!target/**'
  --glob '!.git/**'
  --glob '!.omc/**'
  --glob '!.gstack/**'
  --glob '!.claude/**'
  --glob '!.config/**'
  --glob '!docs/**'
  --glob '!dist/**'
  --glob '!Cargo.lock'
  --glob '!scripts/check-removed-api.sh'
  --glob '!scripts/check-bundle-layout.sh'
)

VIOLATIONS=0

# run_rule <id> <description> <rg-args...>
#
# Run a single ripgrep rule under the shared exclusion set. Any output is
# reported under the rule id with the matching file:line prefix preserved.
run_rule() {
  local id="$1"
  local desc="$2"
  shift 2

  local hits
  hits="$(rg --no-heading --color=never --line-number "${COMMON_EXCLUDES[@]}" "$@" 2>/dev/null || true)"

  if [ -n "$hits" ]; then
    VIOLATIONS=$((VIOLATIONS + 1))
    {
      printf 'VIOLATION [%s] %s\n' "$id" "$desc"
      printf '%s\n' "$hits" | sed 's/^/    /'
      printf '\n'
    } >&2
  fi
}

# ─── Rules ────────────────────────────────────────────────────────────────────

# I1 — .arzkey envelope artifact + ArzkeyFile type.
run_rule "I1.arzkey_type"     "ArzkeyFile type must be removed"                     -e 'ArzkeyFile'
run_rule "I1.arzkey_word"     "arzkey artifact references must be removed"           -e '\barzkey\b'

# I2 — .arwtns serialized witness + ArwtnsFile type.
run_rule "I2.arwtns_type"     "ArwtnsFile type must be removed"                     -e 'ArwtnsFile'
run_rule "I2.arwtns_word"     "arwtns artifact references must be removed"           -e '\barwtns\b'

# I3 — from_setup_output helper that bundled (ArcsFile, ProvingKey).
run_rule "I3.from_setup"      "from_setup_output helper must be removed"             -e 'from_setup_output'

# I4 — WitnessGenerator trait + export_witness_generator! macro.
run_rule "I4.wgen_trait"      "WitnessGenerator trait must be removed"               -e '\bWitnessGenerator\b'
run_rule "I4.wgen_macro"      "export_witness_generator! macro must be removed"      -e 'export_witness_generator'

# I5 — wasmi runtime stack inside the prove path.
run_rule "I5.wasmi_word"      "wasmi runtime usage must be removed"                  -e '\bwasmi\b'
run_rule "I5.wasm_runtime"    "WasmWitnessRuntime trait must be removed"             -e 'WasmWitnessRuntime'
run_rule "I5.default_runtime" "DefaultRuntime alias must be removed"                 -e '\bDefaultRuntime\b'

# I6 — VerifyingContext opaque wrapper.
run_rule "I6.verifying_ctx"   "VerifyingContext type must be removed"                -e 'VerifyingContext'

# I7 — public verify wrapper inside service crate.
run_rule "I7.verify_pubfn"    "service crate public 'pub fn verify' must be removed" \
  -e 'pub fn verify\b' --glob 'crates/service/src/**'

# I8 — fast-prove feature flag.
run_rule "I8.fast_prove"      "fast-prove feature must be removed"                   -e 'fast-prove'

# I9 — obsolete feature flags.
run_rule "I9.use_optimized"   "use-optimized feature must be removed"                -e 'use-optimized'
run_rule "I9.runtime_wasmi"   "runtime-wasmi feature must be removed"                -e 'runtime-wasmi'
run_rule "I9.runtime_wasmtim" "runtime-wasmtime feature must be removed"             -e 'runtime-wasmtime'

# I10 — RawProofRequest type rename to ProofRequest.
run_rule "I10.raw_proof_req"  "RawProofRequest type must be renamed to ProofRequest" -e '\bRawProofRequest\b'

# I11 — generate_crs CLI binary.
run_rule "I11.generate_crs"   "generate_crs CLI binary must be removed"              -e 'generate_crs'

# I12 — deprecated ark-ar1cs-* crate dependencies.
run_rule "I12.dep_zkey"       "ark-ar1cs-zkey workspace dependency must be removed"       -e 'ark-ar1cs-zkey'
run_rule "I12.dep_wtns"       "ark-ar1cs-wtns workspace dependency must be removed"       -e 'ark-ar1cs-wtns'
run_rule "I12.dep_wwitness"   "ark-ar1cs-wasm-witness workspace dependency must be removed" -e 'ark-ar1cs-wasm-witness'
run_rule "I12.dep_prover"     "ark-ar1cs-prover workspace dependency must be removed"     -e 'ark-ar1cs-prover'

# I13 — legacy artifact filenames + struct path fields.
run_rule "I13.wasm_blob"      "zkap_witness_wasm.opt.wasm artifact reference must be removed" \
  --fixed-strings 'zkap_witness_wasm.opt.wasm'
run_rule "I13.pk_arzkey_file" "pk.arzkey filename reference must be removed"         --fixed-strings 'pk.arzkey'
run_rule "I13.pk_key_file"    "pk.key filename reference must be removed (use pk.bin)"    --fixed-strings 'pk.key'
run_rule "I13.vk_key_file"    "vk.key filename reference must be removed (use vk.bin)"    --fixed-strings 'vk.key'
run_rule "I13.pvk_key_file"   "pvk.key filename reference must be removed (use pvk.bin)"  --fixed-strings 'pvk.key'
run_rule "I13.wasm_path"      "wasm_path field/param must be removed"                -e '\bwasm_path\b'
run_rule "I13.wasm_bytes"     "wasm_bytes field/param must be removed"               -e '\bwasm_bytes\b'

# ─── Report ───────────────────────────────────────────────────────────────────

if [ "$VIOLATIONS" -gt 0 ]; then
  {
    printf 'scripts/check-removed-api.sh: %d rule(s) reported residue\n' "$VIOLATIONS"
    printf '(EXPECTED RED during migration Commits 1-6; activated as required CI gate at Commit 7)\n'
  } >&2
  exit 1
fi

printf 'scripts/check-removed-api.sh: all migration-boundary rules clean\n'
exit 0
