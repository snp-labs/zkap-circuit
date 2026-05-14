#!/usr/bin/env bash
#
# scripts/check-bundle-layout.sh
#
# Migration boundary red-phase check.
#
# Verifies that one or more CRS bundle directories match the post-migration
# target layout: a single 7-file bundle with no legacy `.arzkey` / `.key` /
# wasm-witness artifacts.
#
# Target files (must be present):
#   - circuit.ar1cs
#   - pk.bin
#   - vk.bin
#   - pvk.bin
#   - Groth16Verifier.sol
#   - config.json
#   - manifest.json
#
# Forbidden files (must NOT be present):
#   - pk.arzkey
#   - pk.key, vk.key, pvk.key   (replaced by `.bin` per Q3 decision)
#   - zkap_witness_wasm.opt.wasm, zkap_witness_wasm.wasm
#
# Usage:
#   bash scripts/check-bundle-layout.sh                      # default: dist/1-of-1 and dist/3-of-3
#   bash scripts/check-bundle-layout.sh <dir> [<dir>...]     # check specific directories
#
# The script does NOT invoke `generate_setup`; it is a static directory
# inspector. The intended Commit-2-or-later flow is:
#   1. run `generate_setup --output <tmp>` (or use a checked-in dist dir),
#   2. run `bash scripts/check-bundle-layout.sh <tmp>`.
# Skipping the invocation keeps this script side-effect free and fast.
#
# Exit status:
#   0 = every checked directory matches the post-migration layout
#   1 = at least one violation (missing required file or forbidden file present)
#   2 = environment/setup error
#
# This script is INTENTIONALLY EXPECTED RED during migration Commits 1-6
# (the on-disk dist/ artifacts still ship in the legacy layout). It is
# wired into CI as a required gate only at Commit 7 (cleanup), once dist
# is regenerated.

set -u

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "$REPO_ROOT" || exit 2

if [ "$#" -gt 0 ]; then
  TARGETS=( "$@" )
else
  TARGETS=( dist/1-of-1 dist/3-of-3 )
fi

REQUIRED=(
  circuit.ar1cs
  pk.bin
  vk.bin
  pvk.bin
  Groth16Verifier.sol
  config.json
  manifest.json
)

FORBIDDEN=(
  pk.arzkey
  pk.key
  vk.key
  pvk.key
  zkap_witness_wasm.opt.wasm
  zkap_witness_wasm.wasm
)

VIOLATIONS=0

# check_dir <dir>
#
# Validate that <dir> exists, contains every REQUIRED file, and contains
# none of the FORBIDDEN files. Each missing/extra entry is reported on
# stderr; the function does not exit early.
check_dir() {
  local dir="$1"

  if [ ! -d "$dir" ]; then
    printf 'VIOLATION [bundle-layout] directory does not exist: %s\n' "$dir" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
    return
  fi

  local f
  for f in "${REQUIRED[@]}"; do
    if [ ! -f "$dir/$f" ]; then
      printf 'VIOLATION [bundle-layout] missing required file: %s/%s\n' "$dir" "$f" >&2
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done

  for f in "${FORBIDDEN[@]}"; do
    if [ -e "$dir/$f" ]; then
      printf 'VIOLATION [bundle-layout] forbidden legacy artifact present: %s/%s\n' "$dir" "$f" >&2
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done
}

for d in "${TARGETS[@]}"; do
  check_dir "$d"
done

if [ "$VIOLATIONS" -gt 0 ]; then
  {
    printf 'scripts/check-bundle-layout.sh: %d violation(s)\n' "$VIOLATIONS"
    printf '(EXPECTED RED during migration Commits 1-6; activated as required CI gate at Commit 7)\n'
  } >&2
  exit 1
fi

printf 'scripts/check-bundle-layout.sh: all checked directories match the post-migration bundle layout\n'
exit 0
