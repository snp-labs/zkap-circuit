#!/usr/bin/env bash
# scripts/per-swap-ab-measurement.sh — Per-swap A/B measurement automation for delta-473 analysis.
# Per Architect iter 0 review: uses `|| true` so cargo's assert_eq! failure on A/B branches
# does NOT abort the script (we extract num_constraints from println! BEFORE the panic).
# Run from the repo root.
set -uo pipefail   # NOTE: no -e because individual cargo invocations are expected to fail-with-output on A/B branches

BASELINE_BRANCH="audit/2026-05-20-constraint-followup"
FULL_SWAP_BRANCH="audit/2026-05-20-followup-c1b-swap"
EXPECTED_BASELINE=911941
EXPECTED_FULL=911468

# Single measurement: extract num_constraints from total_circuit_count test output.
# Returns the count via stdout. Cargo's assert_eq! may panic on A/B branches; that's
# expected and the println! at total_circuit_count.rs:63 runs BEFORE the panic at line 69.
measure() {
    local branch="$1"
    git checkout -q "$branch" 2>/dev/null
    local count
    count=$(cargo test --release -p circuit --test total_circuit_count -- --nocapture 2>&1 || true)
    count=$(echo "$count" | grep -oE 'num_constraints[[:space:]]*=[[:space:]]*[0-9]+' | grep -oE '[0-9]+$' | head -1)
    echo "$count"
}

original_branch=$(git rev-parse --abbrev-ref HEAD)
trap 'git checkout -q "$original_branch" 2>/dev/null' EXIT INT TERM

# Patch 2: baseline + full-swap measured FIRST. Abort before touching A/B if either drifts.
echo "=== delta-473 per-swap A/B measurement ==="
echo ""
echo "[1/5] Measuring baseline ($BASELINE_BRANCH)..."
baseline=$(measure "$BASELINE_BRANCH")
echo "      baseline: num_constraints = $baseline"
if [ "$baseline" != "$EXPECTED_BASELINE" ]; then
    echo "FAIL: baseline mismatch ($baseline vs expected $EXPECTED_BASELINE)"
    echo "Did the baseline branch drift? Abort before A/B measurements."
    exit 1
fi

echo "[2/5] Measuring full swap ($FULL_SWAP_BRANCH)..."
full=$(measure "$FULL_SWAP_BRANCH")
echo "      full-swap: num_constraints = $full"
if [ "$full" != "$EXPECTED_FULL" ]; then
    echo "FAIL: full-swap mismatch ($full vs expected $EXPECTED_FULL)"
    echo "Did the swap branch drift? Abort before A/B measurements."
    exit 1
fi

echo "[3/5] Measuring only-C1.1 (audit/measurement/c1b-only-c1-1)..."
only_c1_1=$(measure "audit/measurement/c1b-only-c1-1")
echo "      only-C1.1: num_constraints = $only_c1_1"

echo "[4/5] Measuring only-C1.2 (audit/measurement/c1b-only-c1-2)..."
only_c1_2=$(measure "audit/measurement/c1b-only-c1-2")
echo "      only-C1.2: num_constraints = $only_c1_2"

echo "[5/5] Measuring only-C1.3 (audit/measurement/c1b-only-c1-3)..."
only_c1_3=$(measure "audit/measurement/c1b-only-c1-3")
echo "      only-C1.3: num_constraints = $only_c1_3"

delta_c1_1=$((baseline - only_c1_1))
delta_c1_2=$((baseline - only_c1_2))
delta_c1_3=$((baseline - only_c1_3))
delta_sum=$((delta_c1_1 + delta_c1_2 + delta_c1_3))
delta_full=$((baseline - full))
additivity_gap=$((delta_sum > delta_full ? delta_sum - delta_full : delta_full - delta_sum))

echo ""
echo "=== Per-swap deltas (positive = savings) ==="
printf "C1.1: -%d cs (predicted c1-findings.md detail + TL;DR: -300 cs)\n" "$delta_c1_1"
printf "C1.2: -%d cs (predicted c1-findings.md detail + TL;DR: -465 cs)\n" "$delta_c1_2"
printf "C1.3: -%d cs (predicted: TL;DR=-1,230 / ledger summary=-30 / ledger detail=-1,230)\n" "$delta_c1_3"
printf "Sum:  -%d cs\n" "$delta_sum"
printf "Full: -%d cs (measured all-three)\n" "$delta_full"
printf "Additivity gap: %d cs (|sum - full|; tolerance ±10)\n" "$additivity_gap"
if [ "$additivity_gap" -gt 10 ]; then
    echo "WARN (FM1): additivity gap > 10 cs — swaps are non-additive (constraint-ordering interactions)."
fi
