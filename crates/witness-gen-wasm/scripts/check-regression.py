#!/usr/bin/env python3
"""Compare `cargo bench` output against PR-1a baseline; fail on regression.

PR-1b SLA gate. Reads `baseline.json` (sibling-to-this-script's parent)
plus criterion's per-benchmark `target/criterion/<bench>/new/estimates.json`
files (produced by the most recent `cargo bench` run). For each benchmark
in the baseline, compares measured mean against
`baseline_mean * (1 + slack_pct / 100)`. Exits non-zero on any regression.

Usage:
    # default slack (10% from baseline.json):
    python3 crates/witness-gen-wasm/scripts/check-regression.py

    # override slack (e.g. on noisy CI runners):
    SLACK_PCT=15 python3 crates/witness-gen-wasm/scripts/check-regression.py

    # override criterion dir (default: <repo-root>/target/criterion):
    CRITERION_DIR=/tmp/foo/target/criterion python3 .../check-regression.py

Exit codes:
    0  -- every benchmark within slack of baseline
    1  -- one or more benchmarks regressed beyond slack
    2  -- script error (baseline.json missing, criterion estimates absent,
                       JSON malformed)

Host-pin note: baseline.json's numbers are calibrated on a specific host
class (see `host` field). The .github/workflows/wasm-perf.yml CI workflow
pins to the matching runner class. Running this script on a different
host will produce false-positive regressions; for local dev, set
SLACK_PCT generously or skip the gate entirely.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    script_path = Path(__file__).resolve()
    # scripts/ -> witness-gen-wasm/ -> crates/ -> repo root
    crate_dir = script_path.parents[1]
    repo_root = script_path.parents[3]
    baseline_path = crate_dir / "baseline.json"
    criterion_dir = Path(os.environ.get("CRITERION_DIR", repo_root / "target" / "criterion"))

    if not baseline_path.exists():
        print(f"ERROR: baseline.json not found at {baseline_path}", file=sys.stderr)
        return 2
    try:
        baseline = json.loads(baseline_path.read_text())
    except json.JSONDecodeError as e:
        print(f"ERROR: baseline.json is malformed: {e}", file=sys.stderr)
        return 2

    slack_pct = float(os.environ.get("SLACK_PCT", baseline.get("slack_pct", 10)))
    benchmarks = baseline.get("benchmarks", {})
    if not benchmarks:
        print("ERROR: baseline.json has no `benchmarks` entries", file=sys.stderr)
        return 2

    print(f"baseline host:     {baseline.get('host', '<unset>')}")
    print(f"baselined_at:      {baseline.get('baselined_at', '<unset>')}")
    print(f"slack threshold:   {slack_pct}%")
    print(f"criterion dir:     {criterion_dir}")
    print()

    header = f"{'Benchmark':40} {'Baseline (ms)':>15} {'Measured (ms)':>15} {'Delta':>10}  Status"
    print(header)
    print("-" * len(header))

    fail = False
    rows: list[tuple[str, float, float, float, str]] = []

    for bench_name, bench_data in benchmarks.items():
        est_path = criterion_dir / bench_name / "new" / "estimates.json"
        if not est_path.exists():
            rows.append((bench_name, bench_data["mean_ms"], float("nan"), float("nan"), "NO DATA"))
            fail = True
            continue
        try:
            est = json.loads(est_path.read_text())
        except json.JSONDecodeError as e:
            print(f"ERROR: estimates.json malformed at {est_path}: {e}", file=sys.stderr)
            return 2

        # criterion estimates are in nanoseconds.
        try:
            measured_ns = float(est["mean"]["point_estimate"])
        except (KeyError, TypeError, ValueError) as e:
            print(f"ERROR: estimates.json missing mean.point_estimate at {est_path}: {e}", file=sys.stderr)
            return 2

        measured_ms = measured_ns / 1_000_000.0
        baseline_ms = float(bench_data["mean_ms"])
        threshold_ms = baseline_ms * (1.0 + slack_pct / 100.0)
        delta_pct = (measured_ms - baseline_ms) / baseline_ms * 100.0
        status = "PASS" if measured_ms <= threshold_ms else "FAIL"
        if status == "FAIL":
            fail = True
        rows.append((bench_name, baseline_ms, measured_ms, delta_pct, status))

    for name, b, m, d, s in rows:
        if s == "NO DATA":
            print(f"{name:40} {b:>15.2f} {'--':>15} {'--':>10}  {s}")
        else:
            print(f"{name:40} {b:>15.2f} {m:>15.2f} {d:>+9.1f}%  {s}")

    print()
    if fail:
        print(f"FAILED: one or more benchmarks regressed > {slack_pct}% from baseline "
              "(or estimates.json missing — was `cargo bench` run?)")
        return 1
    print(f"PASS: all benchmarks within {slack_pct}% of baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
