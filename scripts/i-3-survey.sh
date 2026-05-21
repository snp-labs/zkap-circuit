#!/usr/bin/env bash
# scripts/i-3-survey.sh — reproducible call-count probe for AC-8 / I-3.
set -euo pipefail
echo "I-3 survey: slice_from_start call-count and δ"
CALL_COUNT=$(grep -rn 'slice_from_start(' --include='*.rs' crates | wc -l | tr -d ' ')
echo "Total call-sites: $CALL_COUNT"
grep -rn 'slice_from_start(' --include='*.rs' crates
echo "Per-call output-element counts require manual inspection — see .omc/state/i-3-survey.md."
