#!/usr/bin/env bash
# scripts/verify-citations.sh — re-verify all `crates/<path>:<line>` citations in audit docs.
set -euo pipefail
FAILED=""
for doc in docs/audit/*.md; do
  for ref in $(grep -oE '`crates/[^[:space:]`]+:[0-9]+`' "$doc" | sort -u); do
    clean="${ref//\`/}"
    file="${clean%:*}"
    line="${clean##*:}"
    total=$(wc -l < "$file" 2>/dev/null || echo 0)
    [ "$total" -ge "$line" ] || FAILED="$FAILED\n  $doc → $ref (file has $total lines)"
  done
done
[ -z "$FAILED" ] && echo "PASS" || { printf "FAIL — broken citations:%b\n" "$FAILED"; exit 1; }
