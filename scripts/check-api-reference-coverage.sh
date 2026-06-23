#!/usr/bin/env bash
#
# scripts/check-api-reference-coverage.sh
#
# Documentation drift gate for the zkap-service public API surface.
#
# Every identifier re-exported at the crate root of `zkap-service`
# (`crates/service/src/lib.rs`) is the stable, semver-tracked public surface
# (CLAUDE.md: "external callers use only top-level re-exports"). This gate
# asserts that each such identifier is mentioned somewhere in
# `docs/API_REFERENCE.md`, so a newly re-exported item cannot ship
# undocumented. It is the doc analogue of the `const _` signature pins at the
# bottom of `lib.rs`.
#
# Scope: identifiers inside `pub use ...` statements (brace and non-brace
# forms). `pub mod` modules reached via a path (e.g. `zkap_service::manifest`)
# are documented but not enumerated here — their types are more stable than
# the re-export surface that has historically drifted.
#
# Usage:
#   bash scripts/check-api-reference-coverage.sh
#
# Exit status:
#   0 = every re-exported identifier appears in API_REFERENCE.md
#   1 = at least one identifier is undocumented
#   2 = environment/setup error (missing file)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/crates/service/src/lib.rs"
DOC="$ROOT/docs/API_REFERENCE.md"

[ -f "$LIB" ] || { echo "ERROR: not found: $LIB" >&2; exit 2; }
[ -f "$DOC" ] || { echo "ERROR: not found: $DOC" >&2; exit 2; }

# Intentionally-internal re-exports that are NOT part of the documented
# public surface (gated behind non-default internal features).
ALLOWLIST=" synthesize_witnesses_streaming "

# Extract identifiers from every `pub use ...;` statement (handles
# multi-line brace blocks). Brace form -> the names inside { }. Non-brace
# form -> the final `::` path segment.
identifiers="$(
  awk '
    /^[[:space:]]*pub use/ {
      buf = $0
      while (buf !~ /;/) { if ((getline line) <= 0) break; buf = buf " " line }
      if (buf ~ /{/) {
        inner = buf; sub(/^[^{]*{/, "", inner); sub(/}.*/, "", inner)
        n = split(inner, a, ",")
        for (i = 1; i <= n; i++) { gsub(/[[:space:]]/, "", a[i]); if (a[i] != "") print a[i] }
      } else {
        s = buf; sub(/;.*/, "", s)
        n = split(s, p, "::"); last = p[n]; gsub(/[[:space:]]/, "", last)
        if (last != "") print last
      }
    }
  ' "$LIB" | sort -u
)"

missing=""
checked=0
for id in $identifiers; do
  case "$ALLOWLIST" in *" $id "*) continue ;; esac
  checked=$((checked + 1))
  if ! grep -Fq -- "$id" "$DOC"; then
    missing="$missing $id"
  fi
done

if [ -n "$missing" ]; then
  echo "FAIL: public re-exports missing from docs/API_REFERENCE.md:" >&2
  for id in $missing; do echo "  - $id" >&2; done
  echo "" >&2
  echo "Document each item above in docs/API_REFERENCE.md, or (if it is" >&2
  echo "intentionally internal) add it to ALLOWLIST in this script." >&2
  exit 1
fi

echo "OK: all $checked public re-exports are documented in docs/API_REFERENCE.md"
