#!/usr/bin/env bash
#
# scripts/ci/check-crs-size-cap.sh
#
# Assert that a CRS bundle directory fits under a size cap (KiB).
# Used by ci.yml `generate-setup-smoke` and release.yml
# `generate-release-bundle` so the `du | awk` pipeline lives in one place.
#
# Usage:
#   bash scripts/ci/check-crs-size-cap.sh <path> [limit_kib]
# Default limit: 2 GiB (2097152 KiB).
#
# Exit status:
#   0  bundle under cap
#   1  bundle exceeds cap
#   2  setup/usage error

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <path> [limit_kib]" >&2
  exit 2
fi

TARGET="$1"
LIMIT_KIB="${2:-2097152}"

if [ ! -d "$TARGET" ]; then
  echo "ERROR: '$TARGET' is not a directory" >&2
  exit 2
fi

USED_KIB="$(du -sk "$TARGET" | awk '{print $1}')"

printf '%s total: %s KiB / limit %s KiB\n' "$TARGET" "$USED_KIB" "$LIMIT_KIB"

if [ "$USED_KIB" -gt "$LIMIT_KIB" ]; then
  printf 'ERROR: %s exceeds size cap (%s KiB > %s KiB)\n' \
    "$TARGET" "$USED_KIB" "$LIMIT_KIB" >&2
  exit 1
fi
