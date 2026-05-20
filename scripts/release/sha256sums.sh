#!/usr/bin/env bash
#
# scripts/release/sha256sums.sh
#
# Emit a sorted SHA256SUMS file (sha256sum-compatible format) over either:
#   (a) every regular file directly under a directory, or
#   (b) an explicit list of file paths.
#
# Sorting + relative-path normalization makes the output byte-reproducible
# across runners and across re-runs of the release workflow.
#
# Usage:
#   bash scripts/release/sha256sums.sh <dir> [output_file]
#   bash scripts/release/sha256sums.sh --files <output_file> <path> [path ...]
#
# In directory mode, output defaults to "<dir>/SHA256SUMS" and the output
# file itself is excluded from the hashed set. Recursion is intentionally
# disabled — pass --files to control the set explicitly.
#
# Exit status:
#   0  SHA256SUMS written
#   1  no files matched (or sha256 tool unavailable)
#   2  usage error

set -euo pipefail

# Detect the platform's sha256 driver.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA256="shasum -a 256"
else
  echo "ERROR: neither sha256sum nor shasum is on PATH" >&2
  exit 1
fi

usage() {
  cat >&2 <<'EOF'
usage:
  bash scripts/release/sha256sums.sh <dir> [output_file]
  bash scripts/release/sha256sums.sh --files <output_file> <path> [path ...]
EOF
  exit 2
}

if [ "$#" -lt 1 ]; then
  usage
fi

if [ "$1" = "--files" ]; then
  # Explicit file-list mode.
  if [ "$#" -lt 3 ]; then
    usage
  fi
  OUT="$2"
  shift 2
  # Sort input paths by basename so the SHA256SUMS rows are reproducible
  # and human-readable in filename-order (matches directory-mode behaviour).
  SORTED_INPUTS=()
  while IFS= read -r f; do
    SORTED_INPUTS+=("$f")
  done < <(
    for p in "$@"; do
      printf '%s\t%s\n' "$(basename "$p")" "$p"
    done | LC_ALL=C sort -k1,1 | cut -f2-
  )
  : > "$OUT"
  for f in "${SORTED_INPUTS[@]}"; do
    if [ ! -f "$f" ]; then
      echo "ERROR: not a file: $f" >&2
      exit 1
    fi
    # Hash from the file's parent dir so the SHA256SUMS records a basename
    # rather than an absolute or staging-relative path.
    ( cd "$(dirname "$f")" && $SHA256 "$(basename "$f")" ) >> "$OUT"
  done
  echo "Wrote $(wc -l < "$OUT" | tr -d ' ') entries to $OUT"
  exit 0
fi

# Directory mode.
DIR="$1"
OUT="${2:-$DIR/SHA256SUMS}"

if [ ! -d "$DIR" ]; then
  echo "ERROR: '$DIR' is not a directory" >&2
  exit 1
fi

OUT_BASENAME="$(basename "$OUT")"

# Collect every regular file directly under DIR (no recursion), sorted,
# excluding the output file itself if it happens to live in DIR.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

(
  cd "$DIR"
  find . -maxdepth 1 -type f ! -name "$OUT_BASENAME" -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 -I{} -n1 $SHA256 {}
) > "$TMP"

if [ ! -s "$TMP" ]; then
  echo "ERROR: no files matched under $DIR" >&2
  exit 1
fi

# Normalize the leading "./" produced by `find .` so the SHA256SUMS contains
# bare basenames, which is what `sha256sum -c SHA256SUMS` expects when the
# caller `cd`s into the directory first.
sed -E 's|  \./|  |' "$TMP" > "$OUT"

echo "Wrote $(wc -l < "$OUT" | tr -d ' ') entries to $OUT"
