#!/usr/bin/env bash
# DEPRECATED 2026-05-10: replaced by `cargo run -p zkap-cli --bin generate_setup`.
# Kept for backward compatibility; new workflows should use the Rust binary.
#
# Build, optimize, size-gate, and verify the zkap-witness-wasm artifact.
#
# Usage:
#   AR1CS_WITNESS_ARZKEY_PATH=/path/to/circuit.arzkey ./build-wasm.sh [--out DIR]
#
# What it does, in order:
#   1. Confirms AR1CS_WITNESS_ARZKEY_PATH is set and the .arzkey is readable.
#   2. Confirms the wasm32-unknown-unknown rustup target is installed.
#   3. cargo build -p zkap-witness-wasm --target wasm32-unknown-unknown --release.
#   4. wasm-opt -Oz (when binaryen is installed) writes <out>/zkap_witness_wasm.opt.wasm.
#      When wasm-opt is missing, the cargo output is used as-is and a warning is printed.
#   5. Hard fails if the FINAL wasm exceeds 8 MiB.
#   6. Verifies the wasm exports wasm_alloc, wasm_free, embedded_ar1cs_blake3,
#      witness_generator (uses `wasm-tools print` when available; falls back to
#      grep on the export-name strings embedded in the binary).
#
# The script does NOT push, PR, sign, or upload anything. It exits non-zero on
# any failure so CI can wire it as a single gate.

set -euo pipefail

CRATE_NAME="zkap-witness-wasm"
WASM_BIN_BASENAME="zkap_witness_wasm"
TARGET="wasm32-unknown-unknown"
PROFILE="release"
SIZE_LIMIT_MIB=8
SIZE_LIMIT_BYTES=$(( SIZE_LIMIT_MIB * 1024 * 1024 ))
REQUIRED_EXPORTS=(wasm_alloc wasm_free embedded_ar1cs_blake3 witness_generator)

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

OUT_DIR_DEFAULT="${WORKSPACE_ROOT}/target/${TARGET}/${PROFILE}"
OUT_DIR="${OUT_DIR_DEFAULT}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '1,/^set -euo pipefail$/p' "$0" | sed -n '1,/^$/p'
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 64
            ;;
    esac
done

# ── Guards ──────────────────────────────────────────────────────────────────

if [[ -z "${AR1CS_WITNESS_ARZKEY_PATH:-}" ]]; then
    echo "ERROR: AR1CS_WITNESS_ARZKEY_PATH is not set." >&2
    echo "       Set it to the .arzkey this wasm artifact will be paired with;" >&2
    echo "       build.rs embeds its ar1cs_blake3 for runtime cross-check." >&2
    exit 1
fi
if [[ ! -r "${AR1CS_WITNESS_ARZKEY_PATH}" ]]; then
    echo "ERROR: AR1CS_WITNESS_ARZKEY_PATH=${AR1CS_WITNESS_ARZKEY_PATH} not readable." >&2
    exit 1
fi
ARZKEY_SIZE=$(wc -c <"${AR1CS_WITNESS_ARZKEY_PATH}" | tr -d ' ')
if (( ARZKEY_SIZE < 48 )); then
    echo "ERROR: ${AR1CS_WITNESS_ARZKEY_PATH} too short for ARZKEY header (${ARZKEY_SIZE} bytes)." >&2
    exit 1
fi
ARZKEY_MAGIC=$(head -c 6 "${AR1CS_WITNESS_ARZKEY_PATH}")
if [[ "${ARZKEY_MAGIC}" != "ARZKEY" ]]; then
    echo "ERROR: ${AR1CS_WITNESS_ARZKEY_PATH} does not start with ARZKEY magic." >&2
    exit 1
fi

if ! rustup target list --installed 2>/dev/null | grep -qx "${TARGET}"; then
    echo "ERROR: rustup target ${TARGET} not installed." >&2
    echo "       Run: rustup target add ${TARGET}" >&2
    exit 1
fi

# ── Build ───────────────────────────────────────────────────────────────────

echo "==> cargo build -p ${CRATE_NAME} --target ${TARGET} --release"
(
    cd "${WORKSPACE_ROOT}"
    cargo build -p "${CRATE_NAME}" --target "${TARGET}" --release
)

RAW_WASM="${OUT_DIR_DEFAULT}/${WASM_BIN_BASENAME}.wasm"
if [[ ! -f "${RAW_WASM}" ]]; then
    echo "ERROR: cargo did not produce ${RAW_WASM}" >&2
    exit 1
fi

mkdir -p "${OUT_DIR}"
OPT_WASM="${OUT_DIR}/${WASM_BIN_BASENAME}.opt.wasm"
FINAL_WASM=""
USED_WASM_OPT="false"

if command -v wasm-opt >/dev/null 2>&1; then
    echo "==> wasm-opt -Oz $(wasm-opt --version | head -n1)"
    # Feature flags mirror what modern rustc emits for wasm32-unknown-unknown
    # (bulk-memory, mutable-globals, nontrapping-float-to-int, sign-ext are
    # all on by default since Rust 1.78). Without these wasm-opt's validator
    # rejects sequences like `i32.trunc_sat_f64_u` produced by libstd.
    wasm-opt -Oz \
        --enable-bulk-memory \
        --enable-mutable-globals \
        --enable-nontrapping-float-to-int \
        --enable-sign-ext \
        --enable-reference-types \
        --enable-multivalue \
        "${RAW_WASM}" -o "${OPT_WASM}"
    FINAL_WASM="${OPT_WASM}"
    USED_WASM_OPT="true"
else
    echo "WARN: wasm-opt not found on PATH; skipping size optimization." >&2
    echo "      Install binaryen (e.g. \`brew install binaryen\`) for production builds." >&2
    if [[ "${OUT_DIR}" != "${OUT_DIR_DEFAULT}" ]]; then
        cp "${RAW_WASM}" "${OPT_WASM}"
        FINAL_WASM="${OPT_WASM}"
    else
        FINAL_WASM="${RAW_WASM}"
    fi
fi

# ── Size gate ───────────────────────────────────────────────────────────────

FINAL_SIZE_BYTES=$(wc -c <"${FINAL_WASM}" | tr -d ' ')
# Bash-only MiB rendering with three decimal places; avoids depending on `bc`.
SIZE_INT_PART=$(( FINAL_SIZE_BYTES / 1048576 ))
SIZE_FRAC_NUM=$(( ((FINAL_SIZE_BYTES % 1048576) * 1000) / 1048576 ))
FINAL_SIZE_MIB=$(printf '%d.%03d' "${SIZE_INT_PART}" "${SIZE_FRAC_NUM}")

if (( FINAL_SIZE_BYTES > SIZE_LIMIT_BYTES )); then
    echo "ERROR: ${FINAL_WASM} is ${FINAL_SIZE_BYTES} bytes (${FINAL_SIZE_MIB} MiB)," >&2
    echo "       exceeds size gate ${SIZE_LIMIT_MIB} MiB." >&2
    exit 1
fi

# ── Export verification ─────────────────────────────────────────────────────

verify_exports_with_wasm_tools() {
    local wat
    if ! wat=$(wasm-tools print "${FINAL_WASM}" 2>/dev/null); then
        return 2
    fi
    local missing=()
    for sym in "${REQUIRED_EXPORTS[@]}"; do
        if ! grep -qE "\(export \"${sym}\" " <<<"${wat}"; then
            missing+=("${sym}")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        echo "ERROR: wasm exports missing (wasm-tools): ${missing[*]}" >&2
        return 1
    fi
    return 0
}

verify_exports_with_grep() {
    # Fallback when wasm-tools is unavailable: export names are stored as
    # plain UTF-8 strings in the export section, so a binary-safe grep finds
    # them. Possible false positives (the same string could appear elsewhere
    # in the binary), but for the four ABI names that's acceptable noise.
    local missing=()
    for sym in "${REQUIRED_EXPORTS[@]}"; do
        if ! LC_ALL=C grep -aFq "${sym}" "${FINAL_WASM}"; then
            missing+=("${sym}")
        fi
    done
    if (( ${#missing[@]} > 0 )); then
        echo "ERROR: wasm exports missing (grep): ${missing[*]}" >&2
        return 1
    fi
    return 0
}

EXPORT_CHECK_TOOL=""
if command -v wasm-tools >/dev/null 2>&1; then
    EXPORT_CHECK_TOOL="wasm-tools"
    verify_exports_with_wasm_tools
else
    EXPORT_CHECK_TOOL="grep"
    verify_exports_with_grep
fi

# ── Pair / fingerprint identity ─────────────────────────────────────────────
#
# The pair contract is `embedded_ar1cs_blake3 == arzkey.header.ar1cs_blake3`.
# build.rs reads bytes 16..48 of the `.arzkey` header and bakes them into
# the wasm artifact as `EMBEDDED_AR1CS_BLAKE3`. The wasm binary itself
# never re-exposes that constant as a string (LLVM strips the dead path
# under `-Oz`), so the cleanest operator check is to print the source
# bytes here — anyone deploying this wasm can grep for the same hex in
# their `.arzkey` to confirm they are running a paired bundle.

ARZKEY_BLAKE3_HEX=$(
    dd if="${AR1CS_WITNESS_ARZKEY_PATH}" bs=1 skip=16 count=32 status=none \
        | od -An -v -tx1 \
        | tr -d ' \n'
)
if [[ ${#ARZKEY_BLAKE3_HEX} -ne 64 ]]; then
    echo "ERROR: failed to extract 32-byte ar1cs_blake3 from arzkey header" >&2
    exit 1
fi

# Wasm artifact fingerprint — lets operators verify the deployed `.wasm`
# byte-for-byte matches what `build-wasm.sh` produced + size-gated +
# export-checked here.
if command -v shasum >/dev/null 2>&1; then
    WASM_SHA256=$(shasum -a 256 "${FINAL_WASM}" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    WASM_SHA256=$(sha256sum "${FINAL_WASM}" | awk '{print $1}')
else
    WASM_SHA256="(neither shasum nor sha256sum available)"
fi

# ── Report ──────────────────────────────────────────────────────────────────

echo
echo "✓ zkap-witness-wasm build OK"
printf '  wasm path     : %s\n' "${FINAL_WASM}"
printf '  wasm size     : %s bytes (%s MiB) / limit %d MiB\n' \
    "${FINAL_SIZE_BYTES}" "${FINAL_SIZE_MIB}" "${SIZE_LIMIT_MIB}"
printf '  wasm sha256   : %s\n' "${WASM_SHA256}"
printf '  wasm-opt -Oz  : %s\n' "${USED_WASM_OPT}"
printf '  exports       : %s (verified via %s)\n' \
    "${REQUIRED_EXPORTS[*]}" "${EXPORT_CHECK_TOOL}"
printf '  arzkey paired : %s (%s bytes)\n' \
    "${AR1CS_WITNESS_ARZKEY_PATH}" "${ARZKEY_SIZE}"
printf '  ar1cs_blake3  : %s (offset 16..48 of arzkey header — embedded into wasm via build.rs)\n' \
    "${ARZKEY_BLAKE3_HEX}"
