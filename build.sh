#!/bin/bash
set -e  # Exit immediately on error

# =============================================================================
# ZKUP Build Script
# =============================================================================
# Usage: ./build.sh [OPTIONS]
#
# Options:
#   --env, -e <env>       Select build environment (multiple allowed, default: all)
#                         Available: macos-arm64, macos-x64, linux-x64,
#                                    linux-arm64, linux-musl, windows, all
#   --napi-only           Build NAPI bindings only (skip key generation)
#   --keys-only           Perform key generation only (skip NAPI build)
#   --no-clean            Skip clean build
#   --output, -o <path>   Output directory (default: ./output)
#   --no-package          Skip packaging (tar.gz)
#   --dry-run             Check configuration only without running a real build
#   --yes, -y             Auto-approve interactive prompts (for CI)
#   -n <value>            Set ZK_N value (default: 3)
#   -k <value>            Set ZK_K value (default: 3)
#   --help, -h            Print help
#
# Examples:
#   ./build.sh                                    # Full build (all environments)
#   ./build.sh -e macos-arm64                     # Build macOS ARM64 only
#   ./build.sh -e macos-arm64 -e linux-x64        # Build multiple environments
#   ./build.sh --napi-only -e windows             # Build Windows NAPI only
#   ./build.sh --keys-only                        # Key generation only
#   ./build.sh --dry-run -e linux-x64             # Check configuration only
#   ./build.sh --yes -e linux-x64                 # CI environment (auto-approve)
# =============================================================================

# Save script root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENTS=()
NAPI_ONLY=false
KEYS_ONLY=false
DO_CLEAN=true
OUTPUT_DIR="./output"
DO_PACKAGE=true
DRY_RUN=false
AUTO_YES=false
ZK_N_VALUE=3
ZK_K_VALUE=3

# Detect host OS and architecture
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

# List of available environments
AVAILABLE_ENVS=("macos-arm64" "macos-x64" "linux-x64" "linux-arm64" "linux-musl" "windows")

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${GREEN}=== $1 ===${NC}"
}

# Print help
show_help() {
    sed -n '8,29p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# cleanup function (for trap)
cleanup() {
    local exit_code=$?
    # Return if pushd stack remains
    if [ "$(dirs -p | wc -l)" -gt 1 ]; then
        popd > /dev/null 2>&1 || true
    fi
    exit $exit_code
}
trap cleanup EXIT

# Load .env file
load_env_file() {
    local env_file="$SCRIPT_DIR/.env"
    if [ -f "$env_file" ]; then
        log_info "Loading .env file: $env_file"
        set -a
        # shellcheck source=/dev/null
        source "$env_file"
        set +a
    fi
}

# Determine whether cross-compilation is needed (based on host OS/architecture)
needs_cross_compile_for_env() {
    local env=$1
    case "$HOST_OS-$HOST_ARCH" in
        Darwin-arm64)
            # Apple Silicon Mac
            [[ "$env" != "macos-arm64" ]] && return 0
            ;;
        Darwin-x86_64)
            # Intel Mac
            [[ "$env" != "macos-x64" ]] && return 0
            ;;
        Linux-x86_64)
            # Linux x64
            [[ "$env" != "linux-x64" ]] && return 0
            ;;
        Linux-aarch64)
            # Linux ARM64
            [[ "$env" != "linux-arm64" ]] && return 0
            ;;
    esac
    return 1
}

# Check required tools
check_prerequisites() {
    local missing_tools=()
    local needs_cross_compile=false

    # Check basic tools
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo (Rust)")
    fi

    # npm is only required for NAPI builds
    if [ "$KEYS_ONLY" != true ]; then
        if ! command -v npm &> /dev/null; then
            missing_tools+=("npm (Node.js)")
        fi
    fi

    # Check whether cross-compilation is needed (based on host)
    for env in "${ENVIRONMENTS[@]}"; do
        if needs_cross_compile_for_env "$env"; then
            needs_cross_compile=true
            break
        fi
    done

    # zig is required for cross-compilation
    if [ "$needs_cross_compile" = true ] && [ "$KEYS_ONLY" != true ]; then
        if ! command -v zig &> /dev/null; then
            missing_tools+=("zig (for cross-compilation)")
        fi
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Required tools are not installed:"
        for tool in "${missing_tools[@]}"; do
            echo "  - $tool"
        done
        exit 1
    fi

    # Check Rust targets (only for NAPI build + cross-compilation)
    local missing_targets=()
    if [ "$KEYS_ONLY" != true ]; then
        # Invoke rustup only once (performance optimization)
        local installed_targets
        installed_targets=$(rustup target list --installed 2>/dev/null || echo "")

        for env in "${ENVIRONMENTS[@]}"; do
            # Native builds do not need a target installed
            if ! needs_cross_compile_for_env "$env"; then
                continue
            fi

            local target=""
            case $env in
                macos-arm64) target="aarch64-apple-darwin" ;;
                macos-x64) target="x86_64-apple-darwin" ;;
                linux-x64) target="x86_64-unknown-linux-gnu" ;;
                linux-arm64) target="aarch64-unknown-linux-gnu" ;;
                linux-musl) target="x86_64-unknown-linux-musl" ;;
                windows) target="x86_64-pc-windows-msvc" ;;
            esac

            if [ -n "$target" ]; then
                if ! echo "$installed_targets" | grep -q "^${target}$"; then
                    # Prevent duplicate targets
                    if [[ ! " ${missing_targets[*]} " =~ " ${target} " ]]; then
                        missing_targets+=("$target")
                    fi
                fi
            fi
        done
    fi

    if [ ${#missing_targets[@]} -gt 0 ]; then
        log_warn "The following Rust targets are not installed:"
        for target in "${missing_targets[@]}"; do
            echo "  rustup target add $target"
        done
        echo ""

        local do_install=false
        if [ "$AUTO_YES" = true ]; then
            log_info "Auto-approve mode (--yes)"
            do_install=true
        elif [ -t 0 ]; then
            # Interactive mode
            read -p "Install automatically? [y/N] " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ ]] && do_install=true
        else
            # Non-interactive mode (CI)
            log_error "Non-interactive environment. Use the --yes option or install targets manually."
            exit 1
        fi

        if [ "$do_install" = true ]; then
            for target in "${missing_targets[@]}"; do
                log_info "Installing: $target"
                rustup target add "$target"
            done
        else
            exit 1
        fi
    fi

    log_success "Required tools verified"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --env|-e)
            if [[ -z "$2" || "$2" == -* ]]; then
                log_error "--env option requires a value"
                exit 1
            fi
            ENVIRONMENTS+=("$2")
            shift 2
            ;;
        --napi-only)
            NAPI_ONLY=true
            shift
            ;;
        --keys-only)
            KEYS_ONLY=true
            shift
            ;;
        --no-clean)
            DO_CLEAN=false
            shift
            ;;
        --output|-o)
            if [[ -z "$2" || "$2" == -* ]]; then
                log_error "--output option requires a value"
                exit 1
            fi
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-package)
            DO_PACKAGE=false
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --yes|-y)
            AUTO_YES=true
            shift
            ;;
        -n)
            if [[ -z "$2" || "$2" == -* ]]; then
                log_error "-n option requires a value"
                exit 1
            fi
            ZK_N_VALUE="$2"
            shift 2
            ;;
        -k)
            if [[ -z "$2" || "$2" == -* ]]; then
                log_error "-k option requires a value"
                exit 1
            fi
            ZK_K_VALUE="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Help: $0 --help"
            exit 1
            ;;
    esac
done

# Validate mutually exclusive options
if [ "$NAPI_ONLY" = true ] && [ "$KEYS_ONLY" = true ]; then
    log_error "--napi-only and --keys-only cannot be used together"
    exit 1
fi

# Convert OUTPUT_DIR to absolute path
if [[ "$OUTPUT_DIR" != /* ]]; then
    # Remove leading ./ from relative path and convert to absolute path
    OUTPUT_DIR="$SCRIPT_DIR/${OUTPUT_DIR#./}"
fi

# If no environment specified, default to all
if [ ${#ENVIRONMENTS[@]} -eq 0 ]; then
    ENVIRONMENTS=("all")
fi

# If "all" is included, expand to all environments
if [[ " ${ENVIRONMENTS[*]} " =~ " all " ]]; then
    ENVIRONMENTS=("${AVAILABLE_ENVS[@]}")
fi

# Remove duplicate environments
unique_envs=()
for env in "${ENVIRONMENTS[@]}"; do
    if [[ ! " ${unique_envs[*]} " =~ " ${env} " ]]; then
        unique_envs+=("$env")
    fi
done
ENVIRONMENTS=("${unique_envs[@]}")

# Validate that each environment is valid
for env in "${ENVIRONMENTS[@]}"; do
    if [[ ! " ${AVAILABLE_ENVS[*]} " =~ " ${env} " ]]; then
        log_error "Invalid environment: $env"
        log_info "Available environments: ${AVAILABLE_ENVS[*]}"
        exit 1
    fi
done

# Print configuration
log_step "Build Configuration"
log_info "Target environments: ${ENVIRONMENTS[*]}"
log_info "Output directory: $OUTPUT_DIR"
log_info "NAPI only: $NAPI_ONLY"
log_info "Keys only: $KEYS_ONLY"
log_info "Clean build: $DO_CLEAN"
log_info "Package: $DO_PACKAGE"
log_info "Dry Run: $DRY_RUN"
log_info "ZK_N: $ZK_N_VALUE"
log_info "ZK_K: $ZK_K_VALUE"

# Exit here if in dry-run mode
if [ "$DRY_RUN" = true ]; then
    log_step "Check required tools (Dry Run)"
    check_prerequisites
    log_success "Dry run complete - no actual build was performed"
    exit 0
fi

# Set environment variables
setup_env_vars() {
    log_step "Set Environment Variables"

    # Load .env file first if it exists
    load_env_file

    # Use defaults if not set in .env
    export ZK_MAX_JWT_B64_LEN="${ZK_MAX_JWT_B64_LEN:-1024}"
    export ZK_MAX_PAYLOAD_B64_LEN="${ZK_MAX_PAYLOAD_B64_LEN:-896}"
    export ZK_MAX_AUD_LEN="${ZK_MAX_AUD_LEN:-155}"
    export ZK_MAX_EXP_LEN="${ZK_MAX_EXP_LEN:-20}"
    export ZK_MAX_ISS_LEN="${ZK_MAX_ISS_LEN:-93}"
    export ZK_MAX_NONCE_LEN="${ZK_MAX_NONCE_LEN:-93}"
    export ZK_MAX_SUB_LEN="${ZK_MAX_SUB_LEN:-93}"
    export ZK_N="${ZK_N:-$ZK_N_VALUE}"
    export ZK_K="${ZK_K:-$ZK_K_VALUE}"
    export ZK_TREE_HEIGHT="${ZK_TREE_HEIGHT:-16}"
    export ZK_NUM_AUDIENCE_LIMIT="${ZK_NUM_AUDIENCE_LIMIT:-5}"

    # Add LLVM path for cross-compilation on macOS
    local llvm_path=""
    if [ -d "/opt/homebrew/opt/llvm@20/bin" ]; then
        # Apple Silicon Mac
        llvm_path="/opt/homebrew/opt/llvm@20/bin"
    elif [ -d "/usr/local/opt/llvm@20/bin" ]; then
        # Intel Mac
        llvm_path="/usr/local/opt/llvm@20/bin"
    fi

    if [ -n "$llvm_path" ]; then
        export PATH="$llvm_path:$PATH"
        log_info "LLVM path added: $llvm_path"
    fi

    log_success "Environment variables configured"
}

# Clean build
do_clean() {
    if [ "$DO_CLEAN" = true ]; then
        log_step "Clean Build"

        log_info "Running Cargo Clean..."
        cargo clean

        log_info "Removing previous output..."
        rm -rf "$OUTPUT_DIR"

        log_success "Clean complete"
    else
        log_warn "Skipping clean build (--no-clean)"
    fi
}

# Create output directories
create_output_dirs() {
    log_step "Create Output Directories"

    # Create keys directory only if key generation is needed
    if [ "$NAPI_ONLY" != true ]; then
        mkdir -p "$OUTPUT_DIR/keys"
        log_info "Created: $OUTPUT_DIR/keys"
    fi

    # Create napi directory only if NAPI build is needed
    if [ "$KEYS_ONLY" != true ]; then
        for env in "${ENVIRONMENTS[@]}"; do
            mkdir -p "$OUTPUT_DIR/napi/$env"
            log_info "Created: $OUTPUT_DIR/napi/$env"
        done
    fi

    log_success "Directories created"
}

# Key generation
generate_keys() {
    if [ "$NAPI_ONLY" = true ]; then
        log_warn "Skipping key generation (--napi-only)"
        return
    fi

    log_step "CRS and Key Generation"
    log_warn "This process may take a long time..."

    cargo run --release \
        --features baerae,num-cs-logging \
        --bin generate_baerae_crs \
        -- "$OUTPUT_DIR/keys"

    log_success "Key generation complete: $OUTPUT_DIR/keys"
}

# NAPI build function (per environment)
build_napi_for_env() {
    local env=$1
    local target=""
    local cross_compile=false

    # Set target per environment
    case $env in
        macos-arm64) target="aarch64-apple-darwin" ;;
        macos-x64) target="x86_64-apple-darwin" ;;
        linux-x64) target="x86_64-unknown-linux-gnu" ;;
        linux-arm64) target="aarch64-unknown-linux-gnu" ;;
        linux-musl) target="x86_64-unknown-linux-musl" ;;
        windows) target="x86_64-pc-windows-msvc" ;;
    esac

    # Determine whether cross-compilation is needed based on host
    if needs_cross_compile_for_env "$env"; then
        cross_compile=true
    fi

    # Target specification can be omitted for native builds
    if [ "$cross_compile" = false ]; then
        target=""
    fi

    log_info "Building: $env"

    local output_dir="$OUTPUT_DIR/napi/$env"

    # Build command array
    local cmd_args=(npx napi build --platform --release --output-dir "$output_dir" --features constraints-logging)

    if [ -n "$target" ]; then
        cmd_args+=(--target "$target")
    fi

    if [ "$cross_compile" = true ]; then
        cmd_args+=(--cross-compile)
    fi

    # Special handling for linux-musl
    if [ "$env" = "linux-musl" ]; then
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=-crt-static" "${cmd_args[@]}"
    else
        "${cmd_args[@]}"
    fi

    log_success "Done: $env -> $output_dir"
}

# NAPI build
build_napi() {
    if [ "$KEYS_ONLY" = true ]; then
        log_warn "Skipping NAPI build (--keys-only)"
        return
    fi

    log_step "NAPI Bindings Build"

    # Change to bindings/napi directory (use pushd to ensure safe return)
    pushd "$SCRIPT_DIR/bindings/napi" > /dev/null

    # Check and install node_modules
    if [ ! -d "node_modules" ]; then
        log_info "Installing npm dependencies..."
        if ! npm install; then
            log_error "npm install failed"
            popd > /dev/null
            exit 1
        fi
    fi

    # Build per environment
    local total=${#ENVIRONMENTS[@]}
    local current=0

    for env in "${ENVIRONMENTS[@]}"; do
        current=$((current + 1))
        log_info "[$current/$total] Starting build for $env"
        build_napi_for_env "$env"
    done

    # Return to original directory
    popd > /dev/null

    log_success "NAPI build complete"
}

# Packaging
package_output() {
    if [ "$DO_PACKAGE" = false ]; then
        log_warn "Skipping packaging (--no-package)"
        return
    fi

    log_step "Package Output"

    # Remove empty directories
    find "$OUTPUT_DIR" -type d -empty -delete 2>/dev/null || true

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    # Include built environment list in filename
    if [ ${#ENVIRONMENTS[@]} -eq ${#AVAILABLE_ENVS[@]} ]; then
        ENV_SUFFIX="all"
    else
        ENV_SUFFIX=$(IFS=_; echo "${ENVIRONMENTS[*]}")
    fi

    TAR_NAME="zkup-release-${ENV_SUFFIX}-${TIMESTAMP}.tar.gz"
    TAR_PATH="$OUTPUT_DIR/$TAR_NAME"

    tar -czvf "$TAR_PATH" -C "$OUTPUT_DIR" --exclude="*.tar.gz" .

    log_success "Package created: $TAR_PATH"
}

# Build summary
print_summary() {
    log_step "Build Summary"

    echo ""
    log_info "Output directory structure:"
    if command -v tree &> /dev/null; then
        tree -L 3 "$OUTPUT_DIR" 2>/dev/null || ls -laR "$OUTPUT_DIR"
    else
        ls -laR "$OUTPUT_DIR"
    fi

    echo ""
    log_success "All builds completed successfully!"
}

# Main execution
main() {
    local start_time=$SECONDS

    check_prerequisites
    setup_env_vars
    do_clean
    create_output_dirs
    generate_keys
    build_napi
    package_output
    print_summary

    local elapsed=$((SECONDS - start_time))
    local mins=$((elapsed / 60))
    local secs=$((elapsed % 60))
    log_info "Total elapsed time: ${mins}m ${secs}s"
}

main
