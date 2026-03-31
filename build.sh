#!/bin/bash
set -e  # 에러 발생 시 즉시 중단

# =============================================================================
# ZKUP Build Script
# =============================================================================
# 사용법: ./build.sh [OPTIONS]
#
# Options:
#   --env, -e <환경>      빌드 환경 선택 (여러 개 지정 가능, 기본: all)
#                         사용 가능: macos-arm64, macos-x64, linux-x64,
#                                   linux-arm64, linux-musl, windows, all
#   --napi-only           NAPI 바인딩만 빌드 (키 생성 건너뛰기)
#   --keys-only           키 생성만 수행 (NAPI 빌드 건너뛰기)
#   --no-clean            클린 빌드 건너뛰기
#   --output, -o <경로>   출력 디렉토리 (기본: ./output)
#   --no-package          패키징(tar.gz) 건너뛰기
#   --dry-run             실제 빌드 없이 설정만 확인
#   --yes, -y             대화형 프롬프트 자동 승인 (CI용)
#   --help, -h            도움말 출력
#
# 예시:
#   ./build.sh                                    # 전체 빌드 (모든 환경)
#   ./build.sh -e macos-arm64                     # macOS ARM64만 빌드
#   ./build.sh -e macos-arm64 -e linux-x64        # 여러 환경 빌드
#   ./build.sh --napi-only -e windows             # Windows NAPI만 빌드
#   ./build.sh --keys-only                        # 키 생성만 수행
#   ./build.sh --dry-run -e linux-x64             # 설정 확인만
# =============================================================================

# 스크립트 루트 디렉토리 저장
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 기본값 설정
ENVIRONMENTS=()
NAPI_ONLY=false
KEYS_ONLY=false
DO_CLEAN=true
OUTPUT_DIR="./output"
DO_PACKAGE=true
DRY_RUN=false
AUTO_YES=false

# 호스트 OS 및 아키텍처 감지
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"

# 사용 가능한 환경 목록
AVAILABLE_ENVS=("macos-arm64" "macos-x64" "linux-x64" "linux-arm64" "linux-musl" "windows")

# 로깅 함수
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

# 도움말 출력
show_help() {
    sed -n '8,28p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# cleanup 함수 (trap용)
cleanup() {
    local exit_code=$?
    # pushd 스택이 남아있으면 복귀
    if [ "$(dirs -p | wc -l)" -gt 1 ]; then
        popd > /dev/null 2>&1 || true
    fi
    exit $exit_code
}
trap cleanup EXIT

# .env 파일 로드
load_env_file() {
    local env_file="$SCRIPT_DIR/.env"
    if [ -f "$env_file" ]; then
        log_info ".env 파일 로드 중: $env_file"
        set -a
        # shellcheck source=/dev/null
        source "$env_file"
        set +a
    fi
}

# 크로스 컴파일 필요 여부 판단 (호스트 OS/아키텍처 기반)
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

# 필수 도구 검증
check_prerequisites() {
    local missing_tools=()
    local needs_cross_compile=false

    # 기본 도구 확인
    if ! command -v cargo &> /dev/null; then
        missing_tools+=("cargo (Rust)")
    fi

    # npm은 NAPI 빌드 시에만 필요
    if [ "$KEYS_ONLY" != true ]; then
        if ! command -v npm &> /dev/null; then
            missing_tools+=("npm (Node.js)")
        fi
    fi

    # 크로스 컴파일 필요 여부 확인 (호스트 기반)
    for env in "${ENVIRONMENTS[@]}"; do
        if needs_cross_compile_for_env "$env"; then
            needs_cross_compile=true
            break
        fi
    done

    # 크로스 컴파일 시 zig 필요
    if [ "$needs_cross_compile" = true ] && [ "$KEYS_ONLY" != true ]; then
        if ! command -v zig &> /dev/null; then
            missing_tools+=("zig (크로스 컴파일용)")
        fi
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "필수 도구가 설치되지 않았습니다:"
        for tool in "${missing_tools[@]}"; do
            echo "  - $tool"
        done
        exit 1
    fi

    # Rust 타겟 확인 (NAPI 빌드 시에만)
    local missing_targets=()
    if [ "$KEYS_ONLY" != true ]; then
        for env in "${ENVIRONMENTS[@]}"; do
            local target=""
            case $env in
                macos-x64) target="x86_64-apple-darwin" ;;
                linux-x64) target="x86_64-unknown-linux-gnu" ;;
                linux-arm64) target="aarch64-unknown-linux-gnu" ;;
                linux-musl) target="x86_64-unknown-linux-musl" ;;
                windows) target="x86_64-pc-windows-msvc" ;;
            esac

            if [ -n "$target" ]; then
                if ! rustup target list --installed | grep -q "^${target}$"; then
                    missing_targets+=("$target")
                fi
            fi
        done
    fi

    if [ ${#missing_targets[@]} -gt 0 ]; then
        log_warn "설치되지 않은 Rust 타겟이 있습니다:"
        for target in "${missing_targets[@]}"; do
            echo "  rustup target add $target"
        done
        echo ""

        local do_install=false
        if [ "$AUTO_YES" = true ]; then
            log_info "자동 승인 모드 (--yes)"
            do_install=true
        elif [ -t 0 ]; then
            # 대화형 모드
            read -p "자동으로 설치할까요? [y/N] " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ ]] && do_install=true
        else
            # 비대화형 모드 (CI)
            log_error "비대화형 환경입니다. --yes 옵션을 사용하거나 수동으로 타겟을 설치하세요."
            exit 1
        fi

        if [ "$do_install" = true ]; then
            for target in "${missing_targets[@]}"; do
                log_info "설치 중: $target"
                rustup target add "$target"
            done
        else
            exit 1
        fi
    fi

    log_success "필수 도구 검증 완료"
}

# 인자 파싱
while [[ $# -gt 0 ]]; do
    case $1 in
        --env|-e)
            if [[ -z "$2" || "$2" == -* ]]; then
                log_error "--env 옵션에 값이 필요합니다"
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
                log_error "--output 옵션에 값이 필요합니다"
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
        --help|-h)
            show_help
            ;;
        *)
            log_error "알 수 없는 옵션: $1"
            echo "도움말: $0 --help"
            exit 1
            ;;
    esac
done

# 상호 배타 옵션 검증
if [ "$NAPI_ONLY" = true ] && [ "$KEYS_ONLY" = true ]; then
    log_error "--napi-only와 --keys-only는 동시에 사용할 수 없습니다"
    exit 1
fi

# OUTPUT_DIR을 절대경로로 변환
if [[ "$OUTPUT_DIR" != /* ]]; then
    # 상대경로에서 ./ 제거 후 절대경로로 변환
    OUTPUT_DIR="$SCRIPT_DIR/${OUTPUT_DIR#./}"
fi

# 환경이 지정되지 않으면 all로 설정
if [ ${#ENVIRONMENTS[@]} -eq 0 ]; then
    ENVIRONMENTS=("all")
fi

# "all"이 포함되어 있으면 모든 환경으로 확장
if [[ " ${ENVIRONMENTS[*]} " =~ " all " ]]; then
    ENVIRONMENTS=("${AVAILABLE_ENVS[@]}")
fi

# 유효한 환경인지 검증
for env in "${ENVIRONMENTS[@]}"; do
    if [[ ! " ${AVAILABLE_ENVS[*]} " =~ " ${env} " ]]; then
        log_error "잘못된 환경: $env"
        log_info "사용 가능한 환경: ${AVAILABLE_ENVS[*]}"
        exit 1
    fi
done

# 설정 출력
log_step "빌드 설정"
log_info "타겟 환경: ${ENVIRONMENTS[*]}"
log_info "출력 디렉토리: $OUTPUT_DIR"
log_info "NAPI만 빌드: $NAPI_ONLY"
log_info "키만 생성: $KEYS_ONLY"
log_info "클린 빌드: $DO_CLEAN"
log_info "패키징: $DO_PACKAGE"
log_info "Dry Run: $DRY_RUN"

# Dry run 모드일 경우 여기서 종료
if [ "$DRY_RUN" = true ]; then
    log_step "필수 도구 검증 (Dry Run)"
    check_prerequisites
    log_success "Dry run 완료 - 실제 빌드는 수행되지 않았습니다"
    exit 0
fi

# 환경 변수 설정
setup_env_vars() {
    log_step "환경 변수 설정"

    # .env 파일이 있으면 먼저 로드
    load_env_file

    # .env에서 설정되지 않은 경우 기본값 사용
    export ZK_MAX_JWT_B64_LEN="${ZK_MAX_JWT_B64_LEN:-1024}"
    export ZK_MAX_PAYLOAD_B64_LEN="${ZK_MAX_PAYLOAD_B64_LEN:-896}"
    export ZK_MAX_AUD_LEN="${ZK_MAX_AUD_LEN:-155}"
    export ZK_MAX_EXP_LEN="${ZK_MAX_EXP_LEN:-20}"
    export ZK_MAX_ISS_LEN="${ZK_MAX_ISS_LEN:-93}"
    export ZK_MAX_NONCE_LEN="${ZK_MAX_NONCE_LEN:-93}"
    export ZK_MAX_SUB_LEN="${ZK_MAX_SUB_LEN:-93}"
    export ZK_N="${ZK_N:-6}"
    export ZK_K="${ZK_K:-3}"
    export ZK_TREE_HEIGHT="${ZK_TREE_HEIGHT:-16}"
    export ZK_NUM_AUDIENCE_LIMIT="${ZK_NUM_AUDIENCE_LIMIT:-5}"

    # macOS에서 크로스 컴파일을 위해 llvm 경로 추가
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
        log_info "LLVM 경로 추가됨: $llvm_path"
    fi

    log_success "환경 변수 설정 완료"
}

# 클린 빌드
do_clean() {
    if [ "$DO_CLEAN" = true ]; then
        log_step "클린 빌드 (Clean Build)"

        log_info "Cargo Clean 실행 중..."
        cargo clean

        log_info "이전 출력물 삭제 중..."
        rm -rf "$OUTPUT_DIR"

        log_success "클린 완료"
    else
        log_warn "클린 빌드 건너뛰기 (--no-clean)"
    fi
}

# 출력 디렉토리 생성
create_output_dirs() {
    log_step "출력 디렉토리 생성"

    # 키 생성이 필요한 경우에만 keys 디렉토리 생성
    if [ "$NAPI_ONLY" != true ]; then
        mkdir -p "$OUTPUT_DIR/keys"
        log_info "생성됨: $OUTPUT_DIR/keys"
    fi

    # NAPI 빌드가 필요한 경우에만 napi 디렉토리 생성
    if [ "$KEYS_ONLY" != true ]; then
        for env in "${ENVIRONMENTS[@]}"; do
            mkdir -p "$OUTPUT_DIR/napi/$env"
            log_info "생성됨: $OUTPUT_DIR/napi/$env"
        done
    fi

    log_success "디렉토리 생성 완료"
}

# 키 생성
generate_keys() {
    if [ "$NAPI_ONLY" = true ]; then
        log_warn "키 생성 건너뛰기 (--napi-only)"
        return
    fi

    log_step "CRS 및 Key 생성"
    log_warn "이 과정은 시간이 오래 걸릴 수 있습니다..."

    cargo run --release \
        --features baerae,num-cs-logging \
        --bin generate_baerae_crs \
        -- "$OUTPUT_DIR/keys"

    log_success "키 생성 완료: $OUTPUT_DIR/keys"
}

# NAPI 빌드 함수 (환경별)
build_napi_for_env() {
    local env=$1
    local target=""
    local cross_compile=false

    # 환경별 타겟 설정
    case $env in
        macos-arm64) target="aarch64-apple-darwin" ;;
        macos-x64) target="x86_64-apple-darwin" ;;
        linux-x64) target="x86_64-unknown-linux-gnu" ;;
        linux-arm64) target="aarch64-unknown-linux-gnu" ;;
        linux-musl) target="x86_64-unknown-linux-musl" ;;
        windows) target="x86_64-pc-windows-msvc" ;;
    esac

    # 호스트 기반 크로스 컴파일 여부 판단
    if needs_cross_compile_for_env "$env"; then
        cross_compile=true
    fi

    # 네이티브 빌드 시 타겟 지정 생략 가능
    if [ "$cross_compile" = false ]; then
        target=""
    fi

    log_info "빌드 중: $env"

    local output_dir="$OUTPUT_DIR/napi/$env"

    # 빌드 명령어 배열 구성
    local cmd_args=(npx napi build --platform --release --output-dir "$output_dir" --features constraints-logging)

    if [ -n "$target" ]; then
        cmd_args+=(--target "$target")
    fi

    if [ "$cross_compile" = true ]; then
        cmd_args+=(--cross-compile)
    fi

    # linux-musl 특수 처리
    if [ "$env" = "linux-musl" ]; then
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=-crt-static" "${cmd_args[@]}"
    else
        "${cmd_args[@]}"
    fi

    log_success "완료: $env -> $output_dir"
}

# NAPI 빌드
build_napi() {
    if [ "$KEYS_ONLY" = true ]; then
        log_warn "NAPI 빌드 건너뛰기 (--keys-only)"
        return
    fi

    log_step "NAPI 바인딩 빌드"

    # bindings/napi 디렉토리로 이동 (pushd 사용으로 안전한 복귀 보장)
    pushd "$SCRIPT_DIR/bindings/napi" > /dev/null

    # node_modules 확인 및 설치
    if [ ! -d "node_modules" ]; then
        log_info "npm 의존성 설치 중..."
        if ! npm install; then
            log_error "npm install 실패"
            popd > /dev/null
            exit 1
        fi
    fi

    # 각 환경별 빌드
    local total=${#ENVIRONMENTS[@]}
    local current=0

    for env in "${ENVIRONMENTS[@]}"; do
        current=$((current + 1))
        log_info "[$current/$total] $env 빌드 시작"
        build_napi_for_env "$env"
    done

    # 원래 디렉토리로 복귀
    popd > /dev/null

    log_success "NAPI 빌드 완료"
}

# 패키징
package_output() {
    if [ "$DO_PACKAGE" = false ]; then
        log_warn "패키징 건너뛰기 (--no-package)"
        return
    fi

    log_step "결과물 패키징"

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    # 빌드된 환경 목록을 파일명에 포함
    if [ ${#ENVIRONMENTS[@]} -eq ${#AVAILABLE_ENVS[@]} ]; then
        ENV_SUFFIX="all"
    else
        ENV_SUFFIX=$(IFS=_; echo "${ENVIRONMENTS[*]}")
    fi

    TAR_NAME="zkup-release-${ENV_SUFFIX}-${TIMESTAMP}.tar.gz"
    TAR_PATH="$OUTPUT_DIR/$TAR_NAME"

    tar -czvf "$TAR_PATH" -C "$OUTPUT_DIR" --exclude="*.tar.gz" .

    log_success "패키지 생성 완료: $TAR_PATH"
}

# 결과 요약
print_summary() {
    log_step "빌드 결과 요약"

    echo ""
    log_info "출력 디렉토리 구조:"
    if command -v tree &> /dev/null; then
        tree -L 3 "$OUTPUT_DIR" 2>/dev/null || ls -laR "$OUTPUT_DIR"
    else
        ls -laR "$OUTPUT_DIR"
    fi

    echo ""
    log_success "모든 빌드가 완료되었습니다!"
}

# 메인 실행
main() {
    check_prerequisites
    setup_env_vars
    do_clean
    create_output_dirs
    generate_keys
    build_napi
    package_output
    print_summary
}

main
