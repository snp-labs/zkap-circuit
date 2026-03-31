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
#   --help, -h            도움말 출력
#
# 예시:
#   ./build.sh                                    # 전체 빌드 (모든 환경)
#   ./build.sh -e macos-arm64                     # macOS ARM64만 빌드
#   ./build.sh -e macos-arm64 -e linux-x64        # 여러 환경 빌드
#   ./build.sh --napi-only -e windows             # Windows NAPI만 빌드
#   ./build.sh --keys-only                        # 키 생성만 수행
# =============================================================================

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
    sed -n '8,26p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

# 인자 파싱
while [[ $# -gt 0 ]]; do
    case $1 in
        --env|-e)
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
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-package)
            DO_PACKAGE=false
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

# 환경 변수 설정
setup_env_vars() {
    log_step "환경 변수 설정"

    # ZK Circuit Constraints
    export ZK_MAX_JWT_B64_LEN=1024
    export ZK_MAX_PAYLOAD_B64_LEN=896
    export ZK_MAX_AUD_LEN=155
    export ZK_MAX_EXP_LEN=20
    export ZK_MAX_ISS_LEN=93
    export ZK_MAX_NONCE_LEN=93
    export ZK_MAX_SUB_LEN=93
    export ZK_N=6
    export ZK_K=3
    export ZK_TREE_HEIGHT=16
    export ZK_NUM_AUDIENCE_LIMIT=5

    # macOS에서 Windows 빌드를 위해 llvm 경로 추가
    if [ -d "/opt/homebrew/opt/llvm@20/bin" ]; then
        export PATH="/opt/homebrew/opt/llvm@20/bin:$PATH"
        log_info "LLVM 경로 추가됨: /opt/homebrew/opt/llvm@20/bin"
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

    mkdir -p "$OUTPUT_DIR/keys"

    for env in "${ENVIRONMENTS[@]}"; do
        mkdir -p "$OUTPUT_DIR/napi/$env"
        log_info "생성됨: $OUTPUT_DIR/napi/$env"
    done

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
    local extra_flags=""
    local env_vars=""

    case $env in
        macos-arm64)
            # 네이티브 빌드 (타겟 지정 불필요)
            target=""
            ;;
        macos-x64)
            target="x86_64-apple-darwin"
            ;;
        linux-x64)
            target="x86_64-unknown-linux-gnu"
            extra_flags="--cross-compile"
            ;;
        linux-arm64)
            target="aarch64-unknown-linux-gnu"
            extra_flags="--cross-compile"
            ;;
        linux-musl)
            target="x86_64-unknown-linux-musl"
            extra_flags="--cross-compile"
            env_vars="CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS=\"-C target-feature=-crt-static\""
            ;;
        windows)
            target="x86_64-pc-windows-msvc"
            extra_flags="--cross-compile"
            ;;
    esac

    log_info "빌드 중: $env"

    local output_dir="$OUTPUT_DIR/napi/$env"

    # 빌드 명령어 구성
    local cmd="npx napi build --platform --release --output-dir \"$output_dir\" --features constraints-logging"

    if [ -n "$target" ]; then
        cmd="$cmd --target $target"
    fi

    if [ -n "$extra_flags" ]; then
        cmd="$cmd $extra_flags"
    fi

    if [ -n "$env_vars" ]; then
        cmd="$env_vars $cmd"
    fi

    # 빌드 실행
    eval $cmd

    log_success "완료: $env -> $output_dir"
}

# NAPI 빌드
build_napi() {
    if [ "$KEYS_ONLY" = true ]; then
        log_warn "NAPI 빌드 건너뛰기 (--keys-only)"
        return
    fi

    log_step "NAPI 바인딩 빌드"

    # bindings/napi 디렉토리로 이동
    cd bindings/napi

    # node_modules 확인
    if [ ! -d "node_modules" ]; then
        log_info "npm 의존성 설치 중..."
        npm install
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
    cd ../..

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

    tar -czvf "$TAR_NAME" -C "$OUTPUT_DIR" .

    log_success "패키지 생성 완료: $TAR_NAME"
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
    setup_env_vars
    do_clean
    create_output_dirs
    generate_keys
    build_napi
    package_output
    print_summary
}

main
