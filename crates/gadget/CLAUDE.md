# Gadget Crate 개발자 가이드

**규모**: ~18,329줄 Rust 코드
**에디션**: 2024
**목적**: zkup 프로토콜을 위한 ZK 회로 가젯 (제약 조건, 네이티브 구현, 유틸리티)

## 개요

`gadget` crate는 영지식 증명을 위한 암호화 기본 요소와 유틸리티를 구현합니다:
- **네이티브 구현**: 연산 속도가 빠른 일반 Rust 코드
- **제약 시스템 가젯**: 회로용으로 산술화된 구현
- **유틸리티 함수**: 비트 조작, 비교, 문자열 연산

모든 코드는 암호화 도메인별로 구성되며, 성능/제약 트레이드오프를 최적화한 병렬 버전(v0, v1, v2, v3)이 존재합니다.

---

## 디렉토리 구조

```
src/
├── lib.rs                  # 공개 모듈 내보내기
├── anchor/                 # 앵커 스킴 (Poseidon 기반 시크릿 공유)
├── base64/                 # Base64 URL-safe 디코더 (v2, v3)
├── bigint/                 # 큰 정수 연산 (네이티브 + 제약)
├── hashes/                 # 해시 함수 (SHA256, Blake2s256, MiMC7, Poseidon)
├── matrix/                 # Vandermonde 행렬 연산 (v0, 현재)
├── mekletree/              # Merkle 트리 가젯
├── signature/              # 디지털 서명 (RSA)
├── utils/                  # 저수준 유틸리티 (비트, 비교, 슬라이싱 등)
└── debug.rs                # 제약 로깅 매크로

reports/                    # 모듈별 감사 보고서
├── anchor_poseidon_full_audit.md
├── base64_decoder_full_audit.md
├── bigint_full_audit.md
├── hashes_full_audit.md
├── merkletree_full_audit.md
├── signature_full_audit.md
└── utils_full_audit.md
```

---

## 모듈 참조

### 핵심 모듈

#### 1. anchor/ — 앵커 스킴 (시크릿 커밋먼트)
- **목적**: Poseidon 기반 시크릿 커밋먼트 및 선택적 공개
- **주요 내보내기**:
  - `AnchorScheme` 트레이트 — setup, 앵커 생성, witness 생성, 검증
  - `AnchorUtils` 트레이트 — 내적 연산
  - `poseidon::PoseidonAnchor` — 커밋먼트 값 (m = n - k + 1 원소)
  - `poseidon::PoseidonAnchorPublicKey` — 파라미터 구조체
  - `poseidon::PoseidonAnchorSecret` — 시크릿 벡터 (n 원소)
  - `poseidon::PoseidonAnchorWitness` — witness 구성 요소 (a, b, h_known)
  - `constraints::` — 회로 가젯
  - `error::AnchorError` — 에러 열거형
- **상태**: V3 (최신). V1(DL 기반)은 제거됨
- **핵심 개념**:
  - Vandermonde 행렬을 사용하여 selector로부터 witness `a`를 계산
  - `b = a * Matrix` (검증에 사용)
  - `h_known`은 공개된 시크릿(selector == 1)의 해시를 저장
  - 제약 수는 시크릿 벡터 크기와 행렬 차원에 비례

#### 2. base64/ — URL-Safe Base64 디코더
- **목적**: ZK 회로 내에서 base64-URL 인코딩 데이터 디코딩
- **버전**: v2, v3 (v1은 제거됨)
  - **v2**: 테이블 룩업 + 직접 비트 할당 (~1 제약/문자)
  - **v3**: v2 최적화, 제약 ~40% 감소 (~0.6 제약/문자)
- **주요 내보내기**:
  - `Base64Table` — URL-safe Base64 문자 테이블
  - `Base64TableVar<F>` — 회로 변수 버전
  - `Base64DecoderGadget` — 제약 가젯 (`decode_v2()`, `decode_v3()`)
  - `decoder::IndexBits` — Base64 인덱스의 비트 분해
  - `decoder::Base64CharBits` — 6비트 분해 (Big-Endian)
- **파일**:
  - `mod.rs` — `Base64Table`, `Base64TableVar`, AllocVar 구현
  - `decoder.rs` — `IndexBits`, `Base64CharBits`, 네이티브 디코딩
  - `constraints.rs` — `Base64DecoderGadget` v2/v3 구현 (~800줄)
  - `utils.rs` — 헬퍼 유틸리티
  - `error.rs` — Base64Error 열거형

#### 3. hashes/ — 해시 함수
- **목적**: 네이티브 및 회로용 암호화 해시 기본 요소
- **하위 모듈**:
  - **sha256/**: SHA-256 (비트 수준 연산, ~30k 제약/블록)
  - **blake2s256/**: Blake2s-256 (~15-20k 제약)
  - **mimc7/**: MiMC7 해시 (필드 네이티브, 효율적)
  - **poseidon/**: Poseidon 해시 (필드 네이티브, 가장 효율적)
- **공통 트레이트**: `CRHScheme`, `TwoToOneCRHScheme`
- **핵심 개념**:
  - SHA256은 비트 수준 제약 사용 (ZK에서 비쌈)
  - MiMC7, Poseidon은 필드 네이티브 (더 효율적)

#### 4. matrix/ — Vandermonde 행렬 연산
- **목적**: 앵커 스킴을 위한 선형 대수
- **버전**: v0 (`mod_v0.rs`, 참조용), 현재 (`mod.rs` + `constraints.rs`)
- **주요 내보내기**:
  - `VandermondeMatrix<F>` — m × n 행렬 (m = n - k + 1)
    - `new(n, k)` → `Result<Self, VandermondeMatrixError>`
    - `create_submatrix(indices)` — m × m 부분 행렬 추출
    - `calculate_vector_a(selector)` — witness 벡터 a 계산
    - `multiply_vector(x)` → y = Matrix * x
    - `dimensions()` → (m, n)
  - `solve_linear_system()` — 피벗 가우스 소거법

#### 5. bigint/ — 큰 정수 연산
- **목적**: RSA 서명 검증 등 대형 숫자 연산
- **파일**: `constraints.rs` (1,885줄), `utils.rs`

#### 6. signature/ — 디지털 서명
- **하위 모듈**:
  - **rsa/**: RSA 서명 검증
- **공통 트레이트**: `SignatureScheme` (setup, keygen, sign, verify)

#### 7. mekletree/ — Merkle 트리 가젯
- **목적**: Merkle 트리 커밋먼트 및 멤버십 증명
- **주요 내보내기**: `MerkleCircuitInput<F>`, `MerkleTreeParams`, `Empty` 트레이트

---

### 유틸리티 모듈

#### 8. utils/ — 저수준 유틸리티

| 파일 | 목적 | 버전 상태 |
|------|------|----------|
| `arithmetic.rs` | 필드 산술 (덧셈, 뺄셈, 곱셈, 나눗셈, hadamard_product) | v1 (안정) |
| `bit_byte.rs` | 바이트↔비트 분해, 패킹/언패킹 | v1 (안정) |
| `bit_bytes_v2.rs` | 최적화된 비트-바이트 변환 | v2 (신규) |
| `comparison.rs` | 비교 연산자 (a_lt_b, a_gt_b, lt/gt_bit_vector) | v1 (안정) |
| `comparison_v2.rs` | 최적화된 비교 (is_less_than, is_greater_than) | v2 (신규) |
| `convert.rs` | 타입 변환 (비트↔바이트 등) | v1 (안정) |
| `indexing.rs` | 인덱스 기반 접근 유틸리티 | v1 (안정) |
| `select.rs` | 조건부 선택 (single_multiplexer, one_bit_vector) | v1 (안정) |
| `shifting.rs` | 비트 시프트 연산 | v1 (안정) |
| `slice.rs` | 배열 슬라이싱 (slice, slice_from_start, slice_unopt) | v1 (안정) |
| `slice_v2.rs` | 최적화된 슬라이싱 (slice_efficient, slice_grouped) | v2 (신규) |
| `string_v2.rs` | 문자열 조작 | v2 (신규) |
| `uint32.rs` | 32비트 부호 없는 정수 가젯 | v1 (안정) |
| `error.rs` | UtilError 열거형 | 공통 |

**버전 관리 전략**:
- **v1**: 원본, 충분히 테스트된 구현
- **v2**: 제약 수 감소 또는 효율성 최적화
- 두 버전이 공존하며, 소비자가 필요에 따라 선택
- 최근 코드는 가능한 곳에서 v2를 사용 (예: SHA256은 `comparison_v2`, `slice_v2` 사용)
- **주의**: v1→v2 교체 시 제약 수 변경 가능 → CRS 재생성 필요 여부 반드시 검증

#### 9. debug.rs — 제약 로깅 및 디버깅
- **목적**: 제약 시스템 분석을 위한 개발 도구
- **피처 게이트** (컴파일 시 설정):
  - `print-trace`: arkworks 내부 트레이스 출력
  - `constraints-logging`: 가젯별 제약 디버그 로깅
  - `num-cs-logging`: 제약 수 델타 및 총계 로깅
- **매크로**:
  - `dbg_r1cs_eq!(label, lhs, rhs)` — 두 값 비교
  - `dbg_r1cs_eq_slice!(label, lhs, rhs)` — 배열 비교
  - `dbg_cs_delta!(cs, last, label)` — 제약 수 델타 로그
  - `dbg_cs_total!(cs, label)` — 총 제약 수 로그

---

## 의존성 및 피처 플래그

### 주요 의존성
- **arkworks 생태계**: `ark-ff`, `ark-ec`, `ark-r1cs-std`, `ark-relations`, `ark-groth16`, `ark-crypto-primitives`, `ark-bn254`, `ark-ed-on-bn254`
- **암호화**: `sha2`, `blake2`, `rsa`, `base64`
- **수치 연산**: `num`, `num-bigint`, `num-integer`, `num-traits`
- **기타**: `hex`, `rand`, `regex`, `derivative`, `thiserror`, `ark-serialize`

### 피처 플래그
```toml
[features]
print-trace = ["ark-std/print-trace"]  # arkworks 내부 트레이스 출력
constraints-logging = []               # 가젯별 제약 조건 디버그 로깅
num-cs-logging = []                    # 가젯별 제약 수 로깅
```

---

## 아키텍처 패턴

### 1. 이중 구현 패턴
모든 암호화 연산은 네이티브 + 제약 두 가지 구현을 가짐:
```rust
// 네이티브 (빠름)
pub fn sha256_native(input: &[u8]) -> [u8; 32] { ... }

// 제약 (ZK 회로 내)
pub fn sha256_constraints<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    input: &[FpVar<F>],
) -> Result<[FpVar<F>; 32], SynthesisError> { ... }
```

### 2. 트레이트 기반 추상화
- `CRHScheme` — 충돌 저항 해시
- `SignatureScheme` — 서명 알고리즘
- `AnchorScheme` — 앵커 프로토콜
- 구현 교체 시 소비자 코드 변경 불필요

### 3. AllocVar 패턴
모든 회로 타입은 `AllocVar<Native, F>`를 구현:
```rust
impl<F> AllocVar<Base64Table, F> for Base64TableVar<F> { ... }
```
네이티브 ↔ 회로 표현 간 원활한 변환 가능.

### 4. 에러 처리
각 모듈은 고유한 에러 열거형을 가짐:
- `AnchorError`, `Base64Error`, `HashError`, `SignatureError`, `VandermondeMatrixError`, `UtilError`
- 회로 컨텍스트에서는 `SynthesisError`로 변환

---

## 테스트

### 테스트 구성
- **단위 테스트**: 각 파일 내 `#[cfg(test)] mod tests { ... }`
- **감사 보고서**: `/reports/` 디렉토리에 모듈별 상세 감사 보고서
- **자동 생성 테스트**: `crates/gadget/tests/` (gitignored, 재생성 가능)

### 테스트 실행
```bash
cargo test -p gadget --lib                           # 전체 라이브러리 테스트
cargo test -p gadget --lib anchor::                  # 특정 모듈 테스트
cargo test -p gadget --lib -- --nocapture            # 출력 표시
cargo test -p gadget --features constraints-logging  # 디버그 출력 포함
cargo test -p gadget --features num-cs-logging       # 제약 수 로깅 포함
```

### 커버리지
각 모듈은 다음 테스트를 포함:
- **정상 경로**: 올바른 입력, 성공적 실행
- **엣지 케이스**: 빈 입력, 경계값, 극단적 크기
- **에러 케이스**: 잘못된 입력, 제약 위반
- **제약 수 비교**: 이전 버전 대비 벤치마크

---

## 개발 워크플로

### 새 가젯 추가
1. 모듈 생성: `src/mymodule/mod.rs`
2. 네이티브 버전 구현 (`native.rs` 또는 `mod.rs`)
3. 제약 버전 구현 (`constraints.rs`)
4. 에러 타입 추가 (`error.rs`)
5. `lib.rs`에서 내보내기: `pub mod mymodule;`
6. 네이티브 + 제약 모드 모두 테스트
7. 제약 수 벤치마크 실행
8. `/reports/`에 감사 보고서 작성

### 제약 수 최적화
1. `dbg_cs_delta!` 매크로로 핫스팟 식별
2. v1과 v2 버전의 유틸리티 비교 테스트
3. 룩업 테이블 vs 직접 계산 고려
4. `cargo test --features num-cs-logging`으로 벤치마크

### 회로 디버깅
1. 피처 활성화: `cargo test --features constraints-logging`
2. 매크로 사용: `dbg_r1cs_eq!`, `dbg_cs_delta!`
3. 값 동일성 및 제약 만족 확인
4. `/reports/`의 감사 보고서에서 알려진 이슈 확인

---

## 성능 참고

| 가젯 | 제약 수 (대략) | 비고 |
|------|--------------|------|
| SHA256 | ~30k/블록 | 비트 수준 연산, 가장 비쌈 |
| Blake2s256 | ~15-20k | 중간 비용 |
| MiMC7 / Poseidon | ~수천 | 필드 연산, 가장 효율적 |
| Base64 디코드 v2 | ~1/문자 | 테이블 룩업 |
| Base64 디코드 v3 | ~0.6/문자 | v2 대비 ~40% 감소 |

---

## 빠른 참조

### 모듈 진입점
| 모듈 | 주요 타입 | 진입 트레이트 |
|------|----------|-------------|
| `anchor` | `PoseidonAnchor<F>` | `AnchorScheme` |
| `base64` | `Base64DecoderGadget` | (직접 사용) |
| `hashes::sha256` | `Sha256` | `CRHScheme` |
| `hashes::poseidon` | `CRH<PoseidonConfig>` | `CRHScheme` |
| `signature::rsa` | `RSA` | `SignatureScheme` |
| `mekletree` | `MerkleCircuitInput<F>` | (arkworks Merkle) |
| `matrix` | `VandermondeMatrix<F>` | (직접 사용) |

### 일반적인 import 패턴
```rust
use gadget::hashes::poseidon::get_poseidon_params;
use gadget::anchor::{AnchorScheme, poseidon::PoseidonAnchor};
use gadget::base64::{constraints::Base64DecoderGadget, decoder::IndexBits};
use gadget::matrix::VandermondeMatrix;
use gadget::utils::comparison_v2::is_less_than;
use gadget::utils::slice_v2::slice_efficient;
use gadget::utils::*;  // v1 함수 (a_lt_b, hadamard_product 등)
```

---

**최종 업데이트**: 2026-03-23
**Crate 상태**: 프로덕션 (v0.1.0)
**유지보수**: 활발
