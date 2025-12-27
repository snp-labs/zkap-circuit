# zkpasskey-monorepo

Rust와 arkworks 생태계를 활용한 패스키(Passkey) 인증용 영지식 증명(ZKP) 시스템 구현체입니다.

## 개요 (Overview)

본 모노레포는 안전한 패스키 인증을 위한 영지식 증명 시스템의 전체 구현을 포함하고 있습니다. 이 시스템은 zk-SNARK를 포함한 암호화 프리미티브를 사용하여, 사용자의 민감한 인증 정보를 노출하지 않고도 프라이버시를 보호하며 인증할 수 있도록 지원합니다.

### 주요 기능

* **SNARK 구현**: 패스키 검증을 위한 SNARK 회로
* **다국어 지원**: Node.js(NAPI) 위한 네이티브 바인딩 제공
* **메모리 효율적 증명 생성**: 메모리 사용량 추적 기능이 포함된 최적화된 제약 조건 시스템(Constraint System)
* **모듈형 아키텍처**: 회로(Circuit), 가젯(Gadget), 서비스 계층 제공

## 아키텍처 (Architecture)

```
zkpasskey-monorepo/
├── circuit/          # SNARK 회로 구현체
├── gadget/           # 암호화 가젯 및 유틸리티
├── service/          # 고수준 서비스 계층
├── api/              # 언어별 바인딩 (NAPI, FRB)
├── common/           # 공용 유틸리티 및 설정
└── vendors/          # 수정된 외부 의존성

```

## 빠른 시작 (Quick Start)

### 사전 요구 사항

* Rust 1.70+ (2024 에디션)
* Node.js 20.12.2+ (NAPI 바인딩용)

### 빌드 및 실행 방법

#### 1. 통합 설정 스크립트 (추천)

가장 권장되는 방법은 `zkap-contract` 내의 `setup-zk-custom2.sh` 스크립트를 사용하는 것입니다. 이 스크립트는 CRS 생성, NAPI 빌드, 컨트랙트 배포 과정을 자동화합니다.

```bash
# zkap-contract 디렉토리 내에서 실행
./setup-zk-custom2.sh
```

#### 2. CRS 및 검증 키 생성 (수동)

```bash
cargo run --release --features baerae --bin generate_baerae_crs -- <file_path>
```

#### 3. Node.js (NAPI) 패키지 빌드

API 바인딩 결과물은 프로젝트 루트의 `./dist/baerae` 경로에 생성됩니다.

* **표준 빌드 (제약 조건 로깅 포함):**
```bash
cd api/napi
npm run build:dist
```


* **상세 로깅 빌드 (제약 조건 + 메모리 로깅 포함):**
```bash
cd api/napi
npm run build:dist:logging
```


## 서비스 제공자 준비 사항 (OIDC Setup)

프로덕션 배포 전, 서비스 제공자는 제공할 OIDC 서비스에 대해 **(1) Audience 리스트**와 **(2) OpenID Provider(Issuer/PK) 해시**를 미리 생성해야 합니다. 이 과정은 `generate_hash.rs` 도구를 사용하며, 실행 전 `setup-zk-custom2.sh`가 선행되어야 합니다.

### 1. OpenID Provider 해시 생성 (Leaf Hash)

Issuer와 Public Key 쌍을 해싱하여 `leaf_output.json`을 생성합니다.

```bash
cargo run --release --bin generate_hash -- leaf \
  --iss "https://accounts.google.com, https://kauth.kakao.com" \
  --pk "<GOOGLE_PK>, <KAKAO_PK>"
```

### 2. Audience 리스트 해시 생성 (Aud Hash)

허용된 Audience 값들을 해싱하여 `aud_output.json`을 생성합니다.

```bash
cargo run --release --bin generate_hash -- aud \
  --values "google_client_id, kakao_client_id"
```