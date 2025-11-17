# Groth16 Integration Tests

이 디렉토리는 Groth16 영지식 증명 시스템의 통합 테스트를 포함합니다.

## 테스트 개요

### 1. 키 직렬화 테스트 (`test_key_serialization`)

Anchor Key의 직렬화 및 역직렬화가 올바르게 작동하는지 검증합니다.

```bash
cargo test --test groth16_integration_test test_key_serialization -- --nocapture
```

**검증 사항:**
- Poseidon Anchor Key 생성
- 파일에 저장
- 파일에서 로드
- 메타데이터 일치 확인 (n, k, max_aud_len, max_iss_len, max_sub_len)

### 2. Anchor 생성 테스트 (`test_anchor_creation`)

문자열로부터 Poseidon Anchor를 생성하는 기능을 검증합니다.

```bash
cargo test --test groth16_integration_test test_anchor_creation -- --nocapture
```

**검증 사항:**
- 문자열 배열을 Anchor로 변환
- Anchor 해시 계산
- 데이터 길이 검증

### 3. Groth16 Setup 테스트 (`test_groth16_setup`) - IGNORED

Groth16 Proving Key와 Verifying Key 생성을 테스트합니다.

```bash
cargo test --test groth16_integration_test test_groth16_setup -- --nocapture --ignored
```

**참고:** 이 테스트는 시간이 오래 걸리고 실제 암호화 키가 필요하므로 기본적으로 무시됩니다.

**테스트 프로세스:**
1. Anchor Key 생성
2. Schnorr Key 생성
3. Circuit 설정
4. Groth16 setup 수행
5. Proving Key 저장
6. Solidity Verifier 생성
7. Proving Key 로드 검증

**요구사항:**
- `.env` 파일에 `SOLIDITY_VERIFIER_PATH` 설정

### 4. Groth16 Prove & Verify 테스트 (`test_groth16_prove_and_verify`) - IGNORED

전체 증명 생성 및 검증 플로우를 테스트합니다.

```bash
cargo test --test groth16_integration_test test_groth16_prove_and_verify -- --nocapture --ignored
```

**참고:** 이 테스트는 유효한 JWT와 서명 데이터가 필요하므로 기본적으로 무시됩니다.

**테스트 프로세스:**
1. Setup 키 로드
2. Witness 데이터 준비 (JWT, signature, merkle proof 등)
3. 증명 생성
4. 증명 직렬화
5. (향후) 증명 검증

**현재 상태:**
- 증명 생성: ✅ 구현됨
- 증명 검증: ⏳ `verify_proof` 함수 구현 필요

## 모든 테스트 실행

기본 테스트 (무시된 테스트 제외):
```bash
cargo test --test groth16_integration_test
```

모든 테스트 (무시된 테스트 포함):
```bash
cargo test --test groth16_integration_test -- --ignored --nocapture
```

## 테스트 데이터 구조

테스트는 `test_outputs/` 디렉토리에 다음과 같은 파일들을 생성합니다:

```
test_outputs/
├── test_anchor_key.bin           # Poseidon Anchor Public Key
├── test_schnorr_key.bin          # Schnorr Public Key & Parameters
├── test_proving_key.bin          # Groth16 Proving Key (매우 큼)
└── verifier.sol                  # Solidity Verifier Contract
```

## 실제 사용 시나리오

### Setup (1회만 수행)

```rust
use zkpasskey_crypto_modules::service::snark::snark::generate_and_write_proving_key;

// 1. Anchor Key와 Schnorr Key가 이미 생성되어 있어야 함
// 2. Proving Key 생성 (매우 시간이 오래 걸림)
generate_and_write_proving_key(
    "path/to/anchor_key.bin".to_string(),
    "path/to/schnorr_key.bin".to_string(),
    512,  // max_jwt_len
    256,  // max_payload_len
    50,   // max_aud_len
    50,   // max_iss_len
    50,   // max_nonce_len
    100,  // max_sub_len
    5,    // tree_height
    "path/to/proving_key.bin".to_string(),
)?;
```

### Prove (매번 수행)

```rust
use zkpasskey_crypto_modules::service::snark::snark::generate_proof;

// Witness 데이터 준비 후 증명 생성
let (proof, public_inputs) = generate_proof(
    "path/to/proving_key.bin".to_string(),
    "path/to/anchor_key.bin".to_string(),
    "path/to/schnorr_key.bin".to_string(),
    anchor_parts,
    selected_secrets,
    jwt,
    pk,
    merkle_proof,
    root,
    signature,
    leaf_index,
    selector,
    counter,
    random,
    h_userop,
    slot,
)?;

// 증명 직렬화
let mut proof_bytes = Vec::new();
proof.serialize_uncompressed(&mut proof_bytes)?;
```

### Verify (온체인 또는 오프체인)

```rust
// TODO: verify_proof 함수 구현 필요
use zkpasskey_crypto_modules::service::snark::snark::verify_proof;

let is_valid = verify_proof(
    vk_bytes,
    proof_bytes,
    public_inputs_str,
)?;
```

## 메모리 최적화

`generate_proof` 함수는 모바일 환경을 고려하여 메모리 효율적으로 설계되었습니다:

- **파일 기반 로딩**: 키를 메모리에 캐싱하지 않고 필요할 때만 파일에서 로드
- **자동 메모리 해제**: 증명 생성 후 자동으로 키가 메모리에서 해제됨
- **대용량 키 처리**: Proving Key는 수백 MB에 달할 수 있으므로 영속적 캐싱 피함

자세한 내용은 [docs/memory_optimization.md](../docs/memory_optimization.md)를 참고하세요.

## 향후 작업

- [ ] `verify_proof` 함수 구현
- [ ] 실제 JWT 및 서명 데이터를 사용한 end-to-end 테스트
- [ ] 성능 벤치마크 추가
- [ ] 다양한 파라미터 조합 테스트
- [ ] 에러 케이스 테스트 추가
