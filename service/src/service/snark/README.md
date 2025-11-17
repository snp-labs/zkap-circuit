# SNARK Service

이 모듈은 Groth16 zk-SNARK 증명 시스템을 위한 서비스 레이어를 제공합니다.

## 구조

- `snark.rs`: 키 생성 및 증명 생성/검증을 위한 메인 서비스 함수들
- `utils.rs`: 직렬화/역직렬화 및 검증 유틸리티 함수들

## 주요 기능

### 1. 키 생성 (Key Generation)

#### Proving Key와 Verifying Key 동시 생성
```rust
use zkpasskey_crypto_modules::service::snark::setup_keys;
use zkpasskey_crypto_modules::interface::snark::ZkpasskeySetupRequestDto;

let req = ZkpasskeySetupRequestDto {
    max_jwt_len: 2048,
    max_payload_len: 1024,
    max_aud_len: 256,
    max_iss_len: 256,
    max_sub_len: 128,
    tree_height: 32,
    anchor_key_path: "/path/to/anchor_key".to_string(),
    schnorr_key_path: "/path/to/schnorr_key".to_string(),
};

setup_keys(req, "/path/to/proving_key", "/path/to/verifying_key")?;
```

#### Proving Key 단독 생성
```rust
use zkpasskey_crypto_modules::service::snark::generate_and_write_proving_key;

generate_and_write_proving_key(req, "/path/to/proving_key")?;
```

#### Verifying Key 단독 생성
```rust
use zkpasskey_crypto_modules::service::snark::generate_and_write_verifying_key;

generate_and_write_verifying_key(req, "/path/to/verifying_key")?;
```

### 2. 키 로딩 (Key Loading)

```rust
use zkpasskey_crypto_modules::service::snark::load_proving_key_handle;

// Proving Key를 로드하고 핸들 얻기
let handle = load_proving_key_handle("/path/to/proving_key".to_string())?;
```

### 3. 증명 생성 (Proof Generation)

```rust
use zkpasskey_crypto_modules::service::snark::generate_proof;

// witness 데이터 준비
let witness: Vec<u8> = prepare_witness_data();

// 증명 생성
let proof_bytes = generate_proof(handle, witness)?;
```

### 4. 증명 검증 (Proof Verification)

```rust
use zkpasskey_crypto_modules::service::snark::verify_proof;

// Verifying Key, 증명, 공개 입력 준비
let vk_bytes = read_verifying_key("/path/to/verifying_key")?;
let proof_bytes = read_proof("/path/to/proof")?;
let public_inputs = vec![
    "123456789".to_string(),
    "987654321".to_string(),
];

// 증명 검증
let is_valid = verify_proof(vk_bytes, proof_bytes, public_inputs)?;
```

## 구현 상태

현재 이 모듈은 **스켈레톤 코드**입니다. 실제 사용을 위해서는 다음 항목들을 구현해야 합니다:

### TODO: 구현해야 할 항목들

1. **Circuit 정의**
   - zkPasskey를 위한 R1CS 제약 조건 정의
   - JWT 검증 로직
   - Anchor 및 Schnorr 서명 검증 로직
   - Merkle Tree 검증 로직

2. **키 생성 구현**
   - `generate_and_write_proving_key()` 함수 구현
   - `generate_and_write_verifying_key()` 함수 구현
   - `setup_keys()` 함수 구현
   - Circuit 초기화 및 setup 로직

3. **키 로딩 구현**
   - `load_proving_key_handle()` 함수 구현
   - KeyManager와의 통합

4. **증명 생성 구현**
   - `generate_proof()` 함수 구현
   - Witness 데이터 처리
   - Circuit 인스턴스화

5. **증명 검증 구현**
   - `verify_proof()` 함수 구현
   - 공개 입력 파싱
   - 직렬화/역직렬화 로직

6. **유틸리티 함수 구현 (utils.rs)**
   - `serialize_proof()`: ark-serialize를 사용한 증명 직렬화
   - `deserialize_proof()`: 증명 역직렬화
   - `serialize_vk()`: Verifying Key 직렬화
   - `deserialize_vk()`: Verifying Key 역직렬화
   - `parse_public_inputs()`: 문자열을 필드 원소로 변환
   - `validate_witness()`: Witness 검증
   - `prepare_circuit_input()`: Circuit 입력 준비

## Anchor Service와의 비교

이 모듈은 `anchor` service의 구조를 참고하여 작성되었습니다:

| Anchor Service | SNARK Service |
|----------------|---------------|
| `generate_and_write_poseidon_anchor_key()` | `generate_and_write_proving_key()` |
| `generate_and_write_dl_anchor_key()` | `generate_and_write_verifying_key()` |
| `create_poseidon_anchor()` | `generate_proof()` |
| `poseidon_derive_indices()` | `verify_proof()` |
| `load_poseidon_anchor_key_handle()` | `load_proving_key_handle()` |

## 의존성

- `ark-groth16`: Groth16 zk-SNARK 구현
- `ark-crypto-primitives`: 암호화 프리미티브
- `ark-ec`: 타원곡선 연산
- `ark-ff`: 유한체 연산
- `ark-serialize`: 직렬화/역직렬화

## 참고 자료

- [Groth16 논문](https://eprint.iacr.org/2016/260.pdf)
- [arkworks 문서](https://docs.rs/ark-groth16/)
- [R1CS 제약 시스템](https://docs.rs/ark-relations/)
