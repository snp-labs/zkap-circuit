use circuit::token::{Claim, ClaimIndices, error::TokenError, parse_claim_from_str};
use common::constants::ZkPasskeyConfig;
use gadget::{
    base64::mod_v2::{IndexBits, decode_any_base64, decode_any_base64_to_string},
    hashes::sha256::{H, utils::update},
    signature::rsa::{PublicKey, Signature},
};

use crate::Secret;

// SHA-256 블록 크기 (바이트 단위)
const SHA_BLOCK_LEN: usize = 64;

/// 회로에 주입될 Witness 데이터들을 담는 DTO 구조체
/// 요청하신 모든 계산 결과 항목이 포함됩니다.
#[derive(Debug, Clone)]
pub struct JwtCircuitWitness {
    // SHA256 & Base64 관련
    pub state: Vec<u32>,
    pub nblocks: usize,
    pub sha_pad_payload_b64: Vec<u8>,
    pub index_bits: IndexBits,
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub total_len: usize,
    pub pre_hash_block_len: usize,
    pub pad_start_in_suffix: usize,

    // Crypto 관련
    pub pk: PublicKey,
    pub sig: Signature,

    // Claims 관련
    pub claim_indices: Vec<ClaimIndices>,
}

#[derive(Clone)]
pub struct TokenBuilder {
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
    pub claims: Vec<Claim>,
}

impl TokenBuilder {
    /// JWT 문자열을 파싱하여 빌더를 생성합니다.
    /// 이 단계에서는 무거운 연산(Base64 디코딩, 서명 변환 등)을 수행하지 않습니다.
    pub fn new(jwt: &str, keys: Vec<&str>) -> Result<Self, TokenError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::InvalidFormat(
                "JWT must have three parts separated by dots".to_string(),
            ));
        }

        let payload = decode_any_base64_to_string(parts[1])?;
        let mut claims = Vec::with_capacity(keys.len());
        for key in keys {
            claims.push(parse_claim_from_str(&payload, key)?);
        }

        Ok(Self {
            header_b64: parts[0].to_string(),
            payload_b64: parts[1].to_string(),
            signature_b64: parts[2].to_string(),
            claims,
        })
    }

    /// 회로에 필요한 모든 Witness 데이터를 계산하여 반환합니다.
    pub fn build<Config: ZkPasskeyConfig>(
        &self,
        pk_modulus_b64: &str,
    ) -> Result<JwtCircuitWitness, TokenError> {
        // 1. SHA-256 State 및 Padding 계산
        let (
            state,
            nblocks,
            sha_pad_payload_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
            total_len,
            pre_hash_block_len,
            pad_start_in_suffix,
        ) = self.compute_sha_and_base64_witness::<Config>()?;

        // 2. Public Key 및 Signature 디코딩
        let (pk, sig) = self.compute_crypto_witness(pk_modulus_b64)?;

        // 3. Claims Indices 추출 (상수 CLAIMS 순서대로)
        let claim_indices = self.compute_claim_indices()?;

        Ok(JwtCircuitWitness {
            state,
            nblocks,
            sha_pad_payload_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
            total_len,
            pre_hash_block_len,
            pad_start_in_suffix,
            pk,
            sig,
            claim_indices,
        })
    }

    fn compute_sha_and_base64_witness<Config: ZkPasskeyConfig>(
        &self,
    ) -> Result<
        (
            Vec<u32>,
            usize,
            Vec<u8>,
            IndexBits,
            usize,
            usize,
            usize,
            usize,
            usize,
        ),
        TokenError,
    > {
        let pre_hash_block_len = self.header_b64.len() / SHA_BLOCK_LEN;
        let header_b64_rest = self.header_b64[SHA_BLOCK_LEN * pre_hash_block_len..].as_bytes();

        let pay_offset_b64 = header_b64_rest.len() + 1; // '.' 길이 포함
        let pay_len_b64 = self.payload_b64.len();

        // 1-1. Initial State 계산 (Header의 앞부분 블록 처리)
        let state = if pre_hash_block_len == 0 {
            H.to_vec()
        } else {
            update(self.header_b64[..SHA_BLOCK_LEN * pre_hash_block_len].as_bytes()).to_vec()
        };

        // 1-2. Padding 대상 데이터 구성: [Header 나머지] + "." + [Payload]
        // 서명 검증 대상은 "Header.Payload" 전체이지만,
        // 회로 최적화를 위해 이미 해시된 Header 앞부분은 State로 넘기고 나머지만 패딩합니다.
        // *주의*: 여기서 full_token의 일부를 슬라이싱하는 것이 정확하지만,
        // 구현상 header_rest + "." + payload 구조를 만듭니다.
        let post = [header_b64_rest, b".", self.payload_b64.as_bytes()].concat();

        // 전체 길이 (State에 들어간 앞부분 포함)를 기준으로 패딩해야 올바른 SHA 패딩이 됨
        let total_len = self.header_b64.len() + 1 + self.payload_b64.len();

        let pad_start_in_suffix = total_len - pre_hash_block_len * SHA_BLOCK_LEN;

        // 1-3. Base64 Index Bits 계산 (Payload만 사용)
        // 회로 내에서 Base64 디코딩을 위한 비트 인덱스 정보
        let index_bits = IndexBits::from_base64_url(&self.payload_b64, Config::MAX_PAYLOAD_B64_LEN)
            .map_err(|e| TokenError::InvalidFormat(format!("index_bits error: {:?}", e)))?;

        // SHA-256 패딩 적용
        let mut sha_pad_payload_b64 = sha256_pad_with_len(&post, total_len);

        let nblocks = sha_pad_payload_b64.len() / SHA_BLOCK_LEN - 1;

        // 회로 입력 크기에 맞춰 리사이징
        sha_pad_payload_b64.resize(Config::MAX_JWT_B64_LEN, 0);

        Ok((
            state,
            nblocks,
            sha_pad_payload_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
            total_len,
            pre_hash_block_len,
            pad_start_in_suffix,
        ))
    }

    fn compute_crypto_witness(
        &self,
        pk_modulus_b64: &str,
    ) -> Result<(PublicKey, Signature), TokenError> {
        // Signature 디코딩
        let sig_bytes = decode_any_base64(&self.signature_b64)?;

        // Public Key 구성 (Exponent는 65537 고정)
        let n_decoded = decode_any_base64(pk_modulus_b64)?;
        let e_decoded = decode_any_base64("AQAB")?;

        let pk = PublicKey {
            n: n_decoded,
            e: e_decoded,
        };

        Ok((pk, Signature(sig_bytes)))
    }

    fn compute_claim_indices(&self) -> Result<Vec<ClaimIndices>, TokenError> {
        // // Payload 디코딩 (JSON 파싱을 위해)
        // let payload_str = decode_any_base64_to_string(&self.payload_b64)?;

        // // 상수 CLAIMS 배열을 순회하며 인덱스 추출
        // let mut claims_indices = Vec::with_capacity(CLAIMS.len());

        // for &key in CLAIMS.iter() {
        //     let indices = parse_claim_from_str(&payload_str, key)?;
        //     claims_indices.push(indices.indices);
        // }
        let mut claims_indices = Vec::with_capacity(self.claims.len());

        for claim in &self.claims {
            claims_indices.push(claim.indices.clone());
        }

        Ok(claims_indices)
    }

    pub fn parse_secret(&self) -> Secret {
        let mut sub = None;
        let mut iss = None;
        let mut aud = None;

        for (idx, key) in self.claims.iter().enumerate() {
            match key.key.as_str() {
                "sub" => sub = Some(self.claims[idx].value.clone()),
                "iss" => iss = Some(self.claims[idx].value.clone()),
                "aud" => aud = Some(self.claims[idx].value.clone()),
                _ => {}
            }
        }

        // 필수 필드가 누락되었는지 확인
        Secret {
            sub: sub.expect("Missing 'sub' claim"),
            iss: iss.expect("Missing 'iss' claim"),
            aud: aud.expect("Missing 'aud' claim"),
        }
    }

    // Claims에서 특정 키에 해당하는 값을 반환합니다.
    pub fn get_claim_by(&self, key: &str) -> Result<&str, TokenError> {
        for claim in &self.claims {
            if claim.key == key {
                return Ok(&claim.value);
            }
        }
        Err(TokenError::NotFoundKeyError(key.to_string()))
    }
}

/// Helper: SHA-256 Padding
fn sha256_pad_with_len(input: &[u8], total_len: usize) -> Vec<u8> {
    let block_size = 64;
    let mut padded = input.to_vec();

    // 1. Append '1' bit (0x80 byte)
    padded.push(0x80);

    // 2. Calculate zero padding
    // 패딩 계산 시, 현재 padded 길이만 고려하는 게 아니라
    // 실제 전체 메시지 길이(total_len)를 기준으로 0을 채워야 할 위치를 잡아야 할 수도 있음.
    // 하지만 일반적인 구현에서는 '현재 버퍼' 기준으로 블록을 맞추고 마지막에 길이를 붙임.
    // 입력 input은 이미 state 처리된 앞부분이 제외된 상태이므로,
    // 길이 블록(8바이트)과 0x80을 포함하여 block_size 배수가 되도록 0을 채움.

    // 현재 구현은 input 뒤에 바로 붙이는 방식이므로,
    // (input len + 1 (0x80) + 8 (length) + k (zeros)) % 64 == 0 이어야 함.

    let current_len = padded.len();
    let zero_pad_len = (block_size - ((current_len + 8) % block_size)) % block_size;
    padded.extend(vec![0; zero_pad_len]);

    // 3. Append length in bits (Big Endian 64-bit)
    // *중요*: SHA256 패딩의 길이는 '전체 메시지'의 비트 길이여야 함.
    let bit_length = (total_len as u64) * 8;
    padded.extend(&bit_length.to_be_bytes());

    padded
}
