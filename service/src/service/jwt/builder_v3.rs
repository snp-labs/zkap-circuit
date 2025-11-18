use circuit::baerae::constants::{MAX_JWT_B64_LEN, MAX_PAYLOAD_B64_LEN};
use gadget::{
    base64::mod_v2::{IndexBits, decode_any_base64, decode_any_base64_to_string},
    hashes::sha256::{H, utils::update},
    jwt::error::TokenError,
    signature::rsa::native::{PublicKey, Signature},
    token::claim::{Claim, ClaimIndices, parse_claim_from_str},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

pub struct TokenBuilderV3 {
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
    pub claims: Vec<Claim>,
}

const SHA_BLOCK_LEN: usize = 64; // SHA-256 블록 크기 (바이트 단위)

impl TokenBuilderV3 {
    pub fn new(jwt: &str, keys: Vec<&str>) -> Result<Self, TokenError> {
        let (header_b64, payload_b64, signature_b64) = jwt
            .split_once('.')
            .and_then(|(header, rest)| {
                rest.split_once('.').map(|(payload, signature)| {
                    (
                        header.to_string(),
                        payload.to_string(),
                        signature.to_string(),
                    )
                })
            })
            .ok_or(TokenError::InvalidFormat(
                "JWT must have three parts separated by dots".to_string(),
            ))?;

        let payload = decode_any_base64_to_string(&payload_b64)?;

        let mut claims = Vec::with_capacity(keys.len());
        for key in keys {
            claims.push(parse_claim_from_str(&payload, key)?);
        }

        Ok(TokenBuilderV3 {
            header_b64,
            payload_b64,
            signature_b64,
            claims,
        })
    }

    pub fn build_token_witness(
        &self,
    ) -> Result<(Vec<u32>, usize, Vec<u8>, IndexBits, usize, usize), TokenError> {
        let pre_hash_block_len = self.header_b64.len() / SHA_BLOCK_LEN;
        let header_b64_rest = self.header_b64[SHA_BLOCK_LEN * pre_hash_block_len..].as_bytes();
        let pay_offset_b64 = header_b64_rest.len() + 1; // '.' 길이 포함
        let pay_len_b64 = self.payload_b64.len();

        let state = if pre_hash_block_len == 0 {
            H.to_vec()
        } else {
            update(self.header_b64[..SHA_BLOCK_LEN * pre_hash_block_len].as_bytes()).to_vec()
        };

        let post = [header_b64_rest, b".", self.payload_b64.as_bytes()].concat();

        let mut sha_pad_payload_b64 =
            sha256_pad_with_len(&post, self.header_b64.len() + self.payload_b64.len() + 1);

        let nblocks = sha_pad_payload_b64.len() / SHA_BLOCK_LEN - 1;

        let index_bits = IndexBits::from_base64_url(
            &String::from_utf8(sha_pad_payload_b64.clone()).expect("Invalid UTF-8"),
            MAX_PAYLOAD_B64_LEN,
        )?;

        sha_pad_payload_b64.resize(MAX_JWT_B64_LEN, 0);

        Ok((
            state,
            nblocks,
            sha_pad_payload_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
        ))
    }

    pub fn build_pk_sig(&self, pk: &str) -> Result<(PublicKey, Signature), TokenError> {
        // 4. Signature 디코딩
        let sig = decode_any_base64(&self.signature_b64)?;

        // 5. Public Key 구성
        let n_decoded = decode_any_base64(pk)?;
        let e_decoded = decode_any_base64("AQAB")?; // Standard RSA exponent
        let pk = PublicKey {
            n: n_decoded,
            e: e_decoded,
        };

        Ok((pk, Signature(sig)))
    }

    pub fn get_claim_indices(&self) -> Result<Vec<ClaimIndices>, TokenError> {
        Ok(self
            .claims
            .iter()
            .map(|claim| claim.indices.clone())
            .collect())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaeraeClaim {
    pub aud: String,
    pub exp: usize,
    pub iss: String,
    pub nonce: String,
    pub sub: String,
}

/// JWT 토큰을 주어진 공개 키로 디코딩하는 함수
/// # Arguments
/// * `token` - 디코딩할 JWT 토큰 문자열(Base64 인코딩된 형식)
/// * `pk` - RSA 공개 키의 모듈러스 부분(Base64 인코딩된 형식)
/// # Returns
/// * Claim 구조체를 포함하는 Result
pub fn decode_jwt(token: &str, pk: &str) -> Result<BaeraeClaim, jsonwebtoken::errors::Error> {
    let e = "AQAB";

    let decoding_key = DecodingKey::from_rsa_components(&pk, &e)?;
    let validation = Validation::new(Algorithm::RS256);
    let token_data = decode::<BaeraeClaim>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

fn sha256_pad_with_len(input: &[u8], max_len: usize) -> Vec<u8> {
    let block_size = 64; // Block size in bytes
    let mut padded = input.to_vec();

    // Append the '1' bit as 0x80
    padded.push(0x80);

    // Calculate the number of zero bytes to add
    let zero_pad_len = (block_size - ((padded.len() + 8) % block_size)) % block_size;
    padded.extend(vec![0; zero_pad_len]);

    // Append the length in bits as a 64-bit big-endian integer
    let bit_length = (max_len as u64) * 8;
    padded.extend(&bit_length.to_be_bytes());

    padded
}
