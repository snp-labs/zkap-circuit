use gadget::{
    base64::{base64_to_6bit_bools, decode_any_base64, decode_any_base64_to_string},
    hashes::sha256::{
        H,
        utils::{sha256_pad_with_len, update},
    },
    jwt::error::TokenError,
    signature::rsa::native::{PublicKey, Signature},
    token::{
        claim::{Claim, ClaimIndices, parse_claim_from_str},
        decode::TokenPayloadB64,
    },
};

const SHA_BLOCK_LEN: usize = 64; // SHA-256 블록 크기 (바이트 단위)

pub struct TokenBuilderV2 {
    pub header_b64: String,
    pub payload_b64: String,
    pub signature_b64: String,
    pub claims: Vec<Claim>,
}

impl TokenBuilderV2 {
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

        Ok(TokenBuilderV2 {
            header_b64,
            payload_b64,
            signature_b64,
            claims,
        })
    }

    pub fn get_claim_indices(&self) -> Result<Vec<ClaimIndices>, TokenError> {
        Ok(self
            .claims
            .iter()
            .map(|claim| claim.indices.clone())
            .collect())
    }

    pub fn build_state_and_nblock(&self) -> Result<(Vec<u32>, usize), TokenError> {
        let pre_hash_block_len = self.header_b64.len() / SHA_BLOCK_LEN;

        let state = if pre_hash_block_len == 0 {
            H.to_vec()
        } else {
            update(self.header_b64[..SHA_BLOCK_LEN * pre_hash_block_len].as_bytes()).to_vec()
        };

        let nblocks = {
            let header_rest = self.header_b64[SHA_BLOCK_LEN * pre_hash_block_len..].as_bytes();
            let sha_pad_payload_b64 = generate_sha_pad_payload_b64(
                header_rest,
                &self.payload_b64.as_bytes(),
                self.header_b64.len() + self.payload_b64.len() + 1, // +1 for the dot '.'
            );

            sha_pad_payload_b64.len() / SHA_BLOCK_LEN - 1
        };

        Ok((state, nblocks))
    }

    pub fn build_token_payload_b64(
        &self,
        max_jwt_len: usize,
        max_payload_len: usize,
        nblocks: &usize,
    ) -> Result<TokenPayloadB64, TokenError> {
        let pre_hash_block_len = self.header_b64.len() / SHA_BLOCK_LEN;
        let header_b64_rest = &self.header_b64[pre_hash_block_len * 64..];
        let pay_offset_b64 = header_b64_rest.len() + 1; // +1 for the dot '.'
        let pay_len_b64 = self.payload_b64.len();

        let mut sha_pad_payload_b64 = generate_sha_pad_payload_b64(
            header_b64_rest.as_bytes(),
            self.payload_b64.as_bytes(),
            self.header_b64.len() + self.payload_b64.len() + 1, // +1 for the dot '.'
        );

        sha_pad_payload_b64.resize(max_jwt_len, b'0');

        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;
        let mut padded_payload = self.payload_b64.as_bytes().to_vec();
        padded_payload.resize(max_payload_b64_len + 4, b'A'); // Pad with 'A' (base64 zero)

        let bit_witness = base64_to_6bit_bools(&padded_payload)
            .map_err(|e| TokenError::InvalidFormat(format!("Base64 decoding error: {:?}", e)))?;

        Ok(TokenPayloadB64 {
            pay_offset_b64,
            pay_len_b64,
            sha_pad_payload_b64,
            bit_witness,
        })
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
}

fn generate_sha_pad_payload_b64(
    header_b64_rest: &[u8],
    payload: &[u8],
    header_plus_payload_len: usize,
) -> Vec<u8> {
    let post = [header_b64_rest, b".", payload].concat();

    sha256_pad_with_len(&post, header_plus_payload_len)
}
