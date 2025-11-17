use ark_serialize::CanonicalSerialize;

use crate::{
    hashes::sha256::{H, utils::sha256_pad_with_len},
    jwt::{
        error::TokenError,
        token::Token,
        types::Claim,
        utils::{pay_b64_bits, resize},
    },
    signature::rsa::native::{PublicKey, Signature},
};

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct TokenNoOpt {
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub claims: Vec<Claim>,
    pub shapad_payload_b64: Vec<u8>,
    pub sig: Signature,
    pub pk: PublicKey,
    pub bit_witness: Vec<bool>,
    pub state: Vec<u32>, // SHA-256 state has 8 words
    pub num_blocks: usize,
}

impl TokenNoOpt {
    /// Creates an empty TokenNoOpt with specified maximum lengths.
    /// Used for circuit setup and parameter initialization.
    /// 
    /// **Note**: For creating TokenNoOpt from a parsed Token, use `TokenBuilder` instead.
    pub fn empty(keys: Vec<&str>, max_jwt_len: usize, max_payload_len: usize) -> Self {
        let claims = (0..keys.len()).map(|_| Claim::empty()).collect::<Vec<_>>();
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        TokenNoOpt {
            pay_offset_b64: 0,
            pay_len_b64: 0,
            claims,
            shapad_payload_b64: vec![0u8; max_jwt_len],
            sig: Signature::default(),
            pk: PublicKey::empty(),
            bit_witness: vec![false; (max_payload_b64_len) * 6],
            state: vec![0u32; 8], // SHA-256 state has 8 words
            num_blocks: 1,
        }
    }

    /// Creates a new TokenNoOpt from a parsed Token.
    /// Computes full SHA-256 hash in-circuit (no optimization).
    /// 
    /// **Deprecated**: Use `TokenBuilder::new(token, config).build_no_opt()` instead for better maintainability.
    /// 
    /// # Migration Example
    /// ```ignore
    /// // Old way:
    /// let token_no_opt = TokenNoOpt::new(&token, 1024, 512, 128)?;
    /// 
    /// // New way:
    /// use TokenBuilder, TokenConfig;
    /// let config = TokenConfig::new(1024, 512, 128);
    /// let token_no_opt = TokenBuilder::new(token, config).build_no_opt()?;
    /// ```
    #[deprecated(since = "0.2.0", note = "Use TokenBuilder instead")]
    pub fn new(
        token: &Token,
        max_jwt_len: usize,
        max_payload_len: usize,
        max_claim_len: usize,
    ) -> Result<Self, TokenError> {
        let b64_pad_byte = b'A'; // 'A'는 base64에서 0 값에 해당하므로 패딩 문자로 적합합니다.
        let jwt_pad_byte = b'0'; // 패딩 문자로 사용할 바이트

        let bit_witness = {
            let max_pay_len_b64 = (max_payload_len + 2) / 3 * 4;
            pay_b64_bits(&token.payload_b64, max_pay_len_b64, b64_pad_byte)?
        };

        let (shapad_payload_b64, num_blocks) = {
            let signing_input = [&token.header_b64[..], b".", &token.payload_b64[..]].concat();
            let num_blocks = signing_input.len() / 64;
            let mut out = sha256_pad_with_len(&signing_input, signing_input.len());
            out.resize(max_jwt_len, jwt_pad_byte);
            (out, num_blocks)
        };

        let claims = token
            .claims
            .iter()
            .cloned()
            .map(|mut c| {
                c.value = resize(&c.value, max_claim_len, jwt_pad_byte);
                c
            })
            .collect();

        Ok(Self {
            pay_offset_b64: token.header_b64.len() + 1,
            pay_len_b64: token.payload_b64.len(),
            claims: claims,
            shapad_payload_b64,
            sig: token.sig.clone(),
            pk: token.pk.clone(),
            bit_witness,
            state: H.to_vec(),
            num_blocks,
        })
    }
}
