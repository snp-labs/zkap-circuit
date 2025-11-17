use ark_serialize::CanonicalSerialize;

use crate::{
    base64::{decode_any_base64, decode_any_base64_to_string},
    jwt::{
        error::TokenError,
        types::Claim,
        utils::{find_claim_value, parse_claim_from_str},
    },
    signature::rsa::native::{PublicKey, Signature},
};

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct Token {
    pub header_b64: Vec<u8>,
    pub payload_b64: Vec<u8>,
    pub claims: Vec<Claim>,
    pub sig: Signature,
    pub pk: PublicKey,
}

impl Token {
    /// Creates a new Token from JWT string and claim keys.
    /// 
    /// **Deprecated**: Use `JwtTokenBuilder` for more flexible claim extraction.
    /// 
    /// # Migration Example
    /// ```ignore
    /// // Old way:
    /// let token = Token::new(jwt, n, &["iss", "sub", "nonce"])?;
    /// 
    /// // New way (fluent API):
    /// use crate::jwt::JwtTokenBuilder;
    /// let token = JwtTokenBuilder::new(jwt, n)
    ///     .add_claim("iss")
    ///     .add_claim("sub")
    ///     .add_claim("nonce")
    ///     .build()?;
    /// 
    /// // Or batch:
    /// let token = JwtTokenBuilder::new(jwt, n)
    ///     .add_claims(&["iss", "sub", "nonce"])
    ///     .build()?;
    /// ```
    #[deprecated(since = "0.2.0", note = "Use JwtTokenBuilder for fluent API")]
    pub fn new(jwt: &str, n: &str, keys: &[&str]) -> Result<Self, TokenError> {
        // 1. JWT 파싱
        // rsplit_once는 오른쪽부터, split_once는 왼쪽부터 문자열을 한 번만 자릅니다.
        let (header_and_payload, sig_b64) = jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;
        let (header_b64, payload_b64) =
            header_and_payload
                .split_once('.')
                .ok_or(TokenError::InvalidFormat(
                    "JWT must have 3 parts".to_string(),
                ))?;

        // 2. Payload 처리
        let payload_str = decode_any_base64_to_string(payload_b64)?;

        // 3. Claim 추출
        let mut claims = Vec::with_capacity(keys.len());
        for key in keys {
            claims.push(parse_claim_from_str(&payload_str, key)?);
        }

        // 4. Signature 디코딩
        let sig = decode_any_base64(sig_b64)?;

        let n_decoded = decode_any_base64(n)?;

        let e_decoded = decode_any_base64("AQAB")?; // Assuming a default exponent for RSA
        let pk = PublicKey {
            n: n_decoded,
            e: e_decoded,
        };

        Ok(Token {
            header_b64: header_b64.as_bytes().to_vec(),
            payload_b64: payload_b64.as_bytes().to_vec(),
            claims,
            sig: Signature(sig),
            pk,
        })
    }

    pub fn get_claim_value(&self, key: &str) -> Result<String, TokenError> {
        let value = find_claim_value(&self.claims, key)?;
        Ok(value.to_string())
    }
}
