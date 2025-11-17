use crate::{
    base64::{decode_any_base64, decode_any_base64_to_string},
    jwt::{
        error::TokenError,
        token::Token,
        types::Claim,
        utils::parse_claim_from_str,
    },
    signature::rsa::native::{PublicKey, Signature},
};

/// Builder for constructing JWT Token with fluent API
/// 
/// # Example
/// ```ignore
/// use crate::jwt::TokenBuilder;
/// 
/// let token = TokenBuilder::new(jwt_string, public_key_n)
///     .add_claim("iss")
///     .add_claim("sub")
///     .add_claim("nonce")
///     .build()?;
/// ```
pub struct TokenBuilder {
    jwt: String,
    n: String,
    claim_keys: Vec<String>,
}

impl TokenBuilder {
    /// Create a new TokenBuilder with JWT string and RSA public key modulus
    /// 
    /// # Arguments
    /// * `jwt` - JWT string in format "header.payload.signature"
    /// * `n` - RSA public key modulus (base64 encoded)
    pub fn new(jwt: impl Into<String>, n: impl Into<String>) -> Self {
        Self {
            jwt: jwt.into(),
            n: n.into(),
            claim_keys: Vec::new(),
        }
    }

    /// Add a claim key to extract from the JWT payload
    /// 
    /// # Arguments
    /// * `key` - Claim key name (e.g., "iss", "sub", "nonce")
    /// 
    /// # Example
    /// ```ignore
    /// let builder = TokenBuilder::new(jwt, n)
    ///     .add_claim("iss")
    ///     .add_claim("sub");
    /// ```
    pub fn add_claim(mut self, key: impl Into<String>) -> Self {
        self.claim_keys.push(key.into());
        self
    }

    /// Add multiple claim keys at once
    /// 
    /// # Arguments
    /// * `keys` - Iterator of claim key names
    /// 
    /// # Example
    /// ```ignore
    /// let builder = TokenBuilder::new(jwt, n)
    ///     .add_claims(&["iss", "sub", "nonce"]);
    /// ```
    pub fn add_claims<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.claim_keys.extend(keys.into_iter().map(|k| k.into()));
        self
    }

    /// Build the Token
    /// 
    /// This will:
    /// 1. Parse the JWT string
    /// 2. Decode the payload
    /// 3. Extract the specified claims
    /// 4. Decode the signature
    /// 5. Construct the RSA public key
    pub fn build(self) -> Result<Token, TokenError> {
        // 1. JWT 파싱
        let (header_and_payload, sig_b64) = self.jwt.rsplit_once('.').ok_or(
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
        let mut claims = Vec::with_capacity(self.claim_keys.len());
        for key in &self.claim_keys {
            claims.push(parse_claim_from_str(&payload_str, key)?);
        }

        // 4. Signature 디코딩
        let sig = decode_any_base64(sig_b64)?;

        // 5. Public Key 구성
        let n_decoded = decode_any_base64(&self.n)?;
        let e_decoded = decode_any_base64("AQAB")?; // Standard RSA exponent
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";
    const N: &str = "xjlCRBqghVqN0mHyW8BhWGqBH2UJzgQrJQlrHc5KLQvXzW_-_QqWvnxfbhMvLw8UwGzHnX3V7xGLx70HNHxKwQ";

    #[test]
    fn test_token_builder_single_claim() {
        let token = TokenBuilder::new(JWT, N)
            .add_claim("sub")
            .build()
            .unwrap();
        
        assert_eq!(token.claims.len(), 1);
        assert_eq!(token.claims[0].key, "sub");
        assert_eq!(token.claims[0].value, "1234567890");
        
        println!("✓ Single claim builder test passed");
    }

    #[test]
    fn test_token_builder_multiple_claims() {
        let token = TokenBuilder::new(JWT, N)
            .add_claim("sub")
            .add_claim("name")
            .add_claim("admin")
            .build()
            .unwrap();
        
        assert_eq!(token.claims.len(), 3);
        assert_eq!(token.claims[0].key, "sub");
        assert_eq!(token.claims[1].key, "name");
        assert_eq!(token.claims[2].key, "admin");
        
        println!("✓ Multiple claims builder test passed");
        println!("  Claims extracted: {:?}", 
            token.claims.iter().map(|c| &c.key).collect::<Vec<_>>());
    }

    #[test]
    fn test_token_builder_add_claims_batch() {
        let token = TokenBuilder::new(JWT, N)
            .add_claims(vec!["sub", "name", "admin"])
            .build()
            .unwrap();
        
        assert_eq!(token.claims.len(), 3);
        
        println!("✓ Batch claims builder test passed");
    }

    #[test]
    fn test_token_builder_mixed_style() {
        let token = TokenBuilder::new(JWT, N)
            .add_claim("sub")
            .add_claims(vec!["name", "admin"])
            .add_claim("iat")
            .build()
            .unwrap();
        
        assert_eq!(token.claims.len(), 4);
        assert_eq!(token.claims[0].key, "sub");
        assert_eq!(token.claims[1].key, "name");
        assert_eq!(token.claims[2].key, "admin");
        assert_eq!(token.claims[3].key, "iat");
        
        println!("✓ Mixed style builder test passed");
    }

    #[test]
    fn test_token_builder_no_claims() {
        let token = TokenBuilder::new(JWT, N)
            .build()
            .unwrap();
        
        assert_eq!(token.claims.len(), 0);
        assert!(!token.header_b64.is_empty());
        assert!(!token.payload_b64.is_empty());
        
        println!("✓ No claims builder test passed");
    }

    #[test]
    fn test_token_builder_invalid_claim() {
        let result = TokenBuilder::new(JWT, N)
            .add_claim("nonexistent_key")
            .build();
        
        assert!(result.is_err());
        
        println!("✓ Invalid claim error handling test passed");
    }

    #[test]
    fn test_token_builder_comparison_with_old_api() {
        // Old API
        let token_old = Token::new(JWT, N, &["sub", "name", "admin"]).unwrap();
        
        // New API
        let token_new = TokenBuilder::new(JWT, N)
            .add_claims(vec!["sub", "name", "admin"])
            .build()
            .unwrap();
        
        // Should produce same results
        assert_eq!(token_old.claims.len(), token_new.claims.len());
        for (old, new) in token_old.claims.iter().zip(token_new.claims.iter()) {
            assert_eq!(old.key, new.key);
            assert_eq!(old.value, new.value);
        }
        
        println!("✓ API compatibility test passed");
    }
}
