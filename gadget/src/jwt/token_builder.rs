use crate::{
    base64::decode_any_base64_to_string,
    hashes::sha256::{
        H,
        utils::{sha256_pad_with_len, update},
    },
    jwt::{
        error::TokenError,
        token::Token,
        token_no_opt::TokenNoOpt,
        token_opt::{TokenOpt, normalize_overlap, partition_for_hash_optimization},
        types::Claim,
        utils::{find_first_claim_offset, parse_claim_from_str, pay_b64_bits, resize},
    },
    signature::rsa::native::{PublicKey, Signature},
};

/// Padding constants for constraint efficiency
const B64_PAD_BYTE: u8 = b'A'; // Base64 'A' = 0x00 (zero value)
const JWT_PAD_BYTE: u8 = b'0'; // Padding for JWT content

/// Common configuration for token transformation
#[derive(Clone, Debug)]
pub struct TokenConfig {
    pub max_jwt_len: usize,
    pub max_payload_len: usize,
    pub max_claim_len: usize,
}

impl TokenConfig {
    pub fn new(
        max_jwt_len: usize,
        max_payload_len: usize,
        max_claim_len: usize,
    ) -> Self {
        Self {
            max_jwt_len,
            max_payload_len,
            max_claim_len,
        }
    }

    pub fn max_payload_b64_len(&self) -> usize {
        ((self.max_payload_len + 2) / 3) * 4
    }
}

/// Intermediate representation for token transformation
/// Contains all parsed and computed data needed for both Opt and NoOpt variants
#[derive(Clone, Debug)]
pub struct TokenIntermediate {
    // Original token data
    pub header_b64: Vec<u8>,
    pub payload_b64: Vec<u8>,
    pub claims: Vec<Claim>,
    pub sig: Signature,
    pub pk: PublicKey,

    // Computed metadata
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub signing_input: Vec<u8>, // header.payload
}

impl TokenIntermediate {
    /// Create intermediate representation from Token
    pub fn from_token(token: &Token, config: &TokenConfig) -> Result<Self, TokenError> {
        let pay_offset_b64 = token.header_b64.len() + 1; // +1 for '.'
        let pay_len_b64 = token.payload_b64.len();

        // Build signing input: "header.payload"
        let signing_input = [&token.header_b64[..], b".", &token.payload_b64[..]].concat();

        // Parse and resize claims
        let payload_str =
            decode_any_base64_to_string(&String::from_utf8_lossy(&token.payload_b64))?;

        let claims = token
            .claims
            .iter()
            .map(|c| {
                let mut nc = parse_claim_from_str(&payload_str, &c.key)?;
                nc.value = resize(&nc.value, config.max_claim_len, JWT_PAD_BYTE);
                Ok(nc)
            })
            .collect::<Result<Vec<_>, TokenError>>()?;

        Ok(Self {
            header_b64: token.header_b64.clone(),
            payload_b64: token.payload_b64.clone(),
            claims,
            sig: token.sig.clone(),
            pk: token.pk.clone(),
            pay_offset_b64,
            pay_len_b64,
            signing_input,
        })
    }

    /// Generate bit witness for base64 decoding
    pub fn generate_bit_witness(
        &self,
        payload_b64: &[u8],
        max_len: usize,
    ) -> Result<Vec<bool>, TokenError> {
        pay_b64_bits(payload_b64, max_len, B64_PAD_BYTE)
    }

    /// Generate SHA-256 padded payload
    pub fn generate_shapad_payload(
        &self,
        data: &[u8],
        total_len: usize,
        max_jwt_len: usize,
    ) -> Vec<u8> {
        let mut shapad = sha256_pad_with_len(data, total_len);
        shapad.resize(max_jwt_len, JWT_PAD_BYTE);
        shapad
    }
}

/// Builder for TokenNoOpt - no optimization, full SHA-256 in circuit
pub struct TokenNoOptBuilder {
    intermediate: TokenIntermediate,
    config: TokenConfig,
}

impl TokenNoOptBuilder {
    pub fn new(token: &Token, config: TokenConfig) -> Result<Self, TokenError> {
        let intermediate = TokenIntermediate::from_token(token, &config)?;
        Ok(Self {
            intermediate,
            config,
        })
    }

    pub fn build(self) -> Result<TokenNoOpt, TokenError> {
        let bit_witness = self.intermediate.generate_bit_witness(
            &self.intermediate.payload_b64,
            self.config.max_payload_b64_len(),
        )?;

        let num_blocks = self.intermediate.signing_input.len() / 64;
        let shapad_payload_b64 = self.intermediate.generate_shapad_payload(
            &self.intermediate.signing_input,
            self.intermediate.signing_input.len(),
            self.config.max_jwt_len,
        );

        Ok(TokenNoOpt {
            pay_offset_b64: self.intermediate.pay_offset_b64,
            pay_len_b64: self.intermediate.pay_len_b64,
            claims: self.intermediate.claims,
            shapad_payload_b64,
            sig: self.intermediate.sig,
            pk: self.intermediate.pk,
            bit_witness,
            state: H.to_vec(), // Initial SHA-256 state
            num_blocks,
        })
    }
}

/// Builder for TokenOpt - optimized with pre-computed SHA-256 state
pub struct TokenOptBuilder {
    intermediate: TokenIntermediate,
    config: TokenConfig,
}

impl TokenOptBuilder {
    pub fn new(token: &Token, config: TokenConfig) -> Result<Self, TokenError> {
        let intermediate = TokenIntermediate::from_token(token, &config)?;
        Ok(Self {
            intermediate,
            config,
        })
    }

    pub fn build(self) -> Result<TokenOpt, TokenError> {
        // Find optimal partition point
        let first_claim_offset = find_first_claim_offset(&self.intermediate.claims)?;
        let first_claim_offset_b64 = (first_claim_offset / 3) * 4; // Align to base64 boundary

        // Partition JWT into pre-computed (pre) and in-circuit (post) parts
        // New strategy: prefix = header + "." is always in pre
        let (pre, post, overlap, overlap_len) = partition_for_hash_optimization(
            &self.intermediate.header_b64,
            &self.intermediate.payload_b64,
            first_claim_offset_b64,
        )?;

        // Extract payload portion from post
        // Note: With new strategy, '.' is always in pre, so post might not have it
        let pay_offset_b64 = post
            .iter()
            .position(|&b| b == b'.')
            .map(|idx| idx + 1)
            .unwrap_or(0); // If no '.', post is all payload
        let post_payload_only = &post[pay_offset_b64..];

        // Reconstruct base64 string for decoding
        let post_b64_bytes = [&overlap[..], post_payload_only].concat();
        let post_b64_str = String::from_utf8(post_b64_bytes)
            .map_err(|_| TokenError::InvalidFormat("Invalid UTF-8 in overlap/post".to_string()))?;

        // Decode to get actual payload content
        let post_str = decode_any_base64_to_string(&post_b64_str)?;

        // Re-parse claims based on the new post payload
        let claims = self
            .intermediate
            .claims
            .iter()
            .map(|c| {
                let mut nc = parse_claim_from_str(&post_str, &c.key)?;
                nc.value = resize(&nc.value, self.config.max_claim_len, JWT_PAD_BYTE);
                Ok(nc)
            })
            .collect::<Result<Vec<_>, TokenError>>()?;

        // Normalize overlap to fixed size
        let normalized_overlap = normalize_overlap(overlap, overlap_len, JWT_PAD_BYTE);

        // Pre-compute SHA-256 state
        let state = if pre.is_empty() {
            // No pre-computation: use initial SHA-256 IV
            H.to_vec()
        } else {
            // Pre-compute state by processing complete 64-byte blocks
            if pre.len() % 64 != 0 {
                return Err(TokenError::InvalidLengthError(format!(
                    "pre must be multiple of 64 bytes, got {}",
                    pre.len()
                )));
            }
            update(&pre).to_vec()
        };

        // Generate bit witness
        let bit_witness = self.intermediate.generate_bit_witness(
            post_b64_str.as_bytes(),
            self.config.max_payload_b64_len() + 4,
        )?;

        // Generate SHA-256 padded post
        let mut shapad_payload_b64 = sha256_pad_with_len(&post, pre.len() + post.len());
        let num_blocks = shapad_payload_b64.len() / 64 - 1;
        shapad_payload_b64.resize(self.config.max_jwt_len, JWT_PAD_BYTE);

        Ok(TokenOpt {
            pay_offset_b64,
            pay_len_b64: post_payload_only.len(),
            claims,
            shapad_payload_b64,
            sig: self.intermediate.sig,
            pk: self.intermediate.pk,
            bit_witness,
            overlap: normalized_overlap,
            overlap_len,
            state,
            num_blocks,
        })
    }
}

/// Unified builder interface
pub struct TokenBuilder {
    token: Token,
    config: TokenConfig,
}

impl TokenBuilder {
    pub fn new(token: Token, config: TokenConfig) -> Self {
        Self { token, config }
    }

    /// Build optimized token (pre-computed SHA-256)
    pub fn build_opt(self) -> Result<TokenOpt, TokenError> {
        TokenOptBuilder::new(&self.token, self.config)?.build()
    }

    /// Build non-optimized token (full SHA-256 in circuit)
    pub fn build_no_opt(self) -> Result<TokenNoOpt, TokenError> {
        TokenNoOptBuilder::new(&self.token, self.config)?.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibm9uY2UiOiJhYmMxMjMiLCJleHAiOjE1MTYyMzkwMjJ9.signature";
    const N: &str = "test_n_value";

    #[test]
    fn test_token_builder_opt() {
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        let config = TokenConfig::new(1024, 512, 128);

        let token_opt = TokenBuilder::new(token, config).build_opt().unwrap();

        assert!(token_opt.pay_offset_b64 > 0);
        assert_eq!(token_opt.claims.len(), 3);
        assert_eq!(token_opt.state.len(), 8); // SHA-256 state
    }

    #[test]
    fn test_token_builder_no_opt() {
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        let config = TokenConfig::new(1024, 512, 128);

        let token_no_opt = TokenBuilder::new(token, config).build_no_opt().unwrap();

        assert!(token_no_opt.pay_offset_b64 > 0);
        assert_eq!(token_no_opt.claims.len(), 3);
        assert_eq!(token_no_opt.state, H.to_vec()); // Initial SHA-256 state
    }

    #[test]
    fn test_token_config() {
        let config = TokenConfig::new(1024, 512, 128);
        assert_eq!(config.max_jwt_len, 1024);
        assert_eq!(config.max_payload_len, 512);
        assert_eq!(config.max_claim_len, 128);
        assert_eq!(config.max_payload_b64_len(), 684); // ((512 + 2) / 3) * 4
    }

    #[test]
    fn test_intermediate_representation() {
        let token = Token::new(JWT, N, &["sub", "nonce", "exp"]).unwrap();
        let config = TokenConfig::new(1024, 512, 128);

        let intermediate = TokenIntermediate::from_token(&token, &config).unwrap();

        assert_eq!(intermediate.claims.len(), 3);
        assert!(intermediate.signing_input.len() > 0);
        assert_eq!(
            intermediate.signing_input,
            [&token.header_b64[..], b".", &token.payload_b64[..]].concat()
        );
    }
}
