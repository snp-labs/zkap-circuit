use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::Path, sponge::poseidon::PoseidonConfig};

use gadget::{
    base64::{base64_to_6bit_bools, decode_any_base64, decode_any_base64_to_string},
    hashes::sha256::{
        H,
        utils::{sha256_pad_with_len, update},
    },
    jwt::{Token, error::TokenError, types::Claim, utils::parse_claim_from_str},
    mekletree::{MerkleCircuitInput, tree_config::MerkleTreeParams},
    signature::rsa::native::{PublicKey, Signature},
    token::{claim::ClaimIndices, decode::TokenPayloadB64, signature::TokenSig},
};

use crate::{
    error::error::ApplicationError,
    service::constants::{AppCurve, AppField, BNP, PoseidonHash}, utils::point::{ascii_to_field_be, str_to_field},
};

pub struct TokenBuilder {
    jwt: String,
    n: String,
    claim_keys: Vec<String>,
    sha_pad_payload_b64: Vec<u8>,
    post: String,
    claims: Vec<Claim>,
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
            sha_pad_payload_b64: Vec::new(),
            claims: Vec::new(),
            post: String::new(),
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

    /// Build TokenSig for circuit constraints
    ///
    /// Creates a TokenSig structure containing signature, public key, and SHA-256 state
    /// for efficient signature verification in zero-knowledge circuits.
    ///
    /// # Example
    /// ```ignore
    /// let token_sig = TokenBuilder::new(jwt, n)
    ///     .build_token_sig()?;
    /// ```
    pub fn build_token_sig(&mut self) -> Result<TokenSig, TokenError> {
        const SHA_BLOCK_LEN: usize = 64;
        // Parse JWT
        let (header_and_payload, sig_b64) = self.jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;

        let (header_b64, _payload_b64) =
            header_and_payload
                .split_once('.')
                .ok_or(TokenError::InvalidFormat(
                    "JWT must have 3 parts".to_string(),
                ))?;

        // Decode signature
        let sig = decode_any_base64(sig_b64)?;

        // Construct public key
        let n_decoded = decode_any_base64(&self.n)?;
        let e_decoded = decode_any_base64("AQAB")?;
        let pk = PublicKey {
            n: n_decoded,
            e: e_decoded,
        };

        let pre_hash_block_len = header_b64.len() / SHA_BLOCK_LEN;

        let state = if pre_hash_block_len == 0 {
            H.to_vec()
        } else {
            update(header_b64[..SHA_BLOCK_LEN * pre_hash_block_len].as_bytes()).to_vec()
        };

        let nblocks = {
            let post = header_and_payload[SHA_BLOCK_LEN * pre_hash_block_len..].as_bytes();
            let sha_pad_payload_b64 = sha256_pad_with_len(post, header_and_payload.len());
            self.sha_pad_payload_b64 = sha_pad_payload_b64.clone();
            self.post = String::from_utf8(post.to_vec()).unwrap();
            sha_pad_payload_b64.len() / 64 - 1
        };

        Ok(TokenSig {
            sig: Signature(sig),
            pk,
            state,
            nblocks,
        })
    }

    /// Build TokenPayloadB64 for base64 decoding in circuit
    ///
    /// Creates a TokenPayloadB64 structure containing base64-encoded payload
    /// with offset, length, and bit witness for efficient decoding in circuits.
    ///
    /// # Arguments
    /// * `max_jwt_len` - Maximum JWT length for padding
    /// * `max_payload_len` - Maximum payload length (decoded)
    ///
    /// # Example
    /// ```ignore
    /// let token_payload = TokenBuilder::new(jwt, n)
    ///     .build_token_payload_b64(1024, 512)?;
    /// ```
    pub fn build_token_payload_b64(
        &self,
        max_jwt_len: usize,
        max_payload_len: usize,
    ) -> Result<TokenPayloadB64, TokenError> {
        // Parse JWT
        let (header_and_payload, _) = self.jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;
        let (_header_b64, payload_b64) =
            header_and_payload
                .split_once('.')
                .ok_or(TokenError::InvalidFormat(
                    "JWT must have 3 parts".to_string(),
                ))?;

        let pay_len_b64 = payload_b64.len();

        // Prepare signing input (header.payload) for SHA-256

        let mut sha_pad_payload_b64 = self.sha_pad_payload_b64.clone();

        let pay_offset_b64 = {
            let (partial_header, _) = self.post.split_once('.').ok_or(
                TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
            )?;
            partial_header.len() + 1 // +1 for the dot '.'
        };

        sha_pad_payload_b64.resize(max_jwt_len, b'0');

        // Generate bit witness for base64 decoding
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;
        let mut padded_payload = payload_b64.as_bytes().to_vec();
        padded_payload.resize(max_payload_b64_len + 4, b'A'); // Pad with 'A' (base64 zero)

        println!("padded_payload: {:?}", padded_payload);
        println!("padded_payload length: {}", padded_payload.len());

        let bit_witness = base64_to_6bit_bools(&padded_payload)
            .map_err(|e| TokenError::InvalidFormat(format!("Base64 decoding error: {:?}", e)))?;

        Ok(TokenPayloadB64 {
            pay_offset_b64,
            pay_len_b64,
            sha_pad_payload_b64,
            bit_witness,
        })
    }

    /// Build ClaimIndices for a specific claim key
    ///
    /// Extracts claim metadata including offset, length, and value position
    /// for efficient claim verification in zero-knowledge circuits.
    ///
    /// # Arguments
    /// * `key` - The claim key to extract (e.g., "iss", "sub", "nonce")
    ///
    /// # Example
    /// ```ignore
    /// let claim_indices = TokenBuilder::new(jwt, n)
    ///     .build_claim_indices("nonce")?;
    /// ```
    pub fn build_claim_indices(&self, key: &str) -> Result<ClaimIndices, TokenError> {
        // Parse JWT
        let (header_and_payload, _) = self.jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;
        let (_, payload_b64) =
            header_and_payload
                .split_once('.')
                .ok_or(TokenError::InvalidFormat(
                    "JWT must have 3 parts".to_string(),
                ))?;

        // Decode payload
        let payload_str = decode_any_base64_to_string(payload_b64)?;

        // Parse claim
        let claim = parse_claim_from_str(&payload_str, key)?;

        // Convert from jwt::types::ClaimIndices to token::claim::ClaimIndices
        Ok(ClaimIndices {
            offset: claim.indices.offset,
            claim_len: claim.indices.len,
            colon_idx: claim.indices.colon_idx,
            value_idx: claim.indices.value_idx,
            value_len: claim.indices.value_len,
        })
    }

    pub fn build_claim_indices_v2(&self) -> Result<Vec<ClaimIndices>, TokenError> {
        let (header_and_payload, _) = self.jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;
        let (_, payload_b64) =
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

        Ok(claims
            .into_iter()
            .map(|claim| ClaimIndices {
                offset: claim.indices.offset,
                claim_len: claim.indices.len,
                colon_idx: claim.indices.colon_idx,
                value_idx: claim.indices.value_idx,
                value_len: claim.indices.value_len,
            })
            .collect())
    }

    /// Build all ClaimIndices for all registered claim keys
    ///
    /// Returns a vector of ClaimIndices corresponding to the claim keys
    /// added via `add_claim()` or `add_claims()`.
    ///
    /// # Example
    /// ```ignore
    /// let indices = TokenBuilder::new(jwt, n)
    ///     .add_claims(&["iss", "sub", "nonce"])
    ///     .build_all_claim_indices()?;
    /// ```
    pub fn build_all_claim_indices(self) -> Result<Vec<ClaimIndices>, TokenError> {
        // Parse JWT
        let (header_and_payload, _) = self.jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;
        let (_, payload_b64) =
            header_and_payload
                .split_once('.')
                .ok_or(TokenError::InvalidFormat(
                    "JWT must have 3 parts".to_string(),
                ))?;

        // Decode payload
        let payload_str = decode_any_base64_to_string(payload_b64)?;

        // Parse all claims
        let mut indices = Vec::with_capacity(self.claim_keys.len());
        for key in &self.claim_keys {
            let claim = parse_claim_from_str(&payload_str, key)?;
            // Convert from jwt::types::ClaimIndices to token::claim::ClaimIndices
            indices.push(ClaimIndices {
                offset: claim.indices.offset,
                claim_len: claim.indices.len,
                colon_idx: claim.indices.colon_idx,
                value_idx: claim.indices.value_idx,
                value_len: claim.indices.value_len,
            });
        }

        Ok(indices)
    }

    pub fn build_claims(&self) -> Result<Vec<Claim>, TokenError> {
        // Parse JWT
        let (header_and_payload, _) = self.jwt.rsplit_once('.').ok_or(
            TokenError::InvalidFormat("JWT must have 3 parts".to_string()),
        )?;
        let (_, payload_b64) =
            header_and_payload
                .split_once('.')
                .ok_or(TokenError::InvalidFormat(
                    "JWT must have 3 parts".to_string(),
                ))?;

        // Decode payload
        let payload_str = decode_any_base64_to_string(payload_b64)?;

        // Parse all claims
        let mut claims = Vec::with_capacity(self.claim_keys.len());
        for key in &self.claim_keys {
            let claim = parse_claim_from_str(&payload_str, key)?;
            claims.push(claim);
        }

        Ok(claims)
    }
}

pub(crate) fn build_merkle_proof(
    hash_param: &PoseidonConfig<AppField>,
    leaf_idx: usize,
    path: &[String],
    iss: &String,
    n: &str,
    e: &str,
) -> Result<MerkleCircuitInput<AppField>, ApplicationError> {
    let n = decode_any_base64(n)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to decoding n: {:?}", e)))?;
    let e = decode_any_base64(e)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to decoding e: {:?}", e)))?;
    let pk = PublicKey { n, e };
    let pk_limbs = pk.to_limbs::<BNP, AppCurve>();
    let iss_limbs = ascii_to_field_be::<AppField>(iss).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to convert iss to field: {:?}", e))
    })?;
    let pre_image = [iss_limbs, pk_limbs.0].concat();
    let leaf = PoseidonHash::evaluate(hash_param, pre_image)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to hash leaf: {:?}", e)))?;

    // 1. 스마트 컨트랙트에서 받은 문자열 경로를 필드(Field) 타입의 벡터로 변환합니다.
    let path_field: Vec<AppField> = path
        .iter()
        .map(|p_str| {
            str_to_field(p_str).map_err(|e| {
                ApplicationError::InvalidFormat(format!(
                    "Failed to convert merkle path element to field: {:?}",
                    e
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 2. 경로가 비어있는 경우, 오류를 발생시켜 안전하게 처리합니다 (Guard Clause).
    // - 0번째 요소는 리프의 형제 노드(sibling) 해시입니다.
    // - 남은 요소들이 바로 인증 경로(auth_path)가 됩니다.
    //  - 스마트 컨트랙트는 리프에 가까운 순서로 주므로, 루트에 가까운 순서로 뒤집습니다.
    let (leaf_sibling_hash, auth_path_slice) = path_field.split_first().ok_or_else(|| {
        ApplicationError::InvalidFormat(
            "Merkle path cannot be empty; must contain at least sibling hash".to_string(),
        )
    })?;

    let auth_path: Vec<_> = auth_path_slice.iter().rev().copied().collect();

    // 4. 최종적으로 Path 구조체를 생성하여 반환합니다.
    let path = Path::<MerkleTreeParams<AppField>> {
        leaf_sibling_hash: *leaf_sibling_hash,
        auth_path,
        leaf_index: leaf_idx,
    };

    Ok(MerkleCircuitInput {
        leaf,
        leaf_idx,
        path,
    })
}

pub(crate) fn build_slot_indices_and_h_slot_and_z(
    parameters: &PoseidonConfig<AppField>,
    slot: &u8,
    selector: &[bool],
    random: &AppField,
) -> Result<(Vec<AppField>, AppField, Vec<AppField>), ApplicationError> {
    let mut slot_indices = Vec::with_capacity(selector.len());
    let mut z = Vec::with_capacity(selector.len());
    for (i, selected) in selector.iter().enumerate() {
        if *selected {
            let index = AppField::from(i as u64);
            slot_indices.push(index);
        }

        if i == *slot as usize {
            z.push(AppField::from(1u64));
        } else {
            z.push(AppField::from(0u64));
        }
    }

    // h_slot 계산 h_slot = H(slot_indices || random)
    let mut pre_image = slot_indices.clone();
    pre_image.push(*random);
    let h_slot = PoseidonHash::evaluate(parameters, pre_image)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Failed to hash h_slot: {:?}", e)))?;

    Ok((slot_indices, h_slot, z))
}
