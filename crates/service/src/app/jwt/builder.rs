use circuit::token::{Claim, ClaimIndices, error::TokenError, parse_claim_from_str};
use circuit::constants::ZkPasskeyConfig;
use gadget::{
    base64::{IndexBits, decode_any_base64, decode_any_base64_to_string},
    signature::rsa::{PublicKey, Signature},
};

use crate::Secret;

// SHA-256 block size in bytes
const SHA_BLOCK_LEN: usize = 64;

/// DTO struct holding Witness data to be injected into the circuit.
/// Passes the full JWT to the circuit so that the complete SHA256 computation
/// is performed inside the circuit starting from the initial H constants.
#[derive(Debug, Clone)]
pub struct JwtCircuitWitness {
    // SHA256 & Base64
    pub nblocks: usize,
    /// Full JWT (header.payload) with SHA256 padding applied
    pub sha_pad_jwt_b64: Vec<u8>,
    pub index_bits: IndexBits,
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub total_len: usize,
    /// Padding start byte index (absolute position in full JWT)
    pub pad_start_byte_idx: usize,

    // Crypto
    pub pk: PublicKey,
    pub sig: Signature,

    // Claims
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
    /// Parses a JWT string and creates a builder.
    /// Heavy operations (Base64 decoding, signature conversion, etc.) are not performed at this stage.
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

    /// Computes and returns all Witness data required by the circuit.
    /// Passes the full JWT to the circuit so that the complete SHA256 computation
    /// is performed inside the circuit starting from the initial H constants.
    pub fn build<Config: ZkPasskeyConfig>(
        &self,
        pk_modulus_b64: &str,
    ) -> Result<JwtCircuitWitness, TokenError> {
        // 1. Compute Full JWT SHA-256 Padding (midstate removed)
        let (
            nblocks,
            sha_pad_jwt_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
            total_len,
            pad_start_byte_idx,
        ) = self.compute_sha_and_base64_witness::<Config>()?;

        // 2. Decode Public Key and Signature
        let (pk, sig) = self.compute_crypto_witness(pk_modulus_b64)?;

        // 3. Extract Claims Indices (in order of constant CLAIMS array)
        let claim_indices = self.compute_claim_indices()?;

        Ok(JwtCircuitWitness {
            nblocks,
            sha_pad_jwt_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
            total_len,
            pad_start_byte_idx,
            pk,
            sig,
            claim_indices,
        })
    }

    /// Applies SHA256 padding to the full JWT and returns it.
    /// The circuit performs the complete SHA256 computation starting from the initial H constants.
    #[allow(clippy::type_complexity)]
    fn compute_sha_and_base64_witness<Config: ZkPasskeyConfig>(
        &self,
    ) -> Result<
        (
            usize,      // nblocks
            Vec<u8>,    // sha_pad_jwt_b64
            IndexBits,  // index_bits
            usize,      // pay_offset_b64
            usize,      // pay_len_b64
            usize,      // total_len
            usize,      // pad_start_byte_idx
        ),
        TokenError,
    > {
        // Full JWT = header + "." + payload
        let full_jwt = format!("{}.{}", self.header_b64, self.payload_b64);
        let total_len = full_jwt.len();

        // Payload offset: header length + 1 (dot)
        let pay_offset_b64 = self.header_b64.len() + 1;
        let pay_len_b64 = self.payload_b64.len();

        // Padding start position (absolute byte index, same as total_len)
        let pad_start_byte_idx = total_len;

        // Compute Base64 Index Bits (Payload only)
        let index_bits = IndexBits::from_base64_url(&self.payload_b64, Config::MAX_PAYLOAD_B64_LEN)
            .map_err(|e| TokenError::InvalidFormat(format!("index_bits error: {:?}", e)))?;

        // Apply SHA-256 padding (over the full JWT)
        let mut sha_pad_jwt_b64 = sha256_pad(full_jwt.as_bytes());

        // nblocks = total blocks - 1 (0-indexed final block)
        let nblocks = sha_pad_jwt_b64.len() / SHA_BLOCK_LEN - 1;

        // Resize to match circuit input size
        sha_pad_jwt_b64.resize(Config::MAX_JWT_B64_LEN, 0);

        Ok((
            nblocks,
            sha_pad_jwt_b64,
            index_bits,
            pay_offset_b64,
            pay_len_b64,
            total_len,
            pad_start_byte_idx,
        ))
    }

    fn compute_crypto_witness(
        &self,
        pk_modulus_b64: &str,
    ) -> Result<(PublicKey, Signature), TokenError> {
        // Decode Signature
        let sig_bytes = decode_any_base64(&self.signature_b64)?;

        // Construct Public Key (Exponent is fixed at 65537)
        let n_decoded = decode_any_base64(pk_modulus_b64)?;
        let e_decoded = decode_any_base64(gadget::constants::RSA_DEFAULT_EXPONENT_B64)?;

        let pk = PublicKey {
            n: n_decoded,
            e: e_decoded,
        };

        Ok((pk, Signature(sig_bytes)))
    }

    fn compute_claim_indices(&self) -> Result<Vec<ClaimIndices>, TokenError> {
        // // Decode payload (for JSON parsing)
        // let payload_str = decode_any_base64_to_string(&self.payload_b64)?;

        // // Iterate over the constant CLAIMS array to extract indices
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

    pub fn parse_secret(&self) -> Result<Secret, TokenError> {
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

        // Check if required fields are missing
        Ok(Secret {
            sub: sub.ok_or_else(|| TokenError::NotFoundKeyError("sub".to_string()))?,
            iss: iss.ok_or_else(|| TokenError::NotFoundKeyError("iss".to_string()))?,
            aud: aud.ok_or_else(|| TokenError::NotFoundKeyError("aud".to_string()))?,
        })
    }

    // Returns the value corresponding to the given key from Claims.
    pub fn get_claim_by(&self, key: &str) -> Result<&str, TokenError> {
        for claim in &self.claims {
            if claim.key == key {
                return Ok(&claim.value);
            }
        }
        Err(TokenError::NotFoundKeyError(key.to_string()))
    }
}

/// Helper: SHA-256 Padding for full message
fn sha256_pad(input: &[u8]) -> Vec<u8> {
    let block_size = 64;
    let total_len = input.len();
    let mut padded = input.to_vec();

    // 1. Append '1' bit (SHA256_PAD_MARKER = 0x80)
    padded.push(gadget::constants::SHA256_PAD_MARKER);

    // 2. Calculate zero padding
    // (input len + 1 (0x80) + 8 (length) + k (zeros)) % 64 == 0
    let current_len = padded.len();
    let zero_pad_len = (block_size - ((current_len + 8) % block_size)) % block_size;
    padded.extend(vec![0; zero_pad_len]);

    // 3. Append length in bits (Big Endian 64-bit)
    let bit_length = (total_len as u64) * 8;
    padded.extend(&bit_length.to_be_bytes());

    padded
}
