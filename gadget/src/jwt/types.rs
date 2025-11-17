use std::collections::BTreeMap;

use ark_serialize::CanonicalSerialize;

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct ClaimIndices {
    pub offset: usize,
    pub len: usize,
    pub colon_idx: usize,
    pub value_idx: usize,
    pub value_len: usize,
}

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct Claim {
    pub key: String,
    pub value: String,
    pub indices: ClaimIndices,
}

impl Claim {
    pub fn empty() -> Self {
        Claim {
            key: String::new(),
            value: String::new(),
            indices: ClaimIndices::default(),
        }
    }
}

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct JwtMetadata {
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub claims: BTreeMap<String, ClaimIndices>,
    pub overlap: Vec<u8>,
    pub overlap_len: usize,
    pub state: Vec<u32>,
    pub post_b64: Vec<u8>,
    pub num_sha256_blocks: usize,
}

impl JwtMetadata {
    pub fn empty(keys: Vec<&str>, max_payload_len: usize, max_overlap_len: usize) -> Self {
        let mut claims = BTreeMap::new();
        for key in keys {
            claims.insert(key.to_string(), ClaimIndices::default());
        }

        JwtMetadata {
            pay_offset_b64: 0,
            pay_len_b64: 0,
            claims,
            overlap: vec![0u8; max_overlap_len],
            overlap_len: 0,
            state: vec![0u32; 8], // SHA-256 state has 8 words
            post_b64: vec![0u8; max_payload_len],
            num_sha256_blocks: 1,
        }
    }
}
