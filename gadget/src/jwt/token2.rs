use ark_serialize::CanonicalSerialize;

use crate::jwt::types::Claim;

#[derive(Clone, Debug, Default, CanonicalSerialize)]
pub struct Token {
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub claims: Vec<Claim>,
    pub sha_pad_payload_b64: Vec<u8>,
    pub bit_witness: Vec<bool>,
}

impl Token {
    pub fn empty(keys_len: usize, max_jwt_len: usize, max_payload_len: usize) -> Self {
        let claims = (0..keys_len).map(|_| Claim::empty()).collect::<Vec<_>>();
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        Token {
            pay_offset_b64: 0,
            pay_len_b64: 0,
            claims,
            sha_pad_payload_b64: vec![0u8; max_jwt_len],
            bit_witness: vec![false; (max_payload_b64_len) * 6],
        }
    }
}
