pub mod constraints;

#[derive(Clone)]
pub struct TokenPayloadB64 {
    pub pay_offset_b64: usize,
    pub pay_len_b64: usize,
    pub sha_pad_payload_b64: Vec<u8>,
    pub bit_witness: Vec<bool>,
}

impl TokenPayloadB64 {
    pub fn empty(max_jwt_len: usize, max_payload_len: usize) -> Self {
        let max_payload_b64_len = ((max_payload_len + 2) / 3) * 4;

        TokenPayloadB64 {
            pay_offset_b64: 0,
            pay_len_b64: 0,
            sha_pad_payload_b64: vec![0u8; max_jwt_len],
            bit_witness: vec![false; (max_payload_b64_len + 4) * 6],
        }
    }
}
