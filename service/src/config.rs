use gadget::matrix::VandermondeMatrix;

use crate::service::constants::AppField;

pub const MAX_JWT_B64_LEN: usize = 1024;
pub const MAX_PAYLOAD_B64_LEN: usize = 640;
pub const MAX_AUD_LEN: usize = 155;
pub const MAX_EXP_LEN: usize = 10;
pub const MAX_ISS_LEN: usize = 155;
pub const MAX_NONCE_LEN: usize = 155;
pub const MAX_SUB_LEN: usize = 155;
pub const N: usize = 6;
pub const K: usize = 3;
pub const TREE_HEIGHT: usize = 4;
pub const CLAIMS: [&str; 5] = ["aud", "exp", "iss", "nonce", "sub"];
pub const RSA_BITS: usize = 2048;
pub const PAD_CHAR: char = '\0';

pub const NUMBER_OF_AUDIENCE: usize = 5;
pub const FORBIDDEN_STRING: &str = "forbidden";

#[derive(Debug, Clone)]
pub struct AnchorConfig {
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_sub_len: usize,
    pub pad_char: char,
    pub matrix: VandermondeMatrix<AppField>,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        AnchorConfig {
            matrix_rows: N,
            matrix_cols: K,
            max_aud_len: MAX_AUD_LEN,
            max_iss_len: MAX_ISS_LEN,
            max_sub_len: MAX_SUB_LEN,
            pad_char: PAD_CHAR,
            matrix: VandermondeMatrix::<AppField>::new(N, K),
        }
    }
}
