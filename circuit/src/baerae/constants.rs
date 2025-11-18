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

pub const NUMBER_OF_AUDIENCE: usize = 5;
pub const FORBIDDEN_STRING: &str = "forbidden";