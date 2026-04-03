pub mod poseidon;
pub mod types;

use circuit::constants::{F, ZkPasskeyConfig};
use gadget::matrix::VandermondeMatrix;

/// Anchor configuration derived from ZkPasskeyConfig.
/// Moved from common::constants to avoid common depending on gadget::matrix.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AnchorConfig {
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_sub_len: usize,
    pub pad_char: char,
    pub matrix: VandermondeMatrix<F>,
}

impl AnchorConfig {
    pub fn from_config<C: ZkPasskeyConfig>() -> Self {
        Self {
            matrix_rows: C::N,
            matrix_cols: C::K,
            max_aud_len: C::MAX_AUD_LEN,
            max_iss_len: C::MAX_ISS_LEN,
            max_sub_len: C::MAX_SUB_LEN,
            pad_char: C::PAD_CHAR,
            matrix: VandermondeMatrix::<F>::new(C::N, C::K),
        }
    }
}