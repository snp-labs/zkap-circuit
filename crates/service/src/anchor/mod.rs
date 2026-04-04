pub mod poseidon;
pub mod types;

use circuit::constants::{F, CircuitConfig, PAD_CHAR};
use gadget::matrix::VandermondeMatrix;

/// Anchor configuration derived from [`CircuitConfig`].
///
/// Packages all parameters required by the Poseidon anchor scheme — matrix dimensions,
/// field-length limits for claim padding, and the pre-built [`VandermondeMatrix`] — into a
/// single struct.  Construct via [`AnchorConfig::from_params`].
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
    pub fn from_params(params: &CircuitConfig) -> Self {
        Self {
            matrix_rows: params.n as usize,
            matrix_cols: params.k as usize,
            max_aud_len: params.max_aud_len as usize,
            max_iss_len: params.max_iss_len as usize,
            max_sub_len: params.max_sub_len as usize,
            pad_char: PAD_CHAR,
            matrix: VandermondeMatrix::<F>::new(params.n as usize, params.k as usize),
        }
    }
}
