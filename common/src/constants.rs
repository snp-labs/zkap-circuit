use ark_crypto_primitives::crh::poseidon::CRH;
use gadget::{
    bigint::constraints::BigNatCircuitParams,
    hashes::blake2s256::{Blake2s256, constraints::Blake2s256Gadget}, matrix::VandermondeMatrix,
};

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

const LAMBDA: usize = 2048; // 2048 bits
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat512TestParams;
impl BigNatCircuitParams for BigNat512TestParams {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

pub type CG = ark_ed_on_bn254::EdwardsProjective;
pub type F = <CG as ark_ec::CurveGroup>::BaseField;
pub type PoseidonHash = CRH<F>;
pub type Blake2 = Blake2s256;
pub type Blake2Gadget = Blake2s256Gadget;
pub type BigNatTestParams = BigNat512TestParams;
pub type BN254 = ark_bn254::Bn254;
pub type CV = ark_ed_on_bn254::constraints::EdwardsVar;
pub type BNP = BigNat512TestParams;

#[derive(Debug, Clone)]
pub struct AnchorConfig {
    pub matrix_rows: usize,
    pub matrix_cols: usize,
    pub max_aud_len: usize,
    pub max_iss_len: usize,
    pub max_sub_len: usize,
    pub pad_char: char,
    pub matrix: VandermondeMatrix<F>,
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
            matrix: VandermondeMatrix::new(N, K),
        }
    }
}
