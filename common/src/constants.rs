use std::fmt::Debug;

use ark_crypto_primitives::crh::poseidon::CRH;
use gadget::{
    bigint::constraints::BigNatCircuitParams,
    hashes::blake2s256::{Blake2s256, constraints::Blake2s256Gadget},
    matrix::VandermondeMatrix,
};

pub trait ZkPasskeyConfig: Clone + Debug + Send + Sync {
    // === JWT Constraints ===
    const MAX_JWT_B64_LEN: usize;
    const MAX_PAYLOAD_B64_LEN: usize;
    const MAX_AUD_LEN: usize;
    const MAX_EXP_LEN: usize;
    const MAX_ISS_LEN: usize;
    const MAX_NONCE_LEN: usize;
    const MAX_SUB_LEN: usize;

    // === Logic Constraints ===
    const N: usize;
    const K: usize;
    const TREE_HEIGHT: usize;
    const CLAIMS: &'static [&'static str];
    const NUM_AUDIENCE_LIMIT: usize;
    const FORBIDDEN_STRING: &'static str;
    const PAD_CHAR: char;

    type BigNatParams: BigNatCircuitParams;
}

const LAMBDA: usize = 2048; // 2048 bits
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat2048Params;
impl BigNatCircuitParams for BigNat2048Params {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

pub type CG = ark_ed_on_bn254::EdwardsProjective;
pub type F = <CG as ark_ec::CurveGroup>::BaseField;
pub type PoseidonHash = CRH<F>;
pub type Blake2 = Blake2s256;
pub type Blake2Gadget = Blake2s256Gadget;
pub type BigNatTestParams = BigNat2048Params;
pub type BN254 = ark_bn254::Bn254;
pub type CV = ark_ed_on_bn254::constraints::EdwardsVar;
pub type BNP = BigNat2048Params;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkapConfig;

include!(concat!(env!("OUT_DIR"), "/generated_config.rs"));

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
