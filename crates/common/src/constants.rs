use std::fmt::Debug;

use ark_crypto_primitives::crh::poseidon::CRH;
use gadget::bigint::constraints::BigNatCircuitParams;

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
pub type BigNatTestParams = BigNat2048Params;
pub type BN254 = ark_bn254::Bn254;
pub type CV = ark_ed_on_bn254::constraints::EdwardsVar;
pub type BNP = BigNat2048Params;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkapConfig;

include!(concat!(env!("OUT_DIR"), "/generated_config.rs"));

// AnchorConfig moved to zkpasskey-service crate (depends on gadget::matrix::VandermondeMatrix)
