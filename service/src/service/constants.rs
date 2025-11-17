use ark_crypto_primitives::crh::poseidon::CRH;
use gadget::{bigint::constraints::BigNatCircuitParams, hashes::blake2s256::{constraints::Blake2s256Gadget, Blake2s256}};

const LAMBDA: usize = 2048; // 2048 bits
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BigNat512TestParams;
impl BigNatCircuitParams for BigNat512TestParams {
    const LIMB_WIDTH: usize = 64;
    const N_LIMBS: usize = LAMBDA / 64;
}

pub type AppCurve = ark_ed_on_bn254::EdwardsProjective;
pub type AppField = <AppCurve as ark_ec::CurveGroup>::BaseField;
pub type PoseidonHash = CRH<AppField>;
pub type Blake2 = Blake2s256;
pub type Blake2Gadget = Blake2s256Gadget;
pub type BigNatTestParams = BigNat512TestParams;
pub type BN254 = ark_bn254::Bn254;
pub type CV = ark_ed_on_bn254::constraints::EdwardsVar;
pub type BNP = BigNat512TestParams;


// pub type Affine = ark_ed_on_bn254::EdwardsAffine;
// pub type C = ark_ed_on_bn254::EdwardsProjective;
// pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
// pub type Sha256HP = Sha256Bn254ParamProvider;
// pub type MiMCHP = MimcBn254ParamProvider;
// pub type CRHG = MiMCGadget<ConstraintF<C>, MiMCHP>;
