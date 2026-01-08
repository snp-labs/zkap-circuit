use common::constants::{F, ZkPasskeyConfig};
use gadget::anchor::poseidon::PoseidonAnchor;

use crate::{
    app,
    types::Secret,
    error::ApplicationError,
};

pub fn create_poseidon_anchor<Config: ZkPasskeyConfig>(
    secrets: Vec<Secret>,
) -> Result<PoseidonAnchor<F>, ApplicationError> {
    app::anchor::poseidon::create_poseidon_anchor::<Config>(secrets)
}