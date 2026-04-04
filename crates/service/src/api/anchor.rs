use circuit::constants::{F, CircuitConfig};
use gadget::anchor::poseidon::PoseidonAnchor;

use crate::{Secret, app, error::ApplicationError};

pub fn generate_anchor(
    params: &CircuitConfig,
    secrets: Vec<Secret>,
) -> Result<PoseidonAnchor<F>, ApplicationError> {
    app::anchor::poseidon::generate_anchor(params, secrets)
}
