use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use circuit::constants::{F, CircuitConfig};
use crate::app::anchor::AnchorConfig;
use gadget::{
    anchor::poseidon::PoseidonAnchorPublicKey,
    base64::{Base64Table, get_base64_table},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
};

#[derive(Clone)]
pub(crate) struct CircuitContext {
    pub poseidon_anchor_key: PoseidonAnchorPublicKey<F>,
    pub anchor_cfg: AnchorConfig,
    pub poseidon_params: PoseidonConfig<F>,
    pub vandermonde_matrix: VandermondeMatrix<F>,
    pub base64_table: Base64Table,
}

impl CircuitContext {
    pub fn new(params: &CircuitConfig) -> Self {
        let poseidon_anchor_key = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };

        Self {
            poseidon_anchor_key,
            anchor_cfg: AnchorConfig::from_params(params),
            poseidon_params: get_poseidon_params::<F>(),
            vandermonde_matrix: VandermondeMatrix::<F>::new(params.n as usize, params.k as usize),
            base64_table: get_base64_table(),
        }
    }
}
