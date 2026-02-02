use std::marker::PhantomData;

use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use common::constants::{AnchorConfig, F, ZkPasskeyConfig};
use gadget::{
    anchor::poseidon::PoseidonAnchorPublicKey,
    base64::{Base64Table, get_base64_table},
    hashes::poseidon::get_poseidon_params,
    matrix::VandermondeMatrix,
};

#[derive(Clone)]
pub(crate) struct CircuitContext<Config: ZkPasskeyConfig> {
    pub poseidon_anchor_key: PoseidonAnchorPublicKey<F>,
    pub anchor_cfg: AnchorConfig,
    pub poseidon_params: PoseidonConfig<F>,
    pub vandermonde_matrix: VandermondeMatrix<F>,
    pub base64_table: Base64Table,
    _phantom: std::marker::PhantomData<Config>,
}

impl<Config: ZkPasskeyConfig> CircuitContext<Config> {
    pub fn new() -> Self {
        let poseidon_anchor_key = PoseidonAnchorPublicKey {
            params: get_poseidon_params::<F>(),
        };

        Self {
            poseidon_anchor_key,
            anchor_cfg: AnchorConfig::from_config::<Config>(),
            poseidon_params: get_poseidon_params::<F>(),
            vandermonde_matrix: VandermondeMatrix::<F>::new(Config::N, Config::K),
            base64_table: get_base64_table(),
            _phantom: PhantomData,
        }
    }
}
