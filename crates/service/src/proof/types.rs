use crate::anchor::AnchorConfig;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use circuit::constants::{CircuitConfig, F};
use gadget::{
    anchor::poseidon::PoseidonAnchorPublicKey,
    base64::{Base64Table, get_base64_table},
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
            params: crate::poseidon_params().clone(),
        };

        Self {
            poseidon_anchor_key,
            anchor_cfg: AnchorConfig::from_params(params),
            poseidon_params: crate::poseidon_params().clone(),
            vandermonde_matrix: VandermondeMatrix::<F>::new(params.n as usize, params.k as usize),
            base64_table: get_base64_table(),
        }
    }
}

/// Computed context for anchor verification
#[derive(Clone)]
pub struct AnchorContext {
    /// Selector vector (marks the currently selected JWT token positions)
    pub selector: Vec<u8>,

    /// Vector a for <a, anchor> * random = <b, h_known> * random
    pub a: Vec<F>,

    /// H(a, random) value
    pub h_a: F,

    /// <a, anchor> * random - LHS value
    pub lhs: F,

    /// Partial RHS values for each proof
    pub partial_rhs_list: Vec<F>,

    /// Selected indices (i where selector[i] == 1)
    pub current_idx_list: Vec<usize>,
}

impl AnchorContext {
    /// Creates a new AnchorContext
    pub fn new(
        selector: Vec<u8>,
        a: Vec<F>,
        h_a: F,
        lhs: F,
        partial_rhs_list: Vec<F>,
        current_idx_list: Vec<usize>,
    ) -> Self {
        Self {
            selector,
            a,
            h_a,
            lhs,
            partial_rhs_list,
            current_idx_list,
        }
    }

    /// Partial RHS value for the i-th proof
    pub fn partial_rhs_for(&self, proof_index: usize) -> F {
        self.partial_rhs_list[proof_index]
    }

    /// Current index for the i-th proof
    pub fn current_idx_for(&self, proof_index: usize) -> usize {
        self.current_idx_list[proof_index]
    }
}

/// Computed context for audience verification
#[derive(Clone)]
pub struct AudienceContext {
    /// Padded audience list (length Config::NUM_AUDIENCE_LIMIT)
    pub padded_list: Vec<F>,

    /// H(padded_aud_list)
    pub h_aud_list: F,
}

impl AudienceContext {
    /// Creates a new AudienceContext
    pub fn new(padded_list: Vec<F>, h_aud_list: F) -> Self {
        Self {
            padded_list,
            h_aud_list,
        }
    }
}
