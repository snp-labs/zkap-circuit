pub mod anchor;
pub mod utils;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use gadget::{
    anchor::{AnchorScheme, poseidon::{
        PoseidonAnchor, PoseidonAnchorPublicKey, PoseidonAnchorScheme, PoseidonAnchorSecret,
    }},
    matrix::VandermondeMatrix,
};

//TODO: DL Anchor와 함께 Trait으로 만들기?
pub struct PoseidonAnchorService<F: PrimeField + Absorb> {
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField + Absorb> PoseidonAnchorService<F> {
    pub fn setup() -> PoseidonAnchorPublicKey<F> {
        let anchor_key = PoseidonAnchorPublicKey {
            params: gadget::hashes::poseidon::get_poseidon_params(),
        };
        anchor_key
    }

    pub fn generate_anchor(
        pk: &PoseidonAnchorPublicKey<F>,
        secrets: &PoseidonAnchorSecret<F>,
        matrix: &VandermondeMatrix<F>,
    ) -> Result<PoseidonAnchor<F>, gadget::anchor::error::AnchorError> {
        PoseidonAnchorScheme::generate_anchor(pk, secrets, matrix)
    }
}
