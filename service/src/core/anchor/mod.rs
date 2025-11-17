use ark_ff::PrimeField;
use ark_std::rand::Rng;

use crate::core::anchor::error::AnchorServiceError;

pub mod poseidon;
pub mod dl;

pub mod error;


// 각 앵커 스킴의 구현에 필요한 타입들을 모아놓은 "설정" 트레잇
pub trait AnchorParams {
    type Field: PrimeField;
    type PublicKey;
    type Secret;
    type Anchor;
}

pub trait AnchorService<P: AnchorParams> {
    fn setup<R: Rng>(rng: &mut R, n: usize, k: usize, max_aud_len: Option<usize>, max_iss_len: Option<usize>, max_sub_len: usize) -> Result<P::PublicKey, AnchorServiceError>;

    fn anchor(keys: &P::PublicKey, secret: &P::Secret) -> Result<P::Anchor, AnchorServiceError>;

    fn derive_secret_indices(anchor_key: &P::PublicKey, anchor: &P::Anchor, known_secrets: &P::Secret) -> Result<Vec<usize>, AnchorServiceError>;
}