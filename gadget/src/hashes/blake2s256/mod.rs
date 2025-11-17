use ark_crypto_primitives::Error;
use ark_crypto_primitives::crh::CRHScheme;
use blake2;
use blake2::Digest;
use rand::Rng;
use std::borrow::Borrow;

pub mod constraints;

#[derive(Clone)]
pub struct Blake2s256;

impl CRHScheme for Blake2s256 {
    type Input = [u8];
    type Output = Vec<u8>;
    type Parameters = ();

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let mut h = blake2::Blake2s256::new();
        h.update(input.borrow());
        Ok(h.finalize().to_vec())
    }
}
