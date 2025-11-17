use std::marker::PhantomData;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use gadget::{
    anchor::{
        AnchorScheme,
        error::AnchorError,
        poseidon::{PoseidonAnchor, PoseidonAnchorScheme, PoseidonAnchorSecret},
    },
    matrix::Matrix,
};

use crate::{
    core::anchor::{AnchorParams, AnchorService},
    interface::anchor::PoseidonAnchorKeyExtension, utils::point::{FromStrings, str_to_field},
};

pub struct PoseidonAnchorParams<F: PrimeField + Absorb>(PhantomData<F>);

pub struct PoseidonAnchorService;

impl<F: PrimeField + Absorb> AnchorService<PoseidonAnchorParams<F>> for PoseidonAnchorService {
    fn setup<R: Rng>(
        rng: &mut R,
        n: usize,
        k: usize,
        max_aud_len: Option<usize>,
        max_iss_len: Option<usize>,
        max_sub_len: usize,
    ) -> Result<
        <PoseidonAnchorParams<F> as AnchorParams>::PublicKey,
        super::error::AnchorServiceError,
    > {
        let anchor_key = PoseidonAnchorScheme::setup(rng, n)?;
        Ok(PoseidonAnchorKeyExtension {
            anchor_key,
            n,
            k,
            max_aud_len,
            max_iss_len,
            max_sub_len,
        })
    }

    fn anchor(
        keys: &<PoseidonAnchorParams<F> as AnchorParams>::PublicKey,
        secret: &<PoseidonAnchorParams<F> as AnchorParams>::Secret,
    ) -> Result<<PoseidonAnchorParams<F> as AnchorParams>::Anchor, super::error::AnchorServiceError>
    {
        let matrix = Matrix::<F>::new(keys.n, keys.k)?;
        let anchor = PoseidonAnchorScheme::<F>::generate_anchor(&keys.anchor_key, secret, &matrix)?;
        Ok(anchor)
    }

    fn derive_secret_indices(
        anchor_key: &<PoseidonAnchorParams<F> as AnchorParams>::PublicKey,
        anchor: &<PoseidonAnchorParams<F> as AnchorParams>::Anchor,
        known_secrets: &<PoseidonAnchorParams<F> as AnchorParams>::Secret,
    ) -> Result<Vec<usize>, super::error::AnchorServiceError> {
        let matrix = Matrix::<F>::new(anchor_key.n, anchor_key.k)?;
        let indices = PoseidonAnchorScheme::get_indices(
            &anchor_key.anchor_key,
            anchor,
            known_secrets,
            &matrix,
        )?;
        Ok(indices)
    }
}

impl<F: PrimeField + Absorb> AnchorParams for PoseidonAnchorParams<F> {
    type Anchor = PoseidonAnchor<F>;
    type Field = F;
    type PublicKey = PoseidonAnchorKeyExtension<F>;
    type Secret = PoseidonAnchorSecret<F>;
}
impl<F> FromStrings for PoseidonAnchor<F>
where
    F: PrimeField,
{
    type Err = AnchorError;

    fn from_strings(strings: &[String]) -> Result<Self, Self::Err> {
        let anchor = strings
            .iter()
            .map(|s| {
                str_to_field::<F>(s).map_err(|e| {
                    AnchorError::InvalidParameters(format!(
                        "Failed to parse anchor element from `{}`: {:?}",
                        s, e
                    ))
                })
            })
            .collect::<Result<Vec<F>, AnchorError>>()?;

        Ok(PoseidonAnchor(anchor))
    }
}
