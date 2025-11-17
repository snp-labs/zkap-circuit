use std::{borrow::Borrow, marker::PhantomData};

use ark_ff::Field;
use sha2::{Digest, Sha256};

use crate::hashes::{CRHScheme, Parameter, TwoToOneCRHScheme, error::HashError};

pub struct SHA256<F: Field, P> {
    _field: PhantomData<F>,
    _params: PhantomData<P>,
}

impl<F, P> CRHScheme for SHA256<F, P>
where
    F: Field,
    P: Parameter<F>,
{
    type Input = [u8];
    type Output = Vec<u8>;

    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, HashError> {
        Ok(Sha256::digest(input.borrow()).to_vec())
    }
}

pub struct TwoToOneSHA256<F: Field> {
    _field: PhantomData<F>,
}

impl<F, P> TwoToOneCRHScheme for SHA256<F, P>
where
    F: Field,
    P: Parameter<F>,
{
    type Input = [u8];
    // This is always 32 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Vec<u8>;

    // Evaluates SHA256(left_input || right_input)
    fn evaluate<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        // Process the left input then the right input
        let mut h = Sha256::default();
        h.update(left_input);
        h.update(right_input);
        Ok(h.finalize().to_vec())
    }

    // Evaluates SHA256(left_input || right_input)
    fn compress<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError> {
        <Self as TwoToOneCRHScheme>::evaluate(left_input, right_input)
    }
}

#[cfg(test)]
mod test {

    use ark_bn254::Fr;
    use ark_serialize::CanonicalSerialize;

    use crate::hashes::{CRHScheme, TwoToOneCRHScheme, sha256::Sha256Bn254ParamProvider};

    use super::SHA256;

    #[test]
    fn test_sha256() {
        let mut left_input = vec![];
        let mut right_input = vec![];
        Fr::from(1111)
            .0
            .serialize_uncompressed(&mut left_input)
            .unwrap();
        Fr::from(1111)
            .0
            .serialize_uncompressed(&mut right_input)
            .unwrap();

        let crh_eval = <SHA256<Fr, Sha256Bn254ParamProvider> as CRHScheme>::evaluate(
            [left_input.as_slice(), right_input.as_slice()].concat(),
        )
        .unwrap();

        let two_to_one_eval =
            <SHA256<Fr, Sha256Bn254ParamProvider> as TwoToOneCRHScheme>::evaluate(
                left_input.clone(),
                right_input.clone(),
            )
            .unwrap();
        assert_eq!(crh_eval, two_to_one_eval);

        let two_to_on_compress =
            <SHA256<Fr, Sha256Bn254ParamProvider> as TwoToOneCRHScheme>::compress(
                left_input.clone(),
                right_input.clone(),
            )
            .unwrap();
        assert_eq!(two_to_on_compress, two_to_one_eval);
    }
}
