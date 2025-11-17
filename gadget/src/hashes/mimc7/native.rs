use std::{borrow::Borrow, marker::PhantomData};

use ark_ff::Field;

use crate::hashes::{CRHScheme, Parameter, TwoToOneCRHScheme, error::HashError};

use super::parameters::RoundConstantsAccessor;

#[derive(Debug, Clone)]
pub struct MiMC<F: Field, P: Parameter<F>> {
    _field: PhantomData<F>,
    _params: PhantomData<P>,
}

impl<F: Field, P: Parameter<F>> MiMC<F, P>
where
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    fn round(xl: F, xr: F, rc: F) -> F {
        let mut xored = xl.add(xr).add(rc);
        let mut tmp = xored.clone();
        for _ in 0..2 {
            tmp = tmp.mul(tmp);
            xored = xored.mul(tmp);
        }

        xored
    }

    fn encrypt(xl: F, xr: F) -> F {
        let params_struct = P::params();
        let params = params_struct.round_constants();
        let mut result = Self::round(xl, xr, F::zero());

        for i in 1..params.len() {
            result = Self::round(result.clone(), xr.clone(), params[i]);
        }

        result.add(xr.clone())
    }
}

impl<F, P> CRHScheme for MiMC<F, P>
where
    F: Field,
    P: Parameter<F>,
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    type Input = [F];
    type Output = F;

    fn evaluate<T: Borrow<Self::Input>>(input: T) -> Result<Self::Output, HashError> {
        let input = input.borrow();
        let mut output: Self::Output;
        if input.len() == 1 {
            let xl = input[0].clone();
            let xr = input[0].clone();
            output = Self::encrypt(xl, xr).add(input[0]).add(input[0]);
        } else {
            output = input[0].clone();
            for i in 1..input.len() {
                let xl = output.clone();
                let xr = input[i].clone();

                output = Self::encrypt(xl, xr);
                output = output.add(xl).add(input[i]);
            }
        }

        Ok(output)
    }
}

pub struct TwoToOneMiMC<F: Field, P: Parameter<F>> {
    _field: PhantomData<F>,
    _params: PhantomData<P>,
}

impl<F: Field, P: Parameter<F>> TwoToOneMiMC<F, P>
where
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    fn encrypt(xl: F, xr: F) -> F {
        MiMC::<F, P>::encrypt(xl, xr)
    }
}

impl<F, P> TwoToOneCRHScheme for TwoToOneMiMC<F, P>
where
    F: Field,
    P: Parameter<F>,
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    type Input = F;
    type Output = F;

    fn evaluate<T: Borrow<Self::Input>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        let xl = left_input.clone();
        let xr = right_input.clone();

        let output = Self::encrypt(xl, xr).add(left_input).add(right_input);

        Ok(output)
    }

    fn compress<T: Borrow<Self::Output>>(
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, HashError> {
        // TODO sponge input
        <Self as TwoToOneCRHScheme>::evaluate(left_input.borrow(), right_input.borrow())
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;

    use crate::hashes::{
        CRHScheme, TwoToOneCRHScheme,
        mimc7::{
            MimcBn254ParamProvider,
            native::{MiMC, TwoToOneMiMC},
        },
    };

    #[test]
    fn test_mimc() {
        let xl = Fr::from(111111);
        let xr = Fr::from(111111);

        let two_to_one_eval = TwoToOneMiMC::<Fr, MimcBn254ParamProvider>::evaluate(xl, xr).unwrap();

        let eval = MiMC::<Fr, MimcBn254ParamProvider>::evaluate([xl, xr].to_vec()).unwrap();

        assert_eq!(eval, two_to_one_eval);

        let two_to_one_compress =
            TwoToOneMiMC::<Fr, MimcBn254ParamProvider>::compress(xl, xr).unwrap();
        assert_eq!(two_to_one_eval, two_to_one_compress);
    }
}
