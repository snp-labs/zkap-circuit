use std::{
    marker::PhantomData,
    ops::{Add, AddAssign},
};

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use crate::hashes::Parameter;

use super::RoundConstantsAccessor;

#[derive(Debug, Clone)]
pub struct MiMCGadget<F: PrimeField, P: Parameter<F>> {
    _field: PhantomData<F>,
    _params: PhantomData<P>,
}

impl<F, P> MiMCGadget<F, P>
where
    F: PrimeField,
    P: Parameter<F>,
    P::ParameterStruct: RoundConstantsAccessor<F>,
{
    fn round(xl: FpVar<F>, xr: FpVar<F>, rc: F) -> FpVar<F> {
        let mut xored = xl + xr;
        xored.add_assign(rc);

        let mut tmp = xored.clone();
        for _ in 0..2 {
            tmp *= tmp.clone();
            xored *= tmp.clone();
        }

        xored
    }

    pub fn encrypt(xl: FpVar<F>, xr: FpVar<F>) -> FpVar<F> {
        Self::_encrypt(xl, xr)
    }

    fn _encrypt(xl: FpVar<F>, xr: FpVar<F>) -> FpVar<F> {
        let params_struct = P::params();
        let param = params_struct.round_constants();
        let mut res = Self::round(xl.clone(), xr.clone(), F::zero());

        for i in 1..param.len() {
            res = Self::round(res.clone(), xr.clone(), param[i]);
        }

        res.add(xr.clone())
    }
}

pub struct TwoToOneMiMCGadget<F: PrimeField, P: Parameter<F>> {
    _field: PhantomData<F>,
    _params: PhantomData<P>,
}
