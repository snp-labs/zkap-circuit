use ark_bn254::Fr as Bn254Fr;
use std::fmt::Debug;

use ark_ff::Field;

use super::Parameter;

pub mod gadget;
pub mod native;
pub mod parameters;
pub mod traits;

pub use gadget::*;
pub use native::*;
pub use parameters::*;

#[derive(Debug, Default, Clone)]
pub struct MimcBn254ParamProvider;

impl Parameter<Bn254Fr> for MimcBn254ParamProvider {
    type ParameterStruct = MimcParameters<Bn254Fr>;

    fn params() -> Self::ParameterStruct {
        MimcParameters {
            round_constants: parameters::get_bn256_round_constants(),
        }
    }
}

pub trait Config: Clone {
    type Field: Field;
    fn round_constants() -> Vec<Self::Field>;
}
