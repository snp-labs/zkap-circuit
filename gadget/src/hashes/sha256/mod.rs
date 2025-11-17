use super::Parameter;
use ark_bn254::Fr as Bn254Fr;

pub mod constraints;
pub mod digest;
pub mod gadget;
pub mod native;
pub mod parameters;
pub mod tests;
pub mod traits;
pub mod utils;

pub use digest::DigestVar;
pub use gadget::SHA256Gadget;
pub use native::{SHA256, TwoToOneSHA256};
pub use parameters::{H, K, Sha2BlockAccessor, Sha256Parameters, State, StateAccessor};

#[derive(Clone, Debug)]
pub struct Sha256Bn254ParamProvider;

impl Parameter<Bn254Fr> for Sha256Bn254ParamProvider {
    type ParameterStruct = ();
    fn params() -> Self::ParameterStruct {
        ()
    }
}
