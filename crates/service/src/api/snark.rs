use ark_bn254::Bn254;
use ark_groth16::Proof;
use circuit::constants::{F, ZkPasskeyConfig};

use crate::{RawProofRequest, app, error::ApplicationError};

#[allow(clippy::type_complexity)]
pub fn generate_proof<Config: ZkPasskeyConfig>(
    req: RawProofRequest,
) -> Result<(Vec<Proof<Bn254>>, Vec<Vec<F>>), ApplicationError> {
    app::snark::zkap::generate_proof::<Config>(req)
}
