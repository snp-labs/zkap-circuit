use ark_bn254::Bn254;
#[allow(unused_imports)]
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof};
use circuit::constants::{F, CircuitConfig};

use crate::{RawProofRequest, app, error::ApplicationError};

#[allow(clippy::type_complexity)]
pub fn prove(
    params: &CircuitConfig,
    req: RawProofRequest,
) -> Result<(Vec<Proof<Bn254>>, Vec<Vec<F>>), ApplicationError> {
    app::snark::zkap::prove(params, req)
}

pub fn verify(
    pvk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[F],
) -> Result<bool, ApplicationError> {
    Groth16::<Bn254>::verify_proof(pvk, proof, public_inputs)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Proof verification failed: {}", e)))
}
