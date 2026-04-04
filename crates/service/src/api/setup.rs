use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey, prepare_verifying_key};
use circuit::constants::{BN254, BNP, CG, CircuitConfig};
use circuit::zkap::ZkapCircuit;
use rand::rngs::OsRng;

use crate::error::ApplicationError;

pub struct SetupOutput {
    pub pk: ProvingKey<BN254>,
    pub vk: VerifyingKey<BN254>,
    pub pvk: PreparedVerifyingKey<BN254>,
}

pub fn groth16_setup(params: &CircuitConfig) -> Result<SetupOutput, ApplicationError> {
    let mut rng = OsRng;
    let circuit = ZkapCircuit::<CG, BNP>::generate_mock_circuit(params);

    let (pk, vk) = Groth16::<BN254>::setup(circuit, &mut rng)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Groth16 setup failed: {}", e)))?;

    let pvk = prepare_verifying_key(&vk);

    Ok(SetupOutput { pk, vk, pvk })
}
