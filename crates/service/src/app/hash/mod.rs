use ark_crypto_primitives::crh::CRHScheme;
use ark_utils::hex_decimal_to_field;
use circuit::constants::{F, PoseidonHash};
use gadget::hashes::poseidon::get_poseidon_params;

use crate::{
    error::ApplicationError,
};

pub fn poseidon_hash(messages: Vec<String>) -> Result<F, ApplicationError> {
    let poseidon_params = get_poseidon_params::<F>();

    let field = messages
        .iter()
        .map(|s| hex_decimal_to_field::<F>(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            ApplicationError::InvalidFormat(format!(
                "Failed to parse input string to field element: {}",
                e
            ))
        })?;

    let result = PoseidonHash::evaluate(&poseidon_params, field)
        .map_err(|e| ApplicationError::Other(format!("Poseidon hash evaluation failed: {}", e)))?;

    Ok(result)
}
