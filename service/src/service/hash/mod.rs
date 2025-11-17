use ark_crypto_primitives::crh::CRHScheme;
use gadget::hashes::poseidon::get_poseidon_params;

use crate::{error::error::ApplicationError, interface::hash::{HashRequestDto, HashResponseDto}, service::constants::{AppField, PoseidonHash}, utils::point::str_to_field};

pub fn poseidon_hash(dto: HashRequestDto) -> Result<HashResponseDto, ApplicationError> {
    let poseidon_params = get_poseidon_params::<AppField>();

    let field = dto.inputs.iter().map(|s| str_to_field::<AppField>(s)).collect::<Result<Vec<_>, _>>().map_err(|e| ApplicationError::InvalidFormat(format!("Failed to parse input string to field element: {}", e)))?;

    let result = PoseidonHash::evaluate(&poseidon_params, field).map_err(|e| ApplicationError::Other(format!("Poseidon hash evaluation failed: {}", e)))?;

    Ok(HashResponseDto { hash: result.to_string() })
}