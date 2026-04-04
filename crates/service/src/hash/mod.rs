use ark_crypto_primitives::crh::CRHScheme;
use ark_utils::hex_decimal_to_field;
use circuit::constants::{F, PoseidonHash, CircuitConfig, PAD_CHAR};
use gadget::{
    base64::decode_any_base64,
    hashes::poseidon::get_poseidon_params,
    signature::rsa::PublicKey,
    utils::str_to_limbs,
};

use crate::error::ApplicationError;

pub fn generate_hash(messages: Vec<String>) -> Result<F, ApplicationError> {
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

pub fn generate_aud_hash(
    params: &CircuitConfig,
    aud_list: Vec<String>,
) -> Result<(Vec<F>, F), ApplicationError> {
    let poseidon_params = get_poseidon_params::<F>();

    let forbidden_str = std::str::from_utf8(&params.forbidden_string)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Invalid forbidden_string: {}", e)))?;

    let mut aud_vec = aud_list;
    let num_audience_limit = params.num_audience_limit as usize;

    if aud_vec.len() > num_audience_limit {
        return Err(ApplicationError::InvalidFormat(format!(
            "Input audience count ({}) exceeds the limit ({}).",
            aud_vec.len(),
            num_audience_limit,
        )));
    }

    while aud_vec.len() < num_audience_limit {
        aud_vec.push(forbidden_str.to_string());
    }

    let aud_fields: Vec<F> = aud_vec
        .iter()
        .map(|a| {
            let limbs = str_to_limbs(a, params.max_aud_len as usize, PAD_CHAR as u8);
            PoseidonHash::evaluate(&poseidon_params, limbs)
                .map_err(|e| ApplicationError::Other(format!("Error processing aud '{}': {}", a, e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let h_aud_list = PoseidonHash::evaluate(&poseidon_params, &*aud_fields)
        .map_err(|e| ApplicationError::Other(format!("Error computing h_aud_lists: {}", e)))?;

    Ok((aud_fields, h_aud_list))
}

pub fn generate_leaf_hash(
    params: &CircuitConfig,
    iss: &str,
    pk_b64: &str,
) -> Result<F, ApplicationError> {
    use circuit::constants::BNP;
    use circuit::constants::CG;

    let poseidon_params = get_poseidon_params::<F>();

    let iss_limbs = str_to_limbs(iss, params.max_iss_len as usize, PAD_CHAR as u8);

    let n_decoded = decode_any_base64(pk_b64)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Error decoding pk: {}", e)))?;
    let e_decoded = decode_any_base64(gadget::constants::RSA_DEFAULT_EXPONENT_B64)
        .map_err(|e| ApplicationError::InvalidFormat(format!("Error decoding exponent: {}", e)))?;

    let pk_obj = PublicKey {
        n: n_decoded,
        e: e_decoded,
    };

    let n_limbs = pk_obj.to_limbs::<BNP, CG>().0;

    let mut leaf_inputs = Vec::new();
    leaf_inputs.extend_from_slice(&iss_limbs);
    leaf_inputs.extend_from_slice(&n_limbs);

    let leaf = PoseidonHash::evaluate(&poseidon_params, &*leaf_inputs)
        .map_err(|e| ApplicationError::Other(format!("Error computing leaf: {}", e)))?;

    Ok(leaf)
}
