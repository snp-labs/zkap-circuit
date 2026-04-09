use ark_crypto_primitives::crh::CRHScheme;
use ark_utils::hex_decimal_to_field;
use circuit::constants::{CircuitConfig, F, PAD_CHAR, PoseidonHash};
use gadget::{base64::decode_any_base64, signature::rsa::PublicKey, utils::str_to_limbs};

use crate::dto::AudHashResult;
use crate::error::ApplicationError;

/// Compute a Poseidon hash of one or more field-element strings.
///
/// Each string in `messages` is parsed as a hex or decimal field element, then the collection
/// is hashed with the cached Poseidon parameters. Returns the resulting field element as a
/// decimal string.
pub fn generate_hash(messages: Vec<String>) -> Result<String, ApplicationError> {
    let poseidon_params = crate::poseidon_params();

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

    let result = PoseidonHash::evaluate(poseidon_params, field)
        .map_err(|e| ApplicationError::Other(format!("Poseidon hash evaluation failed: {}", e)))?;

    Ok(crate::field_to_hex(result))
}

/// Compute per-audience Poseidon hashes and a combined audience-list hash.
///
/// `aud_list` is padded with the circuit's `forbidden_string` up to `params.num_audience_limit`.
/// Each padded audience string is converted to fixed-length limbs and individually hashed;
/// the resulting field elements are then hashed together to produce `h_aud_list`.
/// Returns `(aud_fields, h_aud_list)`.  Errors if `aud_list` exceeds the limit.
pub fn generate_aud_hash(
    params: &CircuitConfig,
    aud_list: Vec<String>,
) -> Result<AudHashResult, ApplicationError> {
    let poseidon_params = crate::poseidon_params();

    let forbidden_str = crate::forbidden_str(params)?;

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
            PoseidonHash::evaluate(poseidon_params, limbs).map_err(|e| {
                ApplicationError::Other(format!("Error processing aud '{}': {}", a, e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let h_aud_list = PoseidonHash::evaluate(poseidon_params, &*aud_fields)
        .map_err(|e| ApplicationError::Other(format!("Error computing h_aud_lists: {}", e)))?;

    Ok(AudHashResult {
        individual: aud_fields.iter().map(|f| crate::field_to_hex(*f)).collect(),
        combined: crate::field_to_hex(h_aud_list),
    })
}

/// Compute the Merkle leaf hash for an issuer + RSA public-key pair.
///
/// Pads `iss` to `params.max_iss_len` bytes, decodes the Base64 modulus `pk_b64`, converts
/// it to BigNat limbs, then hashes `[iss_limbs || pk_n_limbs]` with Poseidon.
/// Returns the leaf field element used when building or verifying the Merkle tree.
pub fn generate_leaf_hash(
    params: &CircuitConfig,
    iss: &str,
    pk_b64: &str,
) -> Result<String, ApplicationError> {
    use circuit::constants::BNP;
    use circuit::constants::CG;

    let poseidon_params = crate::poseidon_params();

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

    let leaf = PoseidonHash::evaluate(poseidon_params, &*leaf_inputs)
        .map_err(|e| ApplicationError::Other(format!("Error computing leaf: {}", e)))?;

    Ok(crate::field_to_hex(leaf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::constants::RawCircuitConfig;

    fn test_config() -> CircuitConfig {
        let raw = RawCircuitConfig {
            max_jwt_b64_len: 1024,
            max_payload_b64_len: 640,
            max_aud_len: 155,
            max_exp_len: 20,
            max_iss_len: 93,
            max_nonce_len: 93,
            max_sub_len: 93,
            n: 6,
            k: 3,
            tree_height: 4,
            num_audience_limit: 5,
            claims: vec![
                "aud".into(),
                "exp".into(),
                "iss".into(),
                "nonce".into(),
                "sub".into(),
            ],
            forbidden_string: "forbidden".into(),
        };
        raw.into()
    }

    #[test]
    fn test_generate_hash_single_element() {
        let result = generate_hash(vec!["1".to_string()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_hash_multiple_elements() {
        let result = generate_hash(vec!["1".to_string(), "2".to_string(), "3".to_string()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_hash_deterministic() {
        let r1 = generate_hash(vec!["42".to_string()]).unwrap();
        let r2 = generate_hash(vec!["42".to_string()]).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_generate_hash_different_inputs_different_outputs() {
        let r1 = generate_hash(vec!["1".to_string()]).unwrap();
        let r2 = generate_hash(vec!["2".to_string()]).unwrap();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_generate_hash_invalid_input() {
        let result = generate_hash(vec!["not_a_number".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_aud_hash_within_limit() {
        let params = test_config();
        let aud_list = vec!["aud1".to_string(), "aud2".to_string()];
        let result = generate_aud_hash(&params, aud_list);
        assert!(result.is_ok());
        let r = result.unwrap();
        // Should be padded to num_audience_limit (5)
        assert_eq!(r.individual.len(), 5);
        assert!(r.combined.starts_with("0x"));
    }

    #[test]
    fn test_generate_aud_hash_exact_limit() {
        let params = test_config();
        let aud_list: Vec<String> = (0..5).map(|i| format!("aud{}", i)).collect();
        let result = generate_aud_hash(&params, aud_list);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().individual.len(), 5);
    }

    #[test]
    fn test_generate_aud_hash_exceeds_limit() {
        let params = test_config();
        let aud_list: Vec<String> = (0..6).map(|i| format!("aud{}", i)).collect();
        let result = generate_aud_hash(&params, aud_list);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exceeds the limit"));
    }

    #[test]
    fn test_generate_aud_hash_deterministic() {
        let params = test_config();
        let aud = vec!["test".to_string()];
        let r1 = generate_aud_hash(&params, aud.clone()).unwrap();
        let r2 = generate_aud_hash(&params, aud).unwrap();
        assert_eq!(r1.combined, r2.combined);
    }

    #[test]
    fn test_generate_leaf_hash_valid() {
        let params = test_config();
        // Use a minimal valid base64-encoded RSA public key modulus
        // This is a small test value, not a real RSA key
        let pk_b64 = "AQAB"; // base64 of [1, 0, 1] (65537 in big-endian... actually just a small value)
        let result = generate_leaf_hash(&params, "https://accounts.google.com", pk_b64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_leaf_hash_deterministic() {
        let params = test_config();
        let pk_b64 = "AQAB";
        let h1 = generate_leaf_hash(&params, "issuer1", pk_b64).unwrap();
        let h2 = generate_leaf_hash(&params, "issuer1", pk_b64).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_generate_leaf_hash_different_issuers() {
        let params = test_config();
        let pk_b64 = "AQAB";
        let h1 = generate_leaf_hash(&params, "issuer1", pk_b64).unwrap();
        let h2 = generate_leaf_hash(&params, "issuer2", pk_b64).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_generate_leaf_hash_invalid_pk() {
        let params = test_config();
        let result = generate_leaf_hash(&params, "issuer", "!!!invalid-base64!!!");
        assert!(result.is_err());
    }
}
