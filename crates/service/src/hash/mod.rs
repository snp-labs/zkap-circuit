//! Host-side Poseidon hashing utilities.
//!
//! Provides [`generate_poseidon_hash`] (generic field-element hash),
//! [`generate_audience_hashes`] (per-audience hash + combined
//! `audience_list_hash`), and [`generate_issuer_key_hash`] (Merkle leaf for
//! issuer + RSA public-key pairs). All functions use the shared
//! [`crate::poseidon_params`] singleton.

use ark_crypto_primitives::crh::CRHScheme;
use ark_utils::{hex_decimal_to_field, str_to_limbs};
use circuit::types::{CircuitConfig, F, PAD_CHAR, PoseidonHash};
use gadget::{base64::decode_any_base64, signature::rsa::PublicKey};

use crate::dto::{
    AudienceHashRequest, AudienceHashResponse, HashRequest, HashResponse, IssuerKeyHashRequest,
    IssuerKeyHashResponse,
};
use crate::error::ApplicationError;

/// RSA-2048 modulus byte length (256). Enforced on
/// [`IssuerKeyHashRequest::rsa_modulus_b64`] after base64 decoding.
const RSA_2048_MODULUS_BYTES: usize = 256;

/// Compute a Poseidon hash over a list of field-element strings.
///
/// Each entry in `request.field_elements` is parsed as either a `0x`-prefixed
/// hex string or a decimal string representing a BN254 Fr element. Parse
/// failures return [`ApplicationError::InvalidFieldElement`] carrying the
/// 0-based input index. The Poseidon output is rendered as a `0x`-prefixed
/// lowercase big-endian hex string.
pub fn generate_poseidon_hash(request: HashRequest) -> Result<HashResponse, ApplicationError> {
    let poseidon_params = crate::poseidon_params();

    let fields: Vec<F> = request
        .field_elements
        .iter()
        .enumerate()
        .map(|(index, s)| {
            hex_decimal_to_field::<F>(s).map_err(|e| ApplicationError::InvalidFieldElement {
                index,
                message: e.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let result = PoseidonHash::evaluate(poseidon_params, fields)
        .map_err(|e| ApplicationError::HashFailed(e.to_string()))?;

    Ok(HashResponse {
        hash: crate::field_to_hex(result),
    })
}

/// Compute per-audience Poseidon hashes and the combined audience-list hash.
///
/// `request.audiences` is order-sensitive (no internal sort) and duplicate
/// entries are permitted; each entry occupies its own slot. Inputs shorter
/// than `config.num_audience_limit` are padded with `config.forbidden_string`
/// before hashing; inputs longer than the limit return
/// [`ApplicationError::AudienceLimitExceeded`].
///
/// Each audience is converted to limbs via `str_to_limbs(max_aud_len,
/// PAD_CHAR)` (quote-aware byte packing handled internally) and individually
/// hashed; the per-audience hashes are then themselves Poseidon-hashed to
/// produce `audience_list_hash`.
pub fn generate_audience_hashes(
    config: &CircuitConfig,
    request: AudienceHashRequest,
) -> Result<AudienceHashResponse, ApplicationError> {
    let poseidon_params = crate::poseidon_params();
    let num_audience_limit = config.num_audience_limit as usize;

    if request.audiences.len() > num_audience_limit {
        return Err(ApplicationError::AudienceLimitExceeded {
            got: request.audiences.len(),
            limit: num_audience_limit,
        });
    }

    let mut aud_vec = request.audiences;
    while aud_vec.len() < num_audience_limit {
        aud_vec.push(config.forbidden_string.clone());
    }

    let aud_fields: Vec<F> = aud_vec
        .iter()
        .map(|a| {
            let limbs = str_to_limbs(a, config.max_aud_len as usize, PAD_CHAR as u8);
            PoseidonHash::evaluate(poseidon_params, limbs)
                .map_err(|e| ApplicationError::HashFailed(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let combined = PoseidonHash::evaluate(poseidon_params, &*aud_fields)
        .map_err(|e| ApplicationError::HashFailed(e.to_string()))?;

    Ok(AudienceHashResponse {
        audience_hashes: aud_fields.iter().map(|f| crate::field_to_hex(*f)).collect(),
        audience_list_hash: crate::field_to_hex(combined),
    })
}

/// Compute the Merkle-leaf Poseidon hash for an issuer + RSA-2048 public-key
/// pair.
///
/// `request.issuer` is padded to `config.max_iss_len` bytes with the circuit
/// pad character. `request.rsa_modulus_b64` must base64-decode to exactly
/// `RSA_2048_MODULUS_BYTES` (256) bytes; other lengths return
/// [`ApplicationError::InvalidRsaModulus`]. The RSA public exponent is fixed
/// at 65537 in-circuit and is sourced from
/// `gadget::constants::RSA_DEFAULT_EXPONENT_B64` rather than being accepted
/// through this API.
pub fn generate_issuer_key_hash(
    config: &CircuitConfig,
    request: IssuerKeyHashRequest,
) -> Result<IssuerKeyHashResponse, ApplicationError> {
    use circuit::types::BNP;
    use circuit::types::CG;

    let poseidon_params = crate::poseidon_params();

    let iss_limbs = str_to_limbs(&request.issuer, config.max_iss_len as usize, PAD_CHAR as u8);

    let n_decoded = decode_any_base64(&request.rsa_modulus_b64)
        .map_err(|e| ApplicationError::InvalidBase64(format!("rsa_modulus_b64: {}", e)))?;
    if n_decoded.len() != RSA_2048_MODULUS_BYTES {
        return Err(ApplicationError::InvalidRsaModulus(format!(
            "expected {} bytes (RSA-2048), got {}",
            RSA_2048_MODULUS_BYTES,
            n_decoded.len()
        )));
    }

    let e_decoded =
        decode_any_base64(gadget::constants::RSA_DEFAULT_EXPONENT_B64).map_err(|e| {
            ApplicationError::InvalidBase64(format!("internal RSA exponent constant: {}", e))
        })?;

    let pk_obj = PublicKey {
        n: n_decoded,
        e: e_decoded,
    };

    let n_limbs = pk_obj.to_limbs::<BNP, CG>().0;

    let mut leaf_inputs = Vec::with_capacity(iss_limbs.len() + n_limbs.len());
    leaf_inputs.extend_from_slice(&iss_limbs);
    leaf_inputs.extend_from_slice(&n_limbs);

    let leaf = PoseidonHash::evaluate(poseidon_params, &*leaf_inputs)
        .map_err(|e| ApplicationError::HashFailed(e.to_string()))?;

    Ok(IssuerKeyHashResponse {
        hash: crate::field_to_hex(leaf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitConfig {
        CircuitConfig {
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
        }
    }

    fn req(elems: &[&str]) -> HashRequest {
        HashRequest {
            field_elements: elems.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn poseidon_hash_single_element() {
        let result = generate_poseidon_hash(req(&["1"]));
        assert!(result.is_ok());
        assert!(result.unwrap().hash.starts_with("0x"));
    }

    #[test]
    fn poseidon_hash_multiple_elements() {
        let result = generate_poseidon_hash(req(&["1", "2", "3"]));
        assert!(result.is_ok());
    }

    #[test]
    fn poseidon_hash_deterministic() {
        let r1 = generate_poseidon_hash(req(&["42"])).unwrap();
        let r2 = generate_poseidon_hash(req(&["42"])).unwrap();
        assert_eq!(r1.hash, r2.hash);
    }

    #[test]
    fn poseidon_hash_hex_and_decimal_agree() {
        let r_dec = generate_poseidon_hash(req(&["10"])).unwrap();
        let r_hex = generate_poseidon_hash(req(&["0x0a"])).unwrap();
        assert_eq!(r_dec.hash, r_hex.hash);
    }

    #[test]
    fn poseidon_hash_different_inputs_different_outputs() {
        let r1 = generate_poseidon_hash(req(&["1"])).unwrap();
        let r2 = generate_poseidon_hash(req(&["2"])).unwrap();
        assert_ne!(r1.hash, r2.hash);
    }

    #[test]
    fn poseidon_hash_invalid_input_reports_index() {
        let result = generate_poseidon_hash(req(&["1", "not_a_number", "3"]));
        match result {
            Err(ApplicationError::InvalidFieldElement { index, .. }) => {
                assert_eq!(index, 1, "offending input is the second entry");
            }
            other => panic!("expected InvalidFieldElement, got {:?}", other),
        }
    }

    #[test]
    fn poseidon_hash_invalid_first_input_reports_index_zero() {
        let result = generate_poseidon_hash(req(&["not_a_number"]));
        match result {
            Err(ApplicationError::InvalidFieldElement { index, .. }) => {
                assert_eq!(index, 0);
            }
            other => panic!("expected InvalidFieldElement, got {:?}", other),
        }
    }

    /// Empty `field_elements` defers to the underlying Poseidon CRH. The
    /// observed behavior is locked in here: either `Ok(_)` or
    /// `Err(ApplicationError::HashFailed(_))` is acceptable, but anything
    /// else would be a regression.
    #[test]
    fn poseidon_hash_empty_locks_in_behavior() {
        let result = generate_poseidon_hash(req(&[]));
        match result {
            Ok(resp) => assert!(resp.hash.starts_with("0x")),
            Err(ApplicationError::HashFailed(_)) => {}
            other => panic!("unexpected result for empty input: {:?}", other),
        }
    }

    #[test]
    fn audience_hashes_within_limit_pads_to_limit() {
        let params = test_config();
        let req = AudienceHashRequest {
            audiences: vec!["aud1".into(), "aud2".into()],
        };
        let r = generate_audience_hashes(&params, req).unwrap();
        assert_eq!(r.audience_hashes.len(), 5);
        assert!(r.audience_list_hash.starts_with("0x"));
        for h in &r.audience_hashes {
            assert!(h.starts_with("0x"));
        }
    }

    #[test]
    fn audience_hashes_exact_limit() {
        let params = test_config();
        let aud_list: Vec<String> = (0..5).map(|i| format!("aud{}", i)).collect();
        let req = AudienceHashRequest {
            audiences: aud_list,
        };
        let r = generate_audience_hashes(&params, req).unwrap();
        assert_eq!(r.audience_hashes.len(), 5);
    }

    #[test]
    fn audience_hashes_exceeds_limit_returns_typed_error() {
        let params = test_config();
        let aud_list: Vec<String> = (0..6).map(|i| format!("aud{}", i)).collect();
        let req = AudienceHashRequest {
            audiences: aud_list,
        };
        match generate_audience_hashes(&params, req) {
            Err(ApplicationError::AudienceLimitExceeded { got, limit }) => {
                assert_eq!(got, 6);
                assert_eq!(limit, 5);
            }
            other => panic!("expected AudienceLimitExceeded, got {:?}", other),
        }
    }

    #[test]
    fn audience_hashes_order_sensitive() {
        let params = test_config();
        let ab = generate_audience_hashes(
            &params,
            AudienceHashRequest {
                audiences: vec!["a".into(), "b".into()],
            },
        )
        .unwrap();
        let ba = generate_audience_hashes(
            &params,
            AudienceHashRequest {
                audiences: vec!["b".into(), "a".into()],
            },
        )
        .unwrap();
        assert_ne!(ab.audience_list_hash, ba.audience_list_hash);
    }

    #[test]
    fn audience_hashes_duplicate_allowed_and_distinct_from_single() {
        let params = test_config();
        let single = generate_audience_hashes(
            &params,
            AudienceHashRequest {
                audiences: vec!["a".into()],
            },
        )
        .unwrap();
        let dup = generate_audience_hashes(
            &params,
            AudienceHashRequest {
                audiences: vec!["a".into(), "a".into()],
            },
        )
        .unwrap();
        assert_ne!(single.audience_list_hash, dup.audience_list_hash);
    }

    #[test]
    fn audience_hashes_deterministic() {
        let params = test_config();
        let r1 = generate_audience_hashes(
            &params,
            AudienceHashRequest {
                audiences: vec!["test".into()],
            },
        )
        .unwrap();
        let r2 = generate_audience_hashes(
            &params,
            AudienceHashRequest {
                audiences: vec!["test".into()],
            },
        )
        .unwrap();
        assert_eq!(r1.audience_list_hash, r2.audience_list_hash);
        assert_eq!(r1.audience_hashes, r2.audience_hashes);
    }

    /// RSA-2048 modulus: a 256-byte buffer. Specific bit pattern is
    /// irrelevant for the host-side hash flow — `gadget::signature::rsa`
    /// accepts any 256-byte big-endian payload and decomposes it into
    /// BigNat limbs.
    fn rsa_modulus_256_bytes() -> Vec<u8> {
        let mut v = vec![0xAB; 256];
        v[0] = 0xC0;
        v[255] = 0x01;
        v
    }

    fn rsa_modulus_b64() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(rsa_modulus_256_bytes())
    }

    #[test]
    fn issuer_key_hash_valid_rsa_2048() {
        let params = test_config();
        let req = IssuerKeyHashRequest {
            issuer: "https://accounts.google.com".into(),
            rsa_modulus_b64: rsa_modulus_b64(),
        };
        let r = generate_issuer_key_hash(&params, req).unwrap();
        assert!(r.hash.starts_with("0x"));
    }

    #[test]
    fn issuer_key_hash_deterministic() {
        let params = test_config();
        let r1 = generate_issuer_key_hash(
            &params,
            IssuerKeyHashRequest {
                issuer: "iss".into(),
                rsa_modulus_b64: rsa_modulus_b64(),
            },
        )
        .unwrap();
        let r2 = generate_issuer_key_hash(
            &params,
            IssuerKeyHashRequest {
                issuer: "iss".into(),
                rsa_modulus_b64: rsa_modulus_b64(),
            },
        )
        .unwrap();
        assert_eq!(r1.hash, r2.hash);
    }

    #[test]
    fn issuer_key_hash_different_issuers_differ() {
        let params = test_config();
        let r1 = generate_issuer_key_hash(
            &params,
            IssuerKeyHashRequest {
                issuer: "issuer-1".into(),
                rsa_modulus_b64: rsa_modulus_b64(),
            },
        )
        .unwrap();
        let r2 = generate_issuer_key_hash(
            &params,
            IssuerKeyHashRequest {
                issuer: "issuer-2".into(),
                rsa_modulus_b64: rsa_modulus_b64(),
            },
        )
        .unwrap();
        assert_ne!(r1.hash, r2.hash);
    }

    #[test]
    fn issuer_key_hash_rejects_invalid_base64() {
        let params = test_config();
        let req = IssuerKeyHashRequest {
            issuer: "iss".into(),
            rsa_modulus_b64: "!!!not-base64!!!".into(),
        };
        match generate_issuer_key_hash(&params, req) {
            Err(ApplicationError::InvalidBase64(_)) => {}
            other => panic!("expected InvalidBase64, got {:?}", other),
        }
    }

    #[test]
    fn issuer_key_hash_rejects_wrong_length_modulus() {
        use base64::Engine;
        let short_modulus = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 128]);
        let params = test_config();
        let req = IssuerKeyHashRequest {
            issuer: "iss".into(),
            rsa_modulus_b64: short_modulus,
        };
        match generate_issuer_key_hash(&params, req) {
            Err(ApplicationError::InvalidRsaModulus(msg)) => {
                assert!(
                    msg.contains("256"),
                    "expected length detail in error: {}",
                    msg
                );
                assert!(
                    msg.contains("128"),
                    "expected observed-length in error: {}",
                    msg
                );
            }
            other => panic!("expected InvalidRsaModulus, got {:?}", other),
        }
    }
}
