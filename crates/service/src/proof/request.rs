use std::path::PathBuf;

use circuit::constants::{CircuitConfig, F};
use gadget::anchor::poseidon::PoseidonAnchor;

use crate::{error::ApplicationError, jwt::builder::TokenBuilder};

/// Raw, unvalidated proof request received from the outside world.
///
/// All string fields are either hex/decimal field-element strings or Base64-encoded bytes.
/// Pass this to [`ProofRequest::from_raw`] to validate and parse it into a domain object.
/// All slice fields must have exactly `K` entries (matching [`CircuitConfig::k`]).
/// `anchor_evals` must have `N - K + 1` entries; `hanchor` is the separate chain hash value.
/// `aud_hash_list` contains pre-computed Poseidon hashes of each audience value
/// (obtain via [`crate::generate_aud_hash`] first).
#[derive(Debug, Clone)]
pub struct RawProofRequest {
    /// Path to the Groth16 proving key file on disk.
    pub pk_path: PathBuf,

    /// JWT tokens — one per credential (must have exactly `K` entries).
    pub jwts: Vec<String>,

    /// RSA public key moduli in Base64 — one per JWT (must have exactly `K` entries).
    pub pk_ops: Vec<String>,

    /// Merkle authentication paths — one `Vec<String>` per JWT (must have exactly `K` entries).
    pub merkle_paths: Vec<Vec<String>>,

    /// Merkle tree leaf indices — one per JWT (must have exactly `K` entries).
    pub leaf_indices: Vec<u64>,

    /// Merkle root as a hex or decimal field-element string.
    pub root: String,

    /// Anchor polynomial evaluations — must have exactly `N - K + 1` entries.
    pub anchor_evals: Vec<String>,

    /// Anchor chain hash (`hanchor`): the chained Poseidon hash of all `anchor_evals`.
    pub hanchor: String,

    /// Signed UserOperation hash (hex/decimal field-element string).
    pub user_op_hash: String,

    /// Random blinding value (hex/decimal field-element string).
    pub random: String,

    /// Pre-computed audience hashes (hex/decimal field-element strings).
    /// Obtain via [`crate::generate_aud_hash`] and use `AudHashResult::individual`.
    pub aud_hash_list: Vec<String>,
}

impl RawProofRequest {
    /// Construct a [`RawProofRequest`] from its constituent parts.
    ///
    /// No validation is performed here; call [`ProofRequest::from_raw`] to validate.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pk_path: PathBuf,
        jwts: Vec<String>,
        pk_ops: Vec<String>,
        merkle_paths: Vec<Vec<String>>,
        leaf_indices: Vec<u64>,
        root: String,
        anchor_evals: Vec<String>,
        hanchor: String,
        user_op_hash: String,
        random: String,
        aud_hash_list: Vec<String>,
    ) -> Self {
        Self {
            pk_path,
            jwts,
            pk_ops,
            merkle_paths,
            leaf_indices,
            root,
            anchor_evals,
            hanchor,
            user_op_hash,
            random,
            aud_hash_list,
        }
    }

    /// Returns the number of JWT tokens
    pub fn token_count(&self) -> usize {
        self.jwts.len()
    }
}

#[derive(Clone)]
pub struct MerkleData {
    pub root: F,
    pub paths: Vec<Vec<String>>,
    pub leaf_indices: Vec<usize>,
}

#[derive(Clone)]
pub struct AnchorData {
    pub anchor: PoseidonAnchor<F>,
    pub hanchor: F,
}

#[derive(Clone)]
pub struct AudienceData {
    pub raw_list: Vec<F>,
}

#[derive(Clone)]
pub struct ExecutionBindingData {
    pub h_sign_user_op: F,
    pub jwt_exp: Vec<F>,
    pub random: F,
}

/// Validated and parsed proof request — the domain object produced by [`ProofRequest::from_raw`].
///
/// All string fields from [`RawProofRequest`] have been parsed into typed field elements,
/// `TokenBuilder` instances, and structured data ready for circuit input construction.
#[derive(Clone)]
pub struct ProofRequest {
    /// Proving key path
    pub pk_path: PathBuf,

    /// Parsed JWT token builders
    pub token_builders: Vec<TokenBuilder>,

    /// RSA public key moduli (kept as original strings - used by the circuit)
    pub pk_ops: Vec<String>,

    /// Merkle tree data
    pub merkle: MerkleData,

    /// Anchor data
    pub anchor: AnchorData,

    /// Execution binding data
    pub execution: ExecutionBindingData,

    /// Audience data
    pub audience: AudienceData,
}

impl ProofRequest {
    /// Validate and parse a [`RawProofRequest`] into a [`ProofRequest`].
    ///
    /// Validation checks that all vectors have the correct length for the given `params` (K entries
    /// for JWT/PK/path/index, and `N - K + 2` entries for `anchor`). Parsing converts hex/decimal
    /// strings to field elements, decodes JWT tokens into `TokenBuilder` instances, and structures
    /// Merkle, anchor, execution, and audience data into typed sub-structs.
    pub fn from_raw(
        params: &CircuitConfig,
        raw: RawProofRequest,
    ) -> Result<Self, ApplicationError> {
        // 1. Input validation
        Self::validate(params, &raw)?;

        // 2. Parsing
        Self::parse(params, raw)
    }

    /// Validates input data
    fn validate(params: &CircuitConfig, raw: &RawProofRequest) -> Result<(), ApplicationError> {
        let k = params.k as usize;
        let n = params.n as usize;

        // Must have K JWT/PK/path/index entries
        if raw.jwts.len() != k
            || raw.pk_ops.len() != k
            || raw.merkle_paths.len() != k
            || raw.leaf_indices.len() != k
        {
            return Err(ApplicationError::InvalidFormat(format!(
                "All input vectors must have length K={}, got: jwts={}, pk_ops={}, mp={}, leaf_index={}",
                k,
                raw.jwts.len(),
                raw.pk_ops.len(),
                raw.merkle_paths.len(),
                raw.leaf_indices.len()
            )));
        }

        // Validate anchor_evals length: N - K + 1
        let expected_anchor_evals_len = n - k + 1;
        if raw.anchor_evals.len() != expected_anchor_evals_len {
            return Err(ApplicationError::InvalidFormat(format!(
                "Invalid anchor_evals length: expected {}, got {}",
                expected_anchor_evals_len,
                raw.anchor_evals.len()
            )));
        }

        Ok(())
    }

    /// Parses raw input into domain objects
    fn parse(params: &CircuitConfig, raw: RawProofRequest) -> Result<Self, ApplicationError> {
        use ark_utils::hex_decimal_to_field;

        // Create TokenBuilders
        let claims: Vec<&str> = params
            .claims
            .iter()
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        let token_builders: Vec<TokenBuilder> = raw
            .jwts
            .iter()
            .map(|jwt| {
                TokenBuilder::new(jwt, claims.clone()).map_err(|e| {
                    ApplicationError::InvalidFormat(format!("JWT parsing failed: {}", e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Extract exp claim from each JWT token
        let jwt_exp: Vec<F> = token_builders
            .iter()
            .enumerate()
            .map(|(i, tb)| {
                let exp_str = tb.get_claim_by("exp").map_err(|e| {
                    ApplicationError::InvalidFormat(format!(
                        "exp claim not found in token[{}]: {}",
                        i, e
                    ))
                })?;
                hex_decimal_to_field::<F>(exp_str).map_err(Into::into)
            })
            .collect::<Result<Vec<F>, ApplicationError>>()?;

        // Parse field elements
        let root = hex_decimal_to_field::<F>(&raw.root)?;
        let h_sign_user_op = hex_decimal_to_field::<F>(&raw.user_op_hash)?;
        let random = hex_decimal_to_field::<F>(&raw.random)?;

        // Parse Anchor
        let anchor_data = Self::parse_anchor(&raw.anchor_evals, &raw.hanchor)?;

        // Parse Audience
        let aud_list = raw
            .aud_hash_list
            .iter()
            .map(|s| hex_decimal_to_field::<F>(s).map_err(Into::into))
            .collect::<Result<Vec<F>, ApplicationError>>()?;

        Ok(Self {
            pk_path: raw.pk_path,
            token_builders,
            pk_ops: raw.pk_ops,
            merkle: MerkleData {
                root,
                paths: raw.merkle_paths,
                leaf_indices: raw.leaf_indices.into_iter().map(|i| i as usize).collect(),
            },
            anchor: anchor_data,
            execution: ExecutionBindingData {
                h_sign_user_op,
                jwt_exp,
                random,
            },
            audience: AudienceData { raw_list: aud_list },
        })
    }

    /// Parses the anchor evaluations and hanchor into typed domain objects.
    fn parse_anchor(
        anchor_evals: &[String],
        hanchor: &str,
    ) -> Result<AnchorData, ApplicationError> {
        use ark_utils::hex_decimal_to_field;

        let hanchor = hex_decimal_to_field::<F>(hanchor).map_err(|e| {
            ApplicationError::InvalidFormat(format!("Failed to parse hanchor '{}': {}", hanchor, e))
        })?;

        let anchor_fields: Vec<F> = anchor_evals
            .iter()
            .map(|f| {
                hex_decimal_to_field::<F>(f)
                    .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))
            })
            .collect::<Result<Vec<F>, ApplicationError>>()?;

        Ok(AnchorData {
            anchor: PoseidonAnchor::new(anchor_fields),
            hanchor,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::constants::RawCircuitConfig;
    use std::path::PathBuf;

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
    fn test_raw_proof_request_new() {
        let req = RawProofRequest::new(
            PathBuf::from("/tmp/pk"),
            vec!["jwt1".into()],
            vec!["pk1".into()],
            vec![vec!["path1".into()]],
            vec![0u64],
            "0".into(),
            vec!["1".into(), "2".into()], // anchor_evals
            "42".into(),                  // hanchor
            "0".into(),                   // h_sign_user_op
            "0".into(),                   // random
            vec!["aud1".into()],          // aud_hash_list
        );
        assert_eq!(req.token_count(), 1);
        assert_eq!(req.pk_path, PathBuf::from("/tmp/pk"));
    }

    #[test]
    fn test_validate_mismatched_jwt_count() {
        let params = test_config(); // k=3
        let raw = RawProofRequest::new(
            PathBuf::from("/tmp/pk"),
            vec!["jwt1".into(), "jwt2".into()], // only 2, need 3
            vec!["pk1".into(), "pk2".into(), "pk3".into()],
            vec![vec![], vec![], vec![]],
            vec![0u64, 1, 2],
            "0".into(),
            vec!["1".into(); 4], // anchor_evals: n-k+1 = 6-3+1 = 4
            "0".into(),          // hanchor
            "0".into(),
            "0".into(),
            vec![],
        );
        let result = ProofRequest::from_raw(&params, raw);
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(err.contains("must have length K=3"));
    }

    #[test]
    fn test_validate_wrong_anchor_length() {
        let params = test_config(); // n=6, k=3 → expected anchor_evals len = 4
        let raw = RawProofRequest::new(
            PathBuf::from("/tmp/pk"),
            vec!["jwt1".into(), "jwt2".into(), "jwt3".into()],
            vec!["pk1".into(), "pk2".into(), "pk3".into()],
            vec![vec![], vec![], vec![]],
            vec![0u64, 1, 2],
            "0".into(),
            vec!["1".into(); 3], // wrong: should be 4
            "0".into(),          // hanchor
            "0".into(),
            "0".into(),
            vec![],
        );
        let result = ProofRequest::from_raw(&params, raw);
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(err.contains("Invalid anchor_evals length"));
    }

    #[test]
    fn test_validate_mismatched_pk_ops_count() {
        let params = test_config(); // k=3
        let raw = RawProofRequest::new(
            PathBuf::from("/tmp/pk"),
            vec!["jwt1".into(), "jwt2".into(), "jwt3".into()],
            vec!["pk1".into()], // only 1, need 3
            vec![vec![], vec![], vec![]],
            vec![0u64, 1, 2],
            "0".into(),
            vec!["1".into(); 4], // anchor_evals
            "0".into(),          // hanchor
            "0".into(),
            "0".into(),
            vec![],
        );
        let result = ProofRequest::from_raw(&params, raw);
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(err.contains("must have length K=3"));
    }

    #[test]
    fn test_validate_mismatched_leaf_indices() {
        let params = test_config(); // k=3
        let raw = RawProofRequest::new(
            PathBuf::from("/tmp/pk"),
            vec!["jwt1".into(), "jwt2".into(), "jwt3".into()],
            vec!["pk1".into(), "pk2".into(), "pk3".into()],
            vec![vec![], vec![], vec![]],
            vec![0u64], // only 1, need 3
            "0".into(),
            vec!["1".into(); 4], // anchor_evals
            "0".into(),          // hanchor
            "0".into(),
            "0".into(),
            vec![],
        );
        let result = ProofRequest::from_raw(&params, raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_anchor_valid() {
        // 3 anchor evals + hanchor as separate arg
        let anchor_evals: Vec<String> = vec!["1".into(), "2".into(), "3".into()];
        let result = ProofRequest::parse_anchor(&anchor_evals, "42");
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.anchor.0.len(), 3);
    }

    #[test]
    fn test_parse_anchor_invalid_hanchor() {
        let anchor_evals: Vec<String> = vec!["1".into(), "2".into()];
        let result = ProofRequest::parse_anchor(&anchor_evals, "not_a_number");
        assert!(result.is_err());
    }
}
