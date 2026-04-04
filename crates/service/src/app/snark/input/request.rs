use std::path::PathBuf;

use circuit::constants::{F, CircuitConfig};
use gadget::anchor::poseidon::PoseidonAnchor;

use crate::{app::jwt::builder::TokenBuilder, error::ApplicationError};

use super::RawProofRequest;

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

/// Domain object after raw input has been validated and parsed.
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
    /// Validates and parses a RawProofRequest into a ProofRequest
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

        // Validate anchor length: (N - K + 1) + 1 (last element is hanchor)
        let expected_anchor_len = (n - k + 1) + 1;
        if raw.anchor.len() != expected_anchor_len {
            return Err(ApplicationError::InvalidFormat(format!(
                "Invalid anchor length: expected {}, got {}",
                expected_anchor_len,
                raw.anchor.len()
            )));
        }

        Ok(())
    }

    /// Parses raw input into domain objects
    fn parse(params: &CircuitConfig, raw: RawProofRequest) -> Result<Self, ApplicationError> {
        use ark_utils::hex_decimal_to_field;

        // Create TokenBuilders
        let claims: Vec<&str> = params.claims.iter()
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
                    ApplicationError::InvalidFormat(format!("exp claim not found in token[{}]: {}", i, e))
                })?;
                hex_decimal_to_field::<F>(exp_str).map_err(Into::into)
            })
            .collect::<Result<Vec<F>, ApplicationError>>()?;

        // Parse field elements
        let root = hex_decimal_to_field::<F>(&raw.root)?;
        let h_sign_user_op = hex_decimal_to_field::<F>(&raw.h_sign_user_op)?;
        let random = hex_decimal_to_field::<F>(&raw.random)?;

        // Parse Anchor
        let anchor_data = Self::parse_anchor(&raw.anchor)?;

        // Parse Audience
        let aud_list = raw
            .aud_list
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
                leaf_indices: raw.leaf_indices,
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

    /// Parses the anchor string array
    fn parse_anchor(raw_anchor: &[String]) -> Result<AnchorData, ApplicationError> {
        use ark_utils::hex_decimal_to_field;

        if raw_anchor.is_empty() {
            return Err(ApplicationError::InvalidFormat(
                "Anchor parts cannot be empty".to_string(),
            ));
        }

        // Last element is hanchor
        let (raw_hanchor, raw_anchor_values) = raw_anchor.split_last().ok_or_else(|| {
            ApplicationError::InvalidFormat("Failed to split anchor parts".to_string())
        })?;

        let hanchor = hex_decimal_to_field::<F>(raw_hanchor).map_err(|e| {
            ApplicationError::InvalidFormat(format!(
                "Failed to parse hanchor '{}': {}",
                raw_hanchor, e
            ))
        })?;

        let anchor_fields: Vec<F> = raw_anchor_values
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
