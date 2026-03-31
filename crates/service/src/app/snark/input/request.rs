use std::path::PathBuf;

use circuit::constants::{F, ZkPasskeyConfig};
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

/// Raw 입력이 검증되고 파싱된 후의 도메인 객체입니다.
#[derive(Clone)]
pub struct ProofRequest {
    /// Proving key 경로
    pub pk_path: PathBuf,

    /// 파싱된 JWT 토큰 빌더들
    pub token_builders: Vec<TokenBuilder>,

    /// RSA 공개키 modulus들 (원본 문자열 유지 - 회로에서 사용)
    pub pk_ops: Vec<String>,

    /// 머클 트리 데이터
    pub merkle: MerkleData,

    /// 앵커 데이터
    pub anchor: AnchorData,

    /// 실행 바인딩 데이터
    pub execution: ExecutionBindingData,

    /// Audience 데이터
    pub audience: AudienceData,
}

impl ProofRequest {
    /// RawProofRequest를 검증하고 파싱하여 ProofRequest 생성
    pub fn from_raw<Config: ZkPasskeyConfig>(
        raw: RawProofRequest,
    ) -> Result<Self, ApplicationError> {
        // 1. 입력 검증
        Self::validate::<Config>(&raw)?;

        // 2. 파싱
        Self::parse::<Config>(raw)
    }

    /// 입력 데이터 검증
    fn validate<Config: ZkPasskeyConfig>(raw: &RawProofRequest) -> Result<(), ApplicationError> {
        // K개의 JWT/PK/경로/인덱스가 있어야 함
        if raw.jwts.len() != Config::K
            || raw.pk_ops.len() != Config::K
            || raw.merkle_paths.len() != Config::K
            || raw.leaf_indices.len() != Config::K
        {
            return Err(ApplicationError::InvalidFormat(format!(
                "All input vectors must have length K={}, got: jwts={}, pk_ops={}, mp={}, leaf_index={}",
                Config::K,
                raw.jwts.len(),
                raw.pk_ops.len(),
                raw.merkle_paths.len(),
                raw.leaf_indices.len()
            )));
        }

        // Anchor 길이 검증: (N - K + 1) + 1 (마지막은 hanchor)
        let expected_anchor_len = (Config::N - Config::K + 1) + 1;
        if raw.anchor.len() != expected_anchor_len {
            return Err(ApplicationError::InvalidFormat(format!(
                "Invalid anchor length: expected {}, got {}",
                expected_anchor_len,
                raw.anchor.len()
            )));
        }

        Ok(())
    }

    /// Raw 입력을 도메인 객체로 파싱
    fn parse<Config: ZkPasskeyConfig>(raw: RawProofRequest) -> Result<Self, ApplicationError> {
        use circuit::field_parser::hex_decimal_to_field;

        // TokenBuilder 생성
        let token_builders: Vec<TokenBuilder> = raw
            .jwts
            .iter()
            .map(|jwt| {
                TokenBuilder::new(jwt, Config::CLAIMS.to_vec()).map_err(|e| {
                    ApplicationError::InvalidFormat(format!("JWT parsing failed: {}", e))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 각 JWT 토큰에서 exp 클레임 추출
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

        // 필드 요소 파싱
        let root = hex_decimal_to_field::<F>(&raw.root)?;
        let h_sign_user_op = hex_decimal_to_field::<F>(&raw.h_sign_user_op)?;
        let random = hex_decimal_to_field::<F>(&raw.random)?;

        // Anchor 파싱
        let anchor_data = Self::parse_anchor(&raw.anchor)?;

        // Audience 파싱
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

    /// Anchor 문자열 배열 파싱
    fn parse_anchor(raw_anchor: &[String]) -> Result<AnchorData, ApplicationError> {
        use circuit::field_parser::hex_decimal_to_field;

        if raw_anchor.is_empty() {
            return Err(ApplicationError::InvalidFormat(
                "Anchor parts cannot be empty".to_string(),
            ));
        }

        // 마지막 요소가 hanchor
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
