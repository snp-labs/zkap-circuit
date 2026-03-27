use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::merkle_tree::Path;
use circuit::constants::{F, PoseidonHash, ZkPasskeyConfig};
use circuit::field_parser::{ascii_to_field_be, hex_decimal_to_field};
use circuit::text::pad;
use gadget::anchor::AnchorUtils;
use gadget::anchor::poseidon::{PoseidonAnchorScheme, PoseidonAnchorWitness, build_anchor_witness};
use gadget::mekletree::tree_config::MerkleTreeParams;

use crate::Secret;
use crate::app::anchor::poseidon::{derive_selector_from_x_list_and_anchor, derive_x_from_secret};
use crate::app::snark::input::ProofRequest;
use crate::app::snark::types::CircuitContext;
use crate::error::ApplicationError;

use super::anchor::AnchorContext;
use super::audience::AudienceContext;
use super::circuit_input::{AnchorWitness, CircuitInput, JwtWitness, MerkleWitness, PublicInputs};

/// 증명 컨텍스트 빌더
///
/// `ProofRequest`를 받아 증명 생성에 필요한 모든 컨텍스트를 구축합니다.
pub struct ProofContextBuilder<Config: ZkPasskeyConfig> {
    request: ProofRequest,
    circuit_ctx: CircuitContext<Config>,
    anchor_ctx: Option<AnchorContext>,
    audience_ctx: Option<AudienceContext>,
}

impl<Config: ZkPasskeyConfig> ProofContextBuilder<Config> {
    /// 새로운 빌더 생성
    pub fn new(request: ProofRequest) -> Self {
        Self {
            request,
            circuit_ctx: CircuitContext::<Config>::new(),
            anchor_ctx: None,
            audience_ctx: None,
        }
    }

    /// Anchor 컨텍스트 계산
    pub fn build_anchor_context(mut self) -> Result<Self, ApplicationError> {
        log::info!("[ProofContextBuilder] Building anchor context...");

        // X 리스트 계산 (각 토큰에서 secret 추출하여 X 계산)
        let x_list = self.derive_x_list()?;

        // Selector 계산
        let selector = derive_selector_from_x_list_and_anchor::<F>(
            &self.circuit_ctx.poseidon_anchor_key,
            &x_list,
            &self.request.anchor.anchor,
            &self.circuit_ctx.vandermonde_matrix,
        )?;

        // Anchor witness 구축
        let anchor_witness = build_anchor_witness(
            &self.circuit_ctx.poseidon_params,
            &x_list,
            &selector,
            &self.circuit_ctx.vandermonde_matrix,
        )?;

        // H(a, random) 계산
        let h_a = self.compute_h_a(&anchor_witness.a)?;

        // LHS 계산
        let lhs = self.compute_lhs(&anchor_witness.a)?;

        // Partial RHS 리스트 계산
        let partial_rhs_list = self.compute_partial_rhs_list(&anchor_witness);

        // 선택된 인덱스 추출
        let current_idx_list: Vec<usize> = selector
            .iter()
            .enumerate()
            .filter_map(|(i, &sel)| if sel == 1 { Some(i) } else { None })
            .collect();

        self.anchor_ctx = Some(AnchorContext::new(
            selector,
            anchor_witness.a,
            h_a,
            lhs,
            partial_rhs_list,
            current_idx_list,
        ));

        log::info!("[ProofContextBuilder] Anchor context built successfully");
        Ok(self)
    }

    /// Audience 컨텍스트 계산
    pub fn build_audience_context(mut self) -> Result<Self, ApplicationError> {
        log::info!("[ProofContextBuilder] Building audience context...");

        let mut padded = self.request.audience.raw_list.clone();

        // 패딩 필요시 금지 문자열로 채움
        if padded.len() < Config::NUM_AUDIENCE_LIMIT {
            let padding_count = Config::NUM_AUDIENCE_LIMIT - padded.len();
            let padded_str = pad(
                Config::FORBIDDEN_STRING,
                Config::MAX_AUD_LEN,
                Config::PAD_CHAR,
            )?;
            let limbs = ascii_to_field_be::<F>(&padded_str)
                .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))?;
            let h = PoseidonHash::evaluate(&self.circuit_ctx.poseidon_params, limbs)
                .map_err(|_| ApplicationError::PoseidonHashError)?;

            padded.extend_from_slice(&vec![h; padding_count]);
        }

        // H(aud_list) 계산
        let h_aud_list = PoseidonHash::evaluate(&self.circuit_ctx.poseidon_params, padded.clone())
            .map_err(|_| ApplicationError::PoseidonHashError)?;

        self.audience_ctx = Some(AudienceContext::new(padded, h_aud_list));

        log::info!("[ProofContextBuilder] Audience context built successfully");
        Ok(self)
    }

    /// i번째 증명을 위한 CircuitInput 생성
    pub fn build_circuit_input(
        &self,
        proof_index: usize,
    ) -> Result<CircuitInput, ApplicationError> {
        let anchor_ctx = self
            .anchor_ctx
            .as_ref()
            .ok_or_else(|| ApplicationError::InvalidFormat("Anchor context not built".into()))?;

        let audience_ctx = self
            .audience_ctx
            .as_ref()
            .ok_or_else(|| ApplicationError::InvalidFormat("Audience context not built".into()))?;

        // JWT witness 빌드
        let jwt_witness = self.request.token_builders[proof_index]
            .build::<Config>(&self.request.pk_ops[proof_index])
            .map_err(|e| ApplicationError::InvalidFormat(format!("JWT build failed: {}", e)))?;

        // 머클 경로 빌드
        let merkle_path = self.build_merkle_path(proof_index)?;

        let leaf_idx = self.request.merkle.leaf_indices[proof_index];

        Ok(CircuitInput {
            public: PublicInputs {
                hanchor: self.request.anchor.hanchor,
                h_a: anchor_ctx.h_a,
                root: self.request.merkle.root,
                h_sign_user_op: self.request.execution.h_sign_user_op,
                jwt_exp: self.request.execution.jwt_exp[proof_index],
                partial_rhs: anchor_ctx.partial_rhs_for(proof_index),
                lhs: anchor_ctx.lhs,
                h_aud_list: audience_ctx.h_aud_list,
            },
            jwt: JwtWitness::from(jwt_witness),
            anchor: AnchorWitness {
                anchor: self.request.anchor.anchor.clone(),
                a: anchor_ctx.a.clone(),
                selector: anchor_ctx.selector.clone(),
                current_idx: anchor_ctx.current_idx_for(proof_index),
            },
            merkle: MerkleWitness {
                path: merkle_path,
                leaf_idx,
            },
            aud_list: audience_ctx.padded_list.clone(),
            random: self.request.execution.random,
        })
    }

    /// 모든 증명을 위한 CircuitInput 생성
    pub fn build_all_circuit_inputs(&self) -> Result<Vec<CircuitInput>, ApplicationError> {
        (0..Config::K)
            .map(|i| self.build_circuit_input(i))
            .collect()
    }

    /// CircuitContext 참조 반환
    pub fn circuit_context(&self) -> &CircuitContext<Config> {
        &self.circuit_ctx
    }

    // ============ Private Helper Methods ============

    /// Secret에서 X 값 계산
    fn derive_x_list(&self) -> Result<Vec<F>, ApplicationError> {
        let secrets: Vec<Secret> = self
            .request
            .token_builders
            .iter()
            .map(|b| b.parse_secret())
            .collect();

        secrets
            .iter()
            .map(|s| {
                derive_x_from_secret(
                    s,
                    &self.circuit_ctx.poseidon_params,
                    &self.circuit_ctx.anchor_cfg,
                )
            })
            .collect::<Result<Vec<F>, ApplicationError>>()
    }

    /// H(a, random) 계산
    fn compute_h_a(&self, a: &[F]) -> Result<F, ApplicationError> {
        let mut inputs = a.to_vec();
        inputs.push(self.request.execution.random);
        PoseidonHash::evaluate(&self.circuit_ctx.poseidon_params, inputs)
            .map_err(|_| ApplicationError::PoseidonHashError)
    }

    /// <a, anchor> * random 계산
    fn compute_lhs(&self, a: &[F]) -> Result<F, ApplicationError> {
        let ip = PoseidonAnchorScheme::<F>::inner_product(a, &self.request.anchor.anchor.0)
            .map_err(|_| ApplicationError::PoseidonHashError)?;
        Ok(ip * self.request.execution.random)
    }

    /// Partial RHS 리스트 계산
    fn compute_partial_rhs_list(&self, anchor_witness: &PoseidonAnchorWitness<F>) -> Vec<F> {
        let partial_rhs_list = anchor_witness.compute_partial_rhs();
        partial_rhs_list
            .into_iter()
            .filter(|&x| x != F::from(0u8))
            .map(|x| x * self.request.execution.random)
            .collect()
    }

    /// 머클 경로 구축
    fn build_merkle_path(
        &self,
        proof_index: usize,
    ) -> Result<Path<MerkleTreeParams<F>>, ApplicationError> {
        let path = &self.request.merkle.paths[proof_index];
        let leaf_idx = self.request.merkle.leaf_indices[proof_index];

        let path_field: Vec<F> = path
            .iter()
            .map(|p_str| {
                hex_decimal_to_field(p_str)
                    .map_err(|e| ApplicationError::InvalidFormat(format!("{:?}", e)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (leaf_sibling_hash, auth_path_slice) = path_field
            .split_first()
            .ok_or_else(|| ApplicationError::InvalidFormat("Empty merkle path".to_string()))?;

        Ok(Path {
            leaf_sibling_hash: *leaf_sibling_hash,
            auth_path: auth_path_slice.iter().rev().copied().collect(),
            leaf_index: leaf_idx,
        })
    }
}
