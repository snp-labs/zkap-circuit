use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::merkle_tree::Path;
use circuit::{
    AnchorWitness, AudienceWitness, ZkapCircuitInput, CircuitConstants, CircuitPublicInputs,
    JwtWitness, MerkleWitness, MiscWitness,
};
use circuit::constants::{F, PoseidonHash, CircuitConfig, PAD_CHAR};
use ark_utils::{try_str_to_fields, hex_decimal_to_field};
use ark_utils::pad;
use gadget::anchor::AnchorUtils;
use gadget::anchor::poseidon::{PoseidonAnchorScheme, PoseidonAnchorWitness, build_anchor_witness};
use gadget::merkletree::tree_config::MerkleTreeParams;

use crate::Secret;
use crate::app::anchor::poseidon::{derive_selector_from_x_list_and_anchor, derive_x_from_secret};
use crate::app::snark::input::ProofRequest;
use crate::app::snark::types::CircuitContext;
use crate::error::ApplicationError;

use super::anchor::AnchorContext;
use super::audience::AudienceContext;

/// Proof context builder
///
/// Receives a `ProofRequest` and builds all context required for proof generation.
pub struct ProofContextBuilder {
    params: CircuitConfig,
    request: ProofRequest,
    circuit_ctx: CircuitContext,
    anchor_ctx: Option<AnchorContext>,
    audience_ctx: Option<AudienceContext>,
}

impl ProofContextBuilder {
    /// Creates a new builder
    pub fn new(params: &CircuitConfig, request: ProofRequest) -> Self {
        Self {
            params: params.clone(),
            request,
            circuit_ctx: CircuitContext::new(params),
            anchor_ctx: None,
            audience_ctx: None,
        }
    }

    /// Computes the Anchor context
    pub fn build_anchor_context(mut self) -> Result<Self, ApplicationError> {
        log::info!("[ProofContextBuilder] Building anchor context...");

        // Compute X list (extract secret from each token and compute X)
        let x_list = self.derive_x_list()?;

        // Compute Selector
        let selector = derive_selector_from_x_list_and_anchor::<F>(
            &self.circuit_ctx.poseidon_anchor_key,
            &x_list,
            &self.request.anchor.anchor,
            &self.circuit_ctx.vandermonde_matrix,
        )?;

        // Build anchor witness
        let anchor_witness = build_anchor_witness(
            &self.circuit_ctx.poseidon_params,
            &x_list,
            &selector,
            &self.circuit_ctx.vandermonde_matrix,
        )?;

        // Compute H(a, random)
        let h_a = self.compute_h_a(&anchor_witness.a)?;

        // Compute LHS
        let lhs = self.compute_lhs(&anchor_witness.a)?;

        // Compute Partial RHS list
        let partial_rhs_list = self.compute_partial_rhs_list(&anchor_witness);

        // Extract selected indices
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

    /// Computes the Audience context
    pub fn build_audience_context(mut self) -> Result<Self, ApplicationError> {
        log::info!("[ProofContextBuilder] Building audience context...");

        let mut padded = self.request.audience.raw_list.clone();

        // If padding is needed, fill with the forbidden string
        let num_audience_limit = self.params.num_audience_limit as usize;
        if padded.len() < num_audience_limit {
            let padding_count = num_audience_limit - padded.len();
            let forbidden_str = std::str::from_utf8(&self.params.forbidden_string)
                .map_err(|e| ApplicationError::InvalidFormat(format!("Invalid forbidden_string: {}", e)))?;
            let padded_str = pad(
                forbidden_str,
                self.params.max_aud_len as usize,
                PAD_CHAR,
            )?;
            let limbs = try_str_to_fields::<F>(&padded_str)
                .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))?;
            let h = PoseidonHash::evaluate(&self.circuit_ctx.poseidon_params, limbs)
                .map_err(|_| ApplicationError::PoseidonHashError)?;

            padded.extend_from_slice(&vec![h; padding_count]);
        }

        // Compute H(aud_list)
        let h_aud_list = PoseidonHash::evaluate(&self.circuit_ctx.poseidon_params, padded.clone())
            .map_err(|_| ApplicationError::PoseidonHashError)?;

        self.audience_ctx = Some(AudienceContext::new(padded, h_aud_list));

        log::info!("[ProofContextBuilder] Audience context built successfully");
        Ok(self)
    }

    /// Builds a ZkapCircuitInput for the i-th proof
    pub fn build_circuit_input(
        &self,
        proof_index: usize,
    ) -> Result<ZkapCircuitInput<F>, ApplicationError> {
        let anchor_ctx = self
            .anchor_ctx
            .as_ref()
            .ok_or_else(|| ApplicationError::InvalidFormat("Anchor context not built".into()))?;

        let audience_ctx = self
            .audience_ctx
            .as_ref()
            .ok_or_else(|| ApplicationError::InvalidFormat("Audience context not built".into()))?;

        // Build JWT witness
        let jwt_witness = self.request.token_builders[proof_index]
            .build(&self.params, &self.request.pk_ops[proof_index])
            .map_err(|e| ApplicationError::InvalidFormat(format!("JWT build failed: {}", e)))?;

        // Build merkle path
        let merkle_path = self.build_merkle_path(proof_index)?;

        let leaf_idx = self.request.merkle.leaf_indices[proof_index];

        Ok(ZkapCircuitInput {
            params: self.params.clone(),
            constants: CircuitConstants {
                vandermonde_matrix: self.circuit_ctx.vandermonde_matrix.clone(),
                poseidon_param: self.circuit_ctx.poseidon_params.clone(),
                base64_table: self.circuit_ctx.base64_table.clone(),
            },
            public_inputs: CircuitPublicInputs {
                hanchor: self.request.anchor.hanchor,
                h_a: anchor_ctx.h_a,
                root: self.request.merkle.root,
                h_sign_user_op: self.request.execution.h_sign_user_op,
                jwt_exp: self.request.execution.jwt_exp[proof_index],
                partial_rhs: anchor_ctx.partial_rhs_for(proof_index),
                lhs: anchor_ctx.lhs,
                h_aud_list: audience_ctx.h_aud_list,
            },
            jwt: JwtWitness {
                nblocks: jwt_witness.nblocks,
                claim_indices: jwt_witness.claim_indices,
                pay_offset_b64: jwt_witness.pay_offset_b64,
                pay_len_b64: jwt_witness.pay_len_b64,
                sha_pad_jwt_b64: jwt_witness.sha_pad_jwt_b64,
                index_bits: jwt_witness.index_bits,
                pk: jwt_witness.pk,
                sig: jwt_witness.sig,
                total_len: jwt_witness.total_len,
                pad_start_byte_idx: jwt_witness.pad_start_byte_idx,
            },
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
            audience: AudienceWitness {
                aud_list: audience_ctx.padded_list.clone(),
            },
            misc: MiscWitness {
                random: self.request.execution.random,
            },
        })
    }

    /// Builds ZkapCircuitInputs for all proofs
    pub fn build_all_circuit_inputs(&self) -> Result<Vec<ZkapCircuitInput<F>>, ApplicationError> {
        (0..self.params.k as usize)
            .map(|i| self.build_circuit_input(i))
            .collect()
    }

    // ============ Private Helper Methods ============

    /// Computes X values from Secrets
    fn derive_x_list(&self) -> Result<Vec<F>, ApplicationError> {
        let secrets: Vec<Secret> = self
            .request
            .token_builders
            .iter()
            .map(|b| b.parse_secret().map_err(|e| ApplicationError::InvalidFormat(format!("{}", e))))
            .collect::<Result<Vec<_>, _>>()?;

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

    /// Computes H(a, random)
    fn compute_h_a(&self, a: &[F]) -> Result<F, ApplicationError> {
        let mut inputs = a.to_vec();
        inputs.push(self.request.execution.random);
        PoseidonHash::evaluate(&self.circuit_ctx.poseidon_params, inputs)
            .map_err(|_| ApplicationError::PoseidonHashError)
    }

    /// Computes <a, anchor> * random
    fn compute_lhs(&self, a: &[F]) -> Result<F, ApplicationError> {
        let ip = PoseidonAnchorScheme::<F>::inner_product(a, &self.request.anchor.anchor.0)
            .map_err(|_| ApplicationError::PoseidonHashError)?;
        Ok(ip * self.request.execution.random)
    }

    /// Computes the Partial RHS list
    fn compute_partial_rhs_list(&self, anchor_witness: &PoseidonAnchorWitness<F>) -> Vec<F> {
        let partial_rhs_list = anchor_witness.compute_partial_rhs();
        partial_rhs_list
            .into_iter()
            .filter(|&x| x != F::from(0u8))
            .map(|x| x * self.request.execution.random)
            .collect()
    }

    /// Builds the merkle path
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
