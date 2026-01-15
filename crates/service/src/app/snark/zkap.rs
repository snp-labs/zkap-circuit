use std::path::PathBuf;

use ark_groth16::Proof;

use common::constants::{BN254, F, ZkPasskeyConfig};
use log;

use crate::{
    app::{
        jwt::builder::TokenBuilder,
        snark::{
            preprocess::{
                compute_anchor_ctx, pad_aud_list_and_hash, parse_inputs, validate_inputs,
            },
            prover::{phase_a_part1, phase_b_part2_msm, prove_streaming},
            types::CircuitContext,
        },
    },
    error::ApplicationError,
};

pub fn generate_baerae_proof<Config: ZkPasskeyConfig>(
    pk_path: &PathBuf,
    raw_jwts: Vec<String>,
    raw_pk_ops: Vec<String>,
    raw_merkle_paths: Vec<Vec<String>>,
    raw_leaf_indices: Vec<usize>,
    raw_root: &str,
    raw_anchor: &[String],
    raw_h_sign_user_op: &str,
    raw_block_timestamp: &str,
    raw_random: &str,
    raw_aud_list: &[String],
) -> Result<(Vec<Proof<BN254>>, Vec<Vec<F>>), ApplicationError> {
    log::info!("[ZKAP] Starting ZK proof generation (Optimized Split Flow)...");

    // 1. 입력 검증
    log::info!("[ZKAP] Step 1: Validating inputs...");
    validate_inputs::<Config>(
        &raw_jwts,
        &raw_pk_ops,
        &raw_merkle_paths,
        &raw_leaf_indices,
        raw_anchor,
    )?;
    log::info!("[ZKAP] Step 1 completed: Input validation passed");

    let circuit_ctx = CircuitContext::<Config>::new();

    // 3. 입력을 도메인 요소로 변환
    log::info!("[ZKAP] Step 3: Converting inputs to domain elements...");

    let parsed_inputs = parse_inputs(
        raw_root,
        raw_h_sign_user_op,
        raw_block_timestamp,
        raw_random,
        raw_anchor,
        raw_aud_list,
    )?;

    log::info!("[ZKAP] Step 3 completed: Inputs converted");

    // 4. TokenBuilder 일괄 생성
    log::info!(
        "[ZKAP] Step 4: Creating TokenBuilders for {} JWTs...",
        raw_jwts.len()
    );
    let builders: Vec<TokenBuilder> = raw_jwts
        .iter()
        .map(|jwt| {
            TokenBuilder::new(jwt, Config::CLAIMS.to_vec())
                .map_err(|e| ApplicationError::InvalidFormat(format!("JWT parsing failed: {}", e)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    log::info!(
        "[ZKAP] Step 4 completed: {} TokenBuilders created",
        builders.len()
    );

    let anchor_ctx = compute_anchor_ctx(&circuit_ctx, &builders, &parsed_inputs)?;

    let (padded_aud_list, h_aud_list) =
        pad_aud_list_and_hash::<Config>(&circuit_ctx.poseidon_params, &parsed_inputs.aud_list)?;

    log::info!("[ZKAP] Phase A+B: Streaming proof generation...");

    let (proofs, public_inputs) = prove_streaming::<Config>(
        pk_path,
        &circuit_ctx,
        &builders,
        &raw_pk_ops,
        &raw_merkle_paths,
        &raw_leaf_indices,
        &parsed_inputs,
        &anchor_ctx,
        &padded_aud_list,
        h_aud_list,
    )?;

    Ok((proofs, public_inputs))
}
