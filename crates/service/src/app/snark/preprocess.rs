use ark_crypto_primitives::{crh::CRHScheme, merkle_tree::Path, sponge::poseidon::PoseidonConfig};
use common::{
    constants::{AnchorConfig, F, PoseidonHash, ZkPasskeyConfig},
    field_parser::{ascii_to_field_be, hex_decimal_to_field}, text::pad,
};
use gadget::{
    anchor::{
        AnchorUtils,
        poseidon::{
            PoseidonAnchor, PoseidonAnchorScheme, PoseidonAnchorWitness, build_anchor_witness,
        },
    },
    mekletree::tree_config::MerkleTreeParams,
};

use crate::{
    Secret,
    app::{
        anchor::poseidon::{derive_selector_from_x_list_and_anchor, derive_x_from_secret},
        jwt::builder::TokenBuilder,
        snark::types::{AnchorContext, CircuitContext, ParsedInputs},
    },
    error::ApplicationError,
};

pub(crate) fn validate_inputs<Config: ZkPasskeyConfig>(
    raw_jwts: &[String],
    raw_pk_ops: &[String],
    raw_merkle_paths: &[Vec<String>],
    raw_leaf_indices: &[usize],
    raw_anchor: &[String],
) -> Result<(), ApplicationError> {
    if raw_jwts.len() != Config::K
        || raw_pk_ops.len() != Config::K
        || raw_merkle_paths.len() != Config::K
        || raw_leaf_indices.len() != Config::K
    {
        return Err(ApplicationError::InvalidFormat(format!(
            "All input vectors must have length K={}, got: jwts={}, pk_ops={}, mp={}, leaf_index={}",
            Config::K,
            raw_jwts.len(),
            raw_pk_ops.len(),
            raw_merkle_paths.len(),
            raw_leaf_indices.len()
        )));
    }
    if raw_anchor.len() != (Config::N - Config::K + 1) + 1 {
        return Err(ApplicationError::InvalidFormat(
            "Invalid anchor_parts length".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_inputs(
    raw_root: &str,
    raw_h_sign_user_op: &str,
    raw_block_timestamp: &str,
    raw_random: &str,
    raw_anchor: &[String],
    raw_aud_list: &[String],
) -> Result<ParsedInputs, ApplicationError> {
    let root = hex_decimal_to_field::<F>(raw_root)?;
    let h_sign_user_op = hex_decimal_to_field::<F>(raw_h_sign_user_op)?;
    let block_timestamp = hex_decimal_to_field::<F>(raw_block_timestamp)?;
    let random = hex_decimal_to_field::<F>(raw_random)?;
    let (anchor, hanchor) = convert_raw_anchor(raw_anchor)?;
    let aud_list = raw_aud_list
        .iter()
        .map(|s| hex_decimal_to_field::<F>(s).map_err(Into::into))
        .collect::<Result<Vec<F>, ApplicationError>>()?;

    Ok(ParsedInputs {
        root,
        h_sign_user_op,
        block_timestamp,
        random,
        anchor,
        hanchor,
        aud_list,
    })
}

pub(crate) fn build_mp(
    path: &[String],
    leaf_idx: usize,
) -> Result<Path<MerkleTreeParams<F>>, ApplicationError> {
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

pub(crate) fn pad_aud_list_and_hash<Config: ZkPasskeyConfig>(
    poseidon_params: &PoseidonConfig<F>,
    aud_list: &[F],
) -> Result<(Vec<F>, F), ApplicationError> {
    let mut padded = aud_list.to_vec();

    if padded.len() < Config::NUM_AUDIENCE_LIMIT {
        let padding_count = Config::NUM_AUDIENCE_LIMIT - padded.len();

        let padded_str = pad(
            Config::FORBIDDEN_STRING,
            Config::MAX_AUD_LEN,
            Config::PAD_CHAR,
        )?;
        let limbs = ascii_to_field_be::<F>(&padded_str)
            .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))?;
        let h = PoseidonHash::evaluate(poseidon_params, limbs)
            .map_err(|_| ApplicationError::PoseidonHashError)?;

        padded.extend_from_slice(&vec![h; padding_count]);
    }

    let h_aud_list = PoseidonHash::evaluate(poseidon_params, padded.clone())
        .map_err(|_| ApplicationError::PoseidonHashError)?;

    Ok((padded, h_aud_list))
}

pub(crate) fn derive_x_list(
    builders: &[TokenBuilder],
    poseidon_params: &PoseidonConfig<F>,
    anchor_config: &AnchorConfig,
) -> Result<Vec<F>, ApplicationError> {
    let secrets: Vec<Secret> = builders.iter().map(|b| b.parse_secret()).collect();

    secrets
        .iter()
        .map(|s| derive_x_from_secret(s, poseidon_params, anchor_config))
        .collect::<Result<Vec<F>, ApplicationError>>()
}

pub(crate) fn compute_h_ctx(
    poseidon_params: &PoseidonConfig<F>,
    a: &[F],
    random: F,
) -> Result<F, ApplicationError> {
    let mut inputs = a.to_vec();
    inputs.push(random);
    PoseidonHash::evaluate(poseidon_params, inputs).map_err(|_| ApplicationError::PoseidonHashError)
}

pub(crate) fn compute_lhs_randomized(
    a: &[F],
    anchor_vec: &[F],
    random: F,
) -> Result<F, ApplicationError> {
    let ip = PoseidonAnchorScheme::<F>::inner_product(a, anchor_vec)
        .map_err(|_| ApplicationError::PoseidonHashError)?;
    Ok(ip * random)
}

pub(crate) fn partial_rhs_randomized(
    anchor_witness: &PoseidonAnchorWitness<F>,
    random: F,
) -> Vec<F> {
    let partial_rhs_list = anchor_witness.compute_partial_rhs();

    partial_rhs_list
        .into_iter()
        .filter(|&x| x != F::from(0u8))
        .map(|x| x * random)
        .collect()
}

pub(crate) fn compute_anchor_ctx<Config: ZkPasskeyConfig>(
    circuit_ctx: &CircuitContext<Config>,
    builders: &[TokenBuilder],
    parsed_inputs: &ParsedInputs,
) -> Result<AnchorContext, ApplicationError> {
    let x_list = derive_x_list(
        builders,
        &circuit_ctx.poseidon_params,
        &circuit_ctx.anchor_cfg,
    )?;

    let selector = derive_selector_from_x_list_and_anchor::<F>(
        &circuit_ctx.poseidon_anchor_key,
        &x_list,
        &parsed_inputs.anchor,
        &circuit_ctx.vandermonde_matrix,
    )?;

    let anchor_witness = build_anchor_witness(
        &circuit_ctx.poseidon_params,
        &x_list,
        &selector,
        &circuit_ctx.vandermonde_matrix,
    )?;

    let h_ctx = compute_h_ctx(
        &circuit_ctx.poseidon_params,
        &anchor_witness.a,
        parsed_inputs.random,
    )?;

    let lhs = compute_lhs_randomized(
        &anchor_witness.a,
        &parsed_inputs.anchor.0,
        parsed_inputs.random,
    )?;

    let partial_rhs_list = partial_rhs_randomized(&anchor_witness, parsed_inputs.random);

    let current_idx_list: Vec<usize> = selector
        .iter()
        .enumerate()
        .filter_map(|(i, &sel)| if sel == 1 { Some(i) } else { None })
        .collect();

    Ok(AnchorContext {
        selector,
        anchor_witness_a: anchor_witness.a,
        h_ctx,
        lhs,
        partial_rhs_list,
        current_idx_list,
    })
}

/// Anchor를 문자열 배열로부터 파싱하여 PoseidonAnchor와 hanchor로 변환합니다.
///
/// # Arguments
/// * `raw_anchor` - Anchor 값들과 hanchor를 포함하는 문자열 배열
///                  마지막 요소가 hanchor, 나머지가 anchor 값들
///
/// # Returns
/// (PoseidonAnchor, hanchor) 튜플
pub fn convert_raw_anchor(
    raw_anchor: &[String],
) -> Result<(PoseidonAnchor<F>, F), ApplicationError> {
    if raw_anchor.is_empty() {
        return Err(ApplicationError::InvalidFormat(
            "Anchor parts cannot be empty".to_string(),
        ));
    }

    // 마지막 요소를 hanchor로 분리
    let (raw_hanchor, raw_anchor) = raw_anchor.split_last().ok_or_else(|| {
        ApplicationError::InvalidFormat("Failed to split anchor parts".to_string())
    })?;

    // hanchor 파싱
    let hanchor = hex_decimal_to_field::<F>(raw_hanchor).map_err(|e| {
        ApplicationError::InvalidFormat(format!("Failed to parse hanchor '{}': {}", raw_hanchor, e))
    })?;

    // anchor 값들 파싱
    let fields: Vec<F> = raw_anchor
        .iter()
        .map(|f| {
            hex_decimal_to_field::<F>(f)
                .map_err(|e| ApplicationError::InvalidFormat(format!("{}", e)))
        })
        .collect::<Result<Vec<F>, ApplicationError>>()?;

    let anchor = PoseidonAnchor::new(fields);

    Ok((anchor, hanchor))
}
